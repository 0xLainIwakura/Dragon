#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sddl.h>
 
#include "transport.h"
#include "client_config.h"
#include "padding.h"
#include "crypto_dragon.h"
 
#ifndef SMB_PIPE_NAME
#define SMB_PIPE_NAME "dragon"
#endif
 
#define SMB_PIPE_BUFFER_SIZE   65536
#define SMB_CONNECT_TIMEOUT_MS 10000
#define SMB_CONNECT_RETRY_MS   500
#define SMB_MAX_CONNECT_RETRIES 20 
#define SMB_IO_TIMEOUT_MS       30000

struct transport_conn {
    HANDLE hPipe;
    int is_server;
    HANDLE hReadEvent;
    HANDLE hWriteEvent;
};

static int conn_init_events(transport_conn_t *conn)
{
    conn->hReadEvent  = CreateEventA(NULL, TRUE, FALSE, NULL);
    conn->hWriteEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!conn->hReadEvent || !conn->hWriteEvent) {
        if (conn->hReadEvent)  CloseHandle(conn->hReadEvent);
        if (conn->hWriteEvent) CloseHandle(conn->hWriteEvent);
        conn->hReadEvent = conn->hWriteEvent = NULL;
        return -1;
    }
    return 0;
}

static void conn_close_events(transport_conn_t *conn)
{
    if (conn->hReadEvent)  { CloseHandle(conn->hReadEvent);  conn->hReadEvent  = NULL; }
    if (conn->hWriteEvent) { CloseHandle(conn->hWriteEvent); conn->hWriteEvent = NULL; }
}


typedef struct {
    char    pipe_path[256];   /* \\.\pipe\<name>       */
    HANDLE  hPipe;            
    int     active;
    HANDLE hConnectEvent; 
} SmbListenerState;
 
#define MAX_SMB_LISTENERS 8
static SmbListenerState  g_smb_listeners[MAX_SMB_LISTENERS];
static int               g_smb_nlisteners = 0;
static CRITICAL_SECTION  g_smb_mu;
static int               g_smb_mu_init = 0;
 
static char g_smb_pipe_name_rt[64] = "";

static uint16_t g_smb_pad_min = 0;
static uint16_t g_smb_pad_max = 0;

void smb_set_padding(uint16_t pad_min, uint16_t pad_max)
{
    g_smb_pad_min = pad_min;
    g_smb_pad_max = pad_max;
}

static void ensure_smb_mu(void) {
    if (!g_smb_mu_init) {
        InitializeCriticalSection(&g_smb_mu);
        g_smb_mu_init = 1;
    }
}

void smb_apply_pipe_name(const char *name)
{
    if (name && name[0]) {
        strncpy(g_smb_pipe_name_rt, name, sizeof(g_smb_pipe_name_rt) - 1);
        g_smb_pipe_name_rt[sizeof(g_smb_pipe_name_rt) - 1] = '\0';
        printf("[SMB] Pipe name set to: %s\n", g_smb_pipe_name_rt);
    }
}


/* =========================================================================
 * Create pipe in server mod (PIPE_ACCESS_DUPLEX)
 * ====================================================================== */
 
static HANDLE create_server_pipe(const char *pipe_path)
{
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
 
    /* Security descriptor to get full access to Everyone */
    PSECURITY_DESCRIPTOR pSD = NULL;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:(A;;GA;;;WD)",   /* DACL: Allow Generic All to World (Everyone) */
            SDDL_REVISION_1, &pSD, NULL))
    {
        sa.lpSecurityDescriptor = pSD;
    }
 
    HANDLE h = CreateNamedPipeA(
        pipe_path,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,                       
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,                    
        SMB_PIPE_BUFFER_SIZE,                       
        SMB_PIPE_BUFFER_SIZE,                        
        0,                                          
        &sa);
 
    if (pSD) LocalFree(pSD);
 
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[SMB] CreateNamedPipe failed: %lu\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }
    return h;
}

static int smb_listen(int port)
{
    ensure_smb_mu();
    EnterCriticalSection(&g_smb_mu);
 
    /* Find a free slot: prefer inactive ones first */
    int idx = -1;
    for (int i = 0; i < MAX_SMB_LISTENERS; i++) {
        if (!g_smb_listeners[i].active) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        fprintf(stderr, "[SMB] too many listeners\n");
        LeaveCriticalSection(&g_smb_mu);
        return -1;
    }
 
    SmbListenerState *ls = &g_smb_listeners[idx];
 
    const char *pipe_name = (g_smb_pipe_name_rt[0]) ? g_smb_pipe_name_rt : SMB_PIPE_NAME;
    snprintf(ls->pipe_path, sizeof(ls->pipe_path), "\\\\.\\pipe\\%s", pipe_name);
        
    ls->hPipe = create_server_pipe(ls->pipe_path);
    if (ls->hPipe == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_smb_mu);
        return -1;
    }
 
    ls->hConnectEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!ls->hConnectEvent) {
        CloseHandle(ls->hPipe);
        ls->hPipe = INVALID_HANDLE_VALUE;
        LeaveCriticalSection(&g_smb_mu);
        return -1;
    }
 
    ls->active = 1;
    LeaveCriticalSection(&g_smb_mu);
 
    printf("[SMB] listening on %s (slot %d)\n", ls->pipe_path, idx);
    return idx;
}

static transport_conn_t *smb_accept(int listener_fd, struct sockaddr_in *out_addr)
{
    if (out_addr)
        memset(out_addr, 0, sizeof(*out_addr));
 
    ensure_smb_mu();
 
    if (listener_fd < 0 || listener_fd >= MAX_SMB_LISTENERS)
        return NULL;
 
    SmbListenerState *ls = &g_smb_listeners[listener_fd];
    if (!ls->active || ls->hPipe == INVALID_HANDLE_VALUE)
        return NULL;
 
    /* Overlapped ConnectNamedPipe */
    OVERLAPPED ov = {0};
    ov.hEvent = ls->hConnectEvent;
    ResetEvent(ov.hEvent);
 
    BOOL connected = ConnectNamedPipe(ls->hPipe, &ov);
    if (!connected) {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            /* Wait for client to connect */
            WaitForSingleObject(ov.hEvent, INFINITE);
            DWORD dummy;
            if (!GetOverlappedResult(ls->hPipe, &ov, &dummy, FALSE)) {
                DWORD err2 = GetLastError();
                if (err2 != ERROR_PIPE_CONNECTED) {
                    fprintf(stderr, "[SMB] ConnectNamedPipe async failed: %lu\n", err2);
                    return NULL;
                }
            }
        } else if (err != ERROR_PIPE_CONNECTED) {
            fprintf(stderr, "[SMB] ConnectNamedPipe failed: %lu\n", err);
            return NULL;
        }
    }
 
    printf("[SMB] client connected on %s\n", ls->pipe_path);
 
    transport_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        DisconnectNamedPipe(ls->hPipe);
        return NULL;
    }
    conn->hPipe     = ls->hPipe;
    conn->is_server = 1;
 
    if (conn_init_events(conn) != 0) {
        DisconnectNamedPipe(ls->hPipe);
        free(conn);
        return NULL;
    }
 
    /* Create new pipe instance for the next client */
    ls->hPipe = create_server_pipe(ls->pipe_path);
    if (ls->hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[SMB] WARNING: failed to create pipe for next client\n");
    }
 
    return conn;
}

static transport_conn_t *smb_connect(const char *host, int port)
{
    char pipe_path[256];

    const char *pname = (g_smb_pipe_name_rt[0]) ? g_smb_pipe_name_rt : SMB_PIPE_NAME;
    snprintf(pipe_path, sizeof(pipe_path), "\\\\%s\\pipe\\%s", host, pname);

    printf("[SMB] connecting to %s\n", pipe_path);
 
    HANDLE hPipe = INVALID_HANDLE_VALUE;
 
    for (int attempt = 0; attempt < SMB_MAX_CONNECT_RETRIES; attempt++) {
 
        hPipe = CreateFileA(
            pipe_path,
            GENERIC_READ | GENERIC_WRITE,
            0,           
            NULL,          
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,             
            NULL);
 
        if (hPipe != INVALID_HANDLE_VALUE)
            break;
 
        DWORD err = GetLastError();
 
       if (err == ERROR_PIPE_BUSY) {
            if (!WaitNamedPipeA(pipe_path, SMB_CONNECT_TIMEOUT_MS))
                continue;
        } else if (err == ERROR_FILE_NOT_FOUND) {
            Sleep(SMB_CONNECT_RETRY_MS);
        } else {
            fprintf(stderr, "[SMB] connect attempt %d error: %lu\n",
                    attempt + 1, err);
            Sleep(SMB_CONNECT_RETRY_MS);
        }
    }
 
    if (hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[SMB] connect failed after %d retries: %lu\n",
                SMB_MAX_CONNECT_RETRIES, GetLastError());
        return NULL;
    }
 
    DWORD mode = PIPE_READMODE_BYTE;
    if (!SetNamedPipeHandleState(hPipe, &mode, NULL, NULL)) {
        fprintf(stderr, "[SMB] SetNamedPipeHandleState failed: %lu\n",
                GetLastError());
    }
 
    transport_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) { CloseHandle(hPipe); return NULL; }
    conn->hPipe     = hPipe;
    conn->is_server = 0;
 
    if (conn_init_events(conn) != 0) {
        CloseHandle(hPipe);
        free(conn);
        return NULL;
    }
 
    printf("[SMB] connected to %s\n", pipe_path);
    return conn;
}

static int smb_write_raw(transport_conn_t *conn, const void *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        OVERLAPPED ov = {0};
        ov.hEvent = conn->hWriteEvent;
        ResetEvent(ov.hEvent);
        DWORD written = 0;
        BOOL ok = WriteFile(conn->hPipe, (const char*)buf + total, (DWORD)(len - total), &written, &ov);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                if (WaitForSingleObject(ov.hEvent, SMB_IO_TIMEOUT_MS) != WAIT_OBJECT_0) {
                    CancelIoEx(conn->hPipe, &ov);
                    return -1;
                }
                if (!GetOverlappedResult(conn->hPipe, &ov, &written, FALSE))
                    return -1;
            } else {
                return -1;
            }
        }
        if (written == 0) return -1;
        total += written;
    }
    return (int)total;
}

static int smb_read_raw(transport_conn_t *conn, void *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        OVERLAPPED ov = {0};
        ov.hEvent = conn->hReadEvent;
        ResetEvent(ov.hEvent);
        DWORD rd = 0;
        BOOL ok = ReadFile(conn->hPipe, (char*)buf + total, (DWORD)(len - total), &rd, &ov);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                if (WaitForSingleObject(ov.hEvent, INFINITE) != WAIT_OBJECT_0) {
                    CancelIoEx(conn->hPipe, &ov);
                    return -1;
                }
                if (!GetOverlappedResult(conn->hPipe, &ov, &rd, FALSE)) {
                    if (GetLastError() == ERROR_MORE_DATA) { total += rd; continue; }
                    return -1;
                }
            } else if (err == ERROR_MORE_DATA) {
                total += rd; continue;
            } else {
                return -1;
            }
        }
        if (rd == 0) return -1;
        total += rd;
    }
    return (int)total;
}

static int smb_send(transport_conn_t *conn, const uint8_t *buf, size_t len)
{
    if (!conn || !buf || len == 0) return -1;

    uint8_t pad[1024];
    int pad_len = 0;

    if (len == WIRE_FRAME_SIZE && g_smb_pad_max > 0)
        pad_len = generate_padding(g_smb_pad_min, g_smb_pad_max, pad, 1024);

    uint32_t total = htonl((uint32_t)(len + pad_len));

    if (smb_write_raw(conn, &total, 4) < 0) return -1;
    if (smb_write_raw(conn, buf, len) < 0) return -1;
    if (pad_len > 0)
        if (smb_write_raw(conn, pad, pad_len) < 0) return -1;

    return (int)len;
}

static int smb_recv(transport_conn_t *conn, uint8_t *buf, size_t len)
{
    if (!conn || !buf || len == 0) return -1;

    uint32_t net_total;
    if (smb_read_raw(conn, &net_total, 4) < 0) return -1;
    uint32_t total = ntohl(net_total);

    if (total < (uint32_t)len) return -1;

    if (smb_read_raw(conn, buf, len) < 0) return -1;

    uint32_t remaining = total - (uint32_t)len;
    while (remaining > 0) {
        char discard[512];
        uint32_t chunk = remaining > sizeof(discard) ? sizeof(discard) : remaining;
        if (smb_read_raw(conn, discard, chunk) < 0) return -1;
        remaining -= chunk;
    }

    return (int)len;
}
 
static int smb_poll(transport_conn_t *conn, int timeout_ms)
{
    if (!conn) return -1;
 
    int elapsed = 0;
    int interval = 50;  /* check every 50ms */
 
    do {
        DWORD avail = 0;
        if (!PeekNamedPipe(conn->hPipe, NULL, 0, NULL, &avail, NULL)) {
            /* pipe broken */
            return -1;
        }
        if (avail > 0) return 1;
 
        if (timeout_ms <= 0) return 0;
 
        Sleep(interval);
        elapsed += interval;
    } while (elapsed < timeout_ms);
 
    return 0;  /* timeout */
}
 
static void smb_close(transport_conn_t *conn)
{
    if (!conn) return;
 
    if (conn->hPipe && conn->hPipe != INVALID_HANDLE_VALUE) {
        CancelIoEx(conn->hPipe, NULL); 
        FlushFileBuffers(conn->hPipe);
        if (conn->is_server) {
            DisconnectNamedPipe(conn->hPipe);
        }
        CloseHandle(conn->hPipe);
    }
    conn_close_events(conn);
    free(conn);
}
 
static void smb_close_listener(int listener_fd)
{
    ensure_smb_mu();
    EnterCriticalSection(&g_smb_mu);
 
    if (listener_fd >= 0 && listener_fd < MAX_SMB_LISTENERS) {
        SmbListenerState *ls = &g_smb_listeners[listener_fd];
        ls->active = 0;
        if (ls->hPipe != INVALID_HANDLE_VALUE) {
            CancelIoEx(ls->hPipe, NULL);
            CloseHandle(ls->hPipe);
            ls->hPipe = INVALID_HANDLE_VALUE;
        }
        if (ls->hConnectEvent) {
            CloseHandle(ls->hConnectEvent);
            ls->hConnectEvent = NULL;
        }
        printf("[SMB] listener %s closed\n", ls->pipe_path);
    }
 
    LeaveCriticalSection(&g_smb_mu);
}
 
static int smb_get_fd(transport_conn_t *conn)
{
    (void)conn;
    return -1;
}
 
/* =========================================================================
 * Transport Registration
 * ====================================================================== */
 
transport_t TRANSPORT_SMB = {
    .name           = "smb",
    .listen         = smb_listen,
    .connect        = smb_connect,
    .accept         = smb_accept,
    .send           = smb_send,
    .recv           = smb_recv,
    .poll           = smb_poll,
    .close          = smb_close,
    .close_listener = smb_close_listener,
    .get_fd         = smb_get_fd,
};