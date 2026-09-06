#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sddl.h>
 
#include "transport.h"
 
#ifndef SMB_PIPE_NAME
#define SMB_PIPE_NAME "dragon"
#endif
 
#define SMB_PIPE_BUFFER_SIZE   8192
#define SMB_CONNECT_TIMEOUT_MS 10000
#define SMB_CONNECT_RETRY_MS   500
#define SMB_MAX_CONNECT_RETRIES 20 

struct transport_conn {
    HANDLE hPipe;
};


typedef struct {
    char    pipe_path[256];   /* \\.\pipe\<name>       */
    HANDLE  hPipe;            
    int     active;
} SmbListenerState;
 
#define MAX_SMB_LISTENERS 8
static SmbListenerState  g_smb_listeners[MAX_SMB_LISTENERS];
static int               g_smb_nlisteners = 0;
static CRITICAL_SECTION  g_smb_mu;
static int               g_smb_mu_init = 0;
 
static void ensure_smb_mu(void) {
    if (!g_smb_mu_init) {
        InitializeCriticalSection(&g_smb_mu);
        g_smb_mu_init = 1;
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
        PIPE_ACCESS_DUPLEX,                       
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
 
    if (g_smb_nlisteners >= MAX_SMB_LISTENERS) {
        fprintf(stderr, "[SMB] too many listeners\n");
        LeaveCriticalSection(&g_smb_mu);
        return -1;
    }
 
    int idx = g_smb_nlisteners;
    SmbListenerState *ls = &g_smb_listeners[idx];
 
    if (port > 0)
        snprintf(ls->pipe_path, sizeof(ls->pipe_path),
                 "\\\\.\\pipe\\%s_%d", SMB_PIPE_NAME, port);
    else
        snprintf(ls->pipe_path, sizeof(ls->pipe_path),
                 "\\\\.\\pipe\\%s", SMB_PIPE_NAME);
 
    ls->hPipe = create_server_pipe(ls->pipe_path);
    if (ls->hPipe == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_smb_mu);
        return -1;
    }
 
    ls->active = 1;
    g_smb_nlisteners++;
    LeaveCriticalSection(&g_smb_mu);
 
    printf("[SMB] listening on %s\n", ls->pipe_path);
    return idx;
}

static transport_conn_t *smb_accept(int listener_fd,
                                     struct sockaddr_in *out_addr)
{
    (void)out_addr; 
 
    ensure_smb_mu();
 
    if (listener_fd < 0 || listener_fd >= g_smb_nlisteners)
        return NULL;
 
    SmbListenerState *ls = &g_smb_listeners[listener_fd];
    if (!ls->active || ls->hPipe == INVALID_HANDLE_VALUE)
        return NULL;
 
    BOOL connected = ConnectNamedPipe(ls->hPipe, NULL);
    if (!connected) {
        DWORD err = GetLastError();
        if (err != ERROR_PIPE_CONNECTED) {
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
    conn->hPipe = ls->hPipe;
 
    ls->hPipe = create_server_pipe(ls->pipe_path);
    if (ls->hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[SMB] WARNING: error creating pipe for next client\n");
    }
 
    return conn;
}

static transport_conn_t *smb_connect(const char *host, int port)
{
    char pipe_path[256];
 
    if (port > 0)
        snprintf(pipe_path, sizeof(pipe_path),
                 "\\\\%s\\pipe\\%s_%d", host, SMB_PIPE_NAME, port);
    else
        snprintf(pipe_path, sizeof(pipe_path),
                 "\\\\%s\\pipe\\%s", host, SMB_PIPE_NAME);
 
    printf("[SMB] connecting to %s\n", pipe_path);
 
    HANDLE hPipe = INVALID_HANDLE_VALUE;
 
    for (int attempt = 0; attempt < SMB_MAX_CONNECT_RETRIES; attempt++) {
 
        hPipe = CreateFileA(
            pipe_path,
            GENERIC_READ | GENERIC_WRITE,
            0,           
            NULL,          
            OPEN_EXISTING,
            0,             
            NULL);
 
        if (hPipe != INVALID_HANDLE_VALUE)
            break;
 
        DWORD err = GetLastError();
 
        if (err == ERROR_PIPE_BUSY) {
            if (!WaitNamedPipeA(pipe_path, SMB_CONNECT_TIMEOUT_MS))
                continue;
        } else {
            Sleep(SMB_CONNECT_RETRY_MS);
        }
    }
 
    if (hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[SMB] connect failed after %d retries: %lu\n",
                SMB_MAX_CONNECT_RETRIES, GetLastError());
        return NULL;
    }
 
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
 
    transport_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) { CloseHandle(hPipe); return NULL; }
    conn->hPipe = hPipe;
 
    printf("[SMB] connected to %s\n", pipe_path);
    return conn;
}

static int smb_send(transport_conn_t *conn,
                     const uint8_t *buf, size_t len)
{
    if (!conn || !buf || len == 0) return -1;
 
    size_t total = 0;
    while (total < len) {
        DWORD written = 0;
        BOOL ok = WriteFile(conn->hPipe,
                            buf + total,
                            (DWORD)(len - total),
                            &written, NULL);
        if (!ok || written == 0) {
            fprintf(stderr, "[SMB] WriteFile failed: %lu\n", GetLastError());
            return -1;
        }
        total += written;
    }
    return (int)total;
}

static int smb_recv(transport_conn_t *conn,
                     uint8_t *buf, size_t len)
{
    if (!conn || !buf || len == 0) return -1;
 
    size_t total = 0;
    while (total < len) {
        DWORD rd = 0;
        BOOL ok = ReadFile(conn->hPipe,
                           buf + total,
                           (DWORD)(len - total),
                           &rd, NULL);
        if (!ok || rd == 0) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA)
                return -1; 
            fprintf(stderr, "[SMB] ReadFile failed: %lu\n", err);
            return -1;
        }
        total += rd;
    }
    return (int)total;
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
 
/*
 * smb_close()
 */
static void smb_close(transport_conn_t *conn)
{
    if (!conn) return;
 
    if (conn->hPipe && conn->hPipe != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(conn->hPipe);
        DisconnectNamedPipe(conn->hPipe);  
        CloseHandle(conn->hPipe);
    }
    free(conn);
}
 
/*
 * smb_close_listener()
 */
static void smb_close_listener(int listener_fd)
{
    ensure_smb_mu();
    EnterCriticalSection(&g_smb_mu);
 
    if (listener_fd >= 0 && listener_fd < g_smb_nlisteners) {
        SmbListenerState *ls = &g_smb_listeners[listener_fd];
        ls->active = 0;
        if (ls->hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(ls->hPipe);
            ls->hPipe = INVALID_HANDLE_VALUE;
        }
        printf("[SMB] listener %s chiuso\n", ls->pipe_path);
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