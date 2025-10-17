// broker_quic.c
// Broker UDP con “mini-QUIC” educativo: registra suscriptores por tópico,
// recibe publicaciones y reenvía DATA de forma confiable (ACK + retransmisión).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#define MQ_MAX_PAYLOAD 1200
#define MQ_TIMEOUT_MS  500
#define MQ_MAX_RETX    10

typedef enum {
    MQ_HELLO    = 1,
    MQ_HELLO_OK = 2,
    MQ_SUB      = 3,
    MQ_PUB      = 4,
    MQ_DATA     = 5,
    MQ_ACK      = 6
} mq_type_t;

#pragma pack(push, 1)
typedef struct {
    uint8_t  type;
    uint32_t seq;
    uint32_t ack;
    uint16_t topic_len;
    uint16_t data_len;
} mq_hdr_t;
#pragma pack(pop)

typedef struct {
    mq_hdr_t hdr;
    char     topic[128];
    uint8_t  data[MQ_MAX_PAYLOAD];
} mq_packet_t;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec*1000ull + (uint64_t)(ts.tv_nsec/1000000ull);
}

static size_t mq_pack(uint8_t* buf, size_t buflen, const mq_packet_t* p) {
    if (buflen < sizeof(mq_hdr_t)) return 0;
    mq_hdr_t h = p->hdr;
    h.seq       = htonl(h.seq);
    h.ack       = htonl(h.ack);
    h.topic_len = htons(h.topic_len);
    h.data_len  = htons(h.data_len);
    memcpy(buf, &h, sizeof(h));
    size_t off = sizeof(h);
    if (p->hdr.topic_len) {
        if (off + p->hdr.topic_len > buflen) return 0;
        memcpy(buf+off, p->topic, p->hdr.topic_len);
        off += p->hdr.topic_len;
    }
    if (p->hdr.data_len) {
        if (off + p->hdr.data_len > buflen) return 0;
        memcpy(buf+off, p->data, p->hdr.data_len);
        off += p->hdr.data_len;
    }
    return off;
}

static bool mq_unpack(const uint8_t* buf, size_t len, mq_packet_t* out) {
    if (len < sizeof(mq_hdr_t)) return false;
    memcpy(&out->hdr, buf, sizeof(mq_hdr_t));
    out->hdr.seq       = ntohl(out->hdr.seq);
    out->hdr.ack       = ntohl(out->hdr.ack);
    out->hdr.topic_len = ntohs(out->hdr.topic_len);
    out->hdr.data_len  = ntohs(out->hdr.data_len);
    size_t off = sizeof(mq_hdr_t);
    if (out->hdr.topic_len) {
        if (off + out->hdr.topic_len > len || out->hdr.topic_len >= sizeof(out->topic)) return false;
        memcpy(out->topic, buf+off, out->hdr.topic_len);
        out->topic[out->hdr.topic_len] = '\0';
        off += out->hdr.topic_len;
    } else out->topic[0] = '\0';
    if (out->hdr.data_len) {
        if (off + out->hdr.data_len > len || out->hdr.data_len > MQ_MAX_PAYLOAD) return false;
        memcpy(out->data, buf+off, out->hdr.data_len);
    }
    return true;
}

static int mq_send_ack(int sock, const struct sockaddr_in* a, socklen_t alen, uint32_t acknum) {
    mq_packet_t p = {0};
    p.hdr.type = MQ_ACK;
    p.hdr.ack  = acknum;
    uint8_t b[64];
    size_t n = mq_pack(b, sizeof(b), &p);
    return (sendto(sock, b, n, 0, (const struct sockaddr*)a, alen) < 0) ? -1 : 0;
}

static int mq_send_reliable(int sock, const struct sockaddr_in* a, socklen_t alen, mq_packet_t* p) {
    uint8_t buf[1600];
    size_t n = mq_pack(buf, sizeof(buf), p);
    if (!n) return -1;
    int tries = 0;
    while (tries < MQ_MAX_RETX) {
        if (sendto(sock, buf, n, 0, (const struct sockaddr*)a, alen) < 0) {
            perror("sendto"); return -1;
        }
        uint64_t start = now_ms();
        for (;;) {
            uint64_t elapsed = now_ms() - start;
            if (elapsed >= MQ_TIMEOUT_MS) break;
            struct timeval tv = { .tv_sec = (MQ_TIMEOUT_MS - elapsed)/1000,
                                  .tv_usec = ((MQ_TIMEOUT_MS - elapsed)%1000)*1000 };
            fd_set fds; FD_ZERO(&fds); FD_SET(sock, &fds);
            int r = select(sock+1, &fds, NULL, NULL, &tv);
            if (r > 0 && FD_ISSET(sock, &fds)) {
                uint8_t rbuf[1600];
                struct sockaddr_in f; socklen_t fl = sizeof(f);
                ssize_t rn = recvfrom(sock, rbuf, sizeof(rbuf), 0, (struct sockaddr*)&f, &fl);
                if (rn > 0) {
                    mq_packet_t ap;
                    if (mq_unpack(rbuf, rn, &ap) && ap.hdr.type==MQ_ACK && ap.hdr.ack==p->hdr.seq) return 0;
                }
            } else if (r < 0 && errno != EINTR) { perror("select"); break; }
        }
        tries++;
    }
    fprintf(stderr, "[broker] timeout esperando ACK seq=%u\n", p->hdr.seq);
    return -1;
}

/* --- Tabla de suscriptores por tópico --- */
typedef struct { struct sockaddr_in addr; char topic[128]; bool active; } subscriber_t;
#define MAX_SUBS 128
static subscriber_t subs[MAX_SUBS];

static void add_sub(const struct sockaddr_in* a, const char* topic) {
    for (int i=0;i<MAX_SUBS;i++) if (!subs[i].active) {
        subs[i].addr = *a;
        strncpy(subs[i].topic, topic, sizeof(subs[i].topic)-1);
        subs[i].active = true;
        printf("[broker] SUB %s -> %s:%d\n", subs[i].topic, inet_ntoa(a->sin_addr), ntohs(a->sin_port));
        return;
    }
    fprintf(stderr, "[broker] tabla de suscriptores llena\n");
}
static int find_subs(const char* topic, int* idxs, int cap){
    int c=0; for(int i=0;i<MAX_SUBS && c<cap;i++)
        if (subs[i].active && strcmp(subs[i].topic, topic)==0) idxs[c++]=i;
    return c;
}

int main(int argc, char** argv) {
    if (argc < 2){ fprintf(stderr,"Uso: %s <port>\n", argv[0]); return 1; }
    int port = atoi(argv[1]);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s<0){ perror("socket"); return 1; }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_ANY); addr.sin_port = htons(port);
    if (bind(s,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("bind"); return 1; }

    printf("[broker] escuchando UDP %d\n", port);

    for (;;) {
        uint8_t buf[2000]; struct sockaddr_in from; socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
        if (n <= 0) continue;
        mq_packet_t p; if (!mq_unpack(buf, n, &p)) continue;

        switch (p.hdr.type) {
            case MQ_HELLO: {
                mq_packet_t r = {0}; r.hdr.type = MQ_HELLO_OK;
                uint8_t b[64]; size_t bn = mq_pack(b, sizeof(b), &r);
                sendto(s, b, bn, 0, (struct sockaddr*)&from, fl);
                printf("[broker] HELLO_OK -> %s:%d\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
            } break;
            case MQ_SUB: {
                add_sub(&from, p.topic);
                mq_send_ack(s, &from, fl, p.hdr.seq);
            } break;
            case MQ_PUB: {
                printf("[broker] PUB topic='%s' de %s:%d\n", p.topic, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
                mq_send_ack(s, &from, fl, p.hdr.seq);
            } break;
            case MQ_DATA: {
                mq_send_ack(s, &from, fl, p.hdr.seq); // confirmar al publisher
                int idxs[64], cnt = find_subs(p.topic, idxs, 64);
                for (int i=0;i<cnt;i++) {
                    subscriber_t* sub = &subs[idxs[i]];
                    mq_packet_t out = {0};
                    out.hdr.type = MQ_DATA;
                    out.hdr.seq  = p.hdr.seq; // reusar seq simple
                    out.hdr.topic_len = (uint16_t)strlen(p.topic);
                    out.hdr.data_len  = p.hdr.data_len;
                    strncpy(out.topic, p.topic, sizeof(out.topic)-1);
                    memcpy(out.data, p.data, p.hdr.data_len);
                    if (mq_send_reliable(s, &sub->addr, sizeof(sub->addr), &out)==0)
                        printf("[broker] entregado a %s:%d (seq=%u)\n",
                               inet_ntoa(sub->addr.sin_addr), ntohs(sub->addr.sin_port), out.hdr.seq);
                    else
                        fprintf(stderr,"[broker] fallo entrega a %s:%d\n",
                                inet_ntoa(sub->addr.sin_addr), ntohs(sub->addr.sin_port));
                }
            } break;
            default: break;
        }
    }
    return 0;
}
