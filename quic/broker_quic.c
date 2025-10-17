// broker_quic.c
// Broker UDP con “mini-QUIC” educativo: registra suscriptores por tópico,
// recibe publicaciones y reenvía DATA de forma confiable (ACK + retransmisión).
//
// COMENTARIOS EXPLICATIVOS (resumen):
// Este fichero implementa un protocolo ligero y educativo que corre sobre UDP
// y reproduce varias ideas centrales de QUIC (retransmisiones en espacio de usuario,
// ACKs, numeración de paquetes), pero de forma muy simplificada:
//  - Usa sockets UDP: la entrega de paquetes la hace el kernel, pero la fiabilidad
//    y retransmisión las implementa este proceso en espacio de usuario (como QUIC).
//  - Usa campos tipo/seq/ack en el header (similares a frames/packet numbers/ACKs).
//  - Implementa un mecanismo de retransmisión con timeout (MQ_TIMEOUT_MS) y
//    reintentos limitados (MQ_MAX_RETX) — comparable a un PTO + retransmisiones.
//  - Implementa ACKs explícitos (MQ_ACK) para confirmar recepción de paquetes.
//
// Limitaciones y diferencias importantes respecto a QUIC real:
//  - No hay cifrado ni handshake TLS 1.3 integrado (aquí HELLO/HELLO_OK es solamente
//    un intercambio de tipo aplicación, no CRYPTO/TLS). QUIC incluye TLS 1.3
//    dentro del protocolo (CRYPTO frames) y claves derivadas para 0/1-RTT.
//  - No hay multiplexación real por streams; el "topic" es sólo un campo de mensaje
//    a nivel de aplicación. QUIC soporta streams independientes dentro de la misma
//    conexión evitando Head-of-Line blocking entre streams.
//  - No hay control de congestión ni flow control (no CUBIC/BBR ni ventanas dinámicas).
//  - No hay Connection IDs ni soporte de migración de path (no mobility).
//  - El esquema de numeración de paquetes es simple (reutiliza seq entre publisher y
//    subscribers), no se manejan envolturas/espacios de número de paquete múltiples.
//
// Diferencia con "Lab 3" (enfoque tradicional):
//  - Si Lab 3 usa TCP: allí la fiabilidad, orden y control de congestión las provee
//    la pila TCP en kernel; aquí se implementa la lógica de fiabilidad en usuario
//    sobre UDP (más parecido a la filosofía de QUIC).
//  - Si Lab 3 usó UDP + capa didáctica de fiabilidad, este fichero es un ejemplo
//    de esa idea aplicada a un broker pub/sub, con ACKs y retransmisiones, pero
//    sin las características avanzadas de QUIC (TLS integrado, streams, CC).
//
// En las anotaciones abajo se explica cada sección/función con más detalle.

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

#define MQ_MAX_PAYLOAD 1200   // ACOTACIÓN práctica similar a MTU - caben en un datagrama UDP
#define MQ_TIMEOUT_MS  500    // timeout para esperar ACKs (simula PTO simplificado)
#define MQ_MAX_RETX    10     // número máximo de retransmisiones antes de fallar

typedef enum {
    MQ_HELLO    = 1,
    MQ_HELLO_OK = 2,
    MQ_SUB      = 3,
    MQ_PUB      = 4,
    MQ_DATA     = 5,
    MQ_ACK      = 6
} mq_type_t;

#pragma pack(push, 1)
// Header sencillo: type + seq (packet number) + ack (acknowledgement number)
// topic_len + data_len para payload variable.
// Este header refleja la idea de paquetes con número y ack; en QUIC hay
// headers más complejos (long/short header, connection IDs, etc.).
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
    char     topic[128];               // campo de aplicación: topic (no es un "stream")
    uint8_t  data[MQ_MAX_PAYLOAD];
} mq_packet_t;

// Ahora funciones auxiliares. Comentarios dentro explican el paralelo con QUIC.

/* now_ms: tiempo en ms (usado para timeouts/retransmisiones)
   En QUIC los timers (PTO, loss detection) son críticos; aquí usamos un timeout
   simple para esperar ACKs después de enviar un paquete fiable. */
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec*1000ull + (uint64_t)(ts.tv_nsec/1000000ull);
}

/* mq_pack / mq_unpack: serialización básica de header + topic + data.
   QUIC define formatos binarios y frames (STREAM, ACK, CRYPTO, etc.). Este
   mini-protocolo tiene tipos similares (MQ_DATA ~ STREAM frame, MQ_ACK ~ ACK). */
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

/* mq_send_ack: construye y envía un paquete MQ_ACK.
   En QUIC los ACKs son frames que pueden piggybackearse o enviarse separados.
   Aquí simplificamos: enviamos un UDP datagrama con tipo MQ_ACK y campo ack. */
static int mq_send_ack(int sock, const struct sockaddr_in* a, socklen_t alen, uint32_t acknum) {
    mq_packet_t p = {0};
    p.hdr.type = MQ_ACK;
    p.hdr.ack  = acknum;
    uint8_t b[64];
    size_t n = mq_pack(b, sizeof(b), &p);
    return (sendto(sock, b, n, 0, (const struct sockaddr*)a, alen) < 0) ? -1 : 0;
}

/* mq_send_reliable: envía un paquete y espera ACK con retransmisiones:
   - Envía datagrama UDP con los bytes serializados.
   - Espera por un MQ_ACK con 'ack == seq' usando select() con timeout.
   - Reintenta hasta MQ_MAX_RETX.
   Esto reproduce la idea de fiabilidad en espacio de usuario (como QUIC),
   aunque QUIC tiene lógica avanzada de pérdida y timers más complejos. */
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
            if (elapsed >= MQ_TIMEOUT_MS) break; // timeout -> volver a retransmitir
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
                    // Si recibimos el ACK para este seq, devolvemos éxito.
                    if (mq_unpack(rbuf, rn, &ap) && ap.hdr.type==MQ_ACK && ap.hdr.ack==p->hdr.seq) return 0;
                }
            } else if (r < 0 && errno != EINTR) { perror("select"); break; }
        }
        tries++;
    }
    fprintf(stderr, "[broker] timeout esperando ACK seq=%u\n", p->hdr.seq);
    return -1;
}

/* --- Tabla de suscriptores por tópico ---
   Este broker mantiene una tabla simple de (addr, topic). En QUIC cada cliente
   podría corresponder a una "conexión" con Connection ID; aquí tratamos a cada
   suscriptor por su dirección IP:port. */
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

/* main:
   - Crea socket UDP y espera datagramas.
   - Procesa tipos: HELLO/HELLO_OK (simple handshake), SUB (registro),
     PUB (publicación), DATA (mensaje a reenviar).
   - En el caso de DATA reenvía de forma fiable a cada suscriptor usando
     mq_send_reliable (ACK + retransmisión). */
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
                // HANDSHAKE SENCILLO: HELLO -> HELLO_OK
                // En QUIC el handshake sería TLS/CRYPTO y derivación de claves.
                mq_packet_t r = {0}; r.hdr.type = MQ_HELLO_OK;
                uint8_t b[64]; size_t bn = mq_pack(b, sizeof(b), &r);
                sendto(s, b, bn, 0, (struct sockaddr*)&from, fl);
                printf("[broker] HELLO_OK -> %s:%d\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
            } break;
            case MQ_SUB: {
                // Registro de suscriptor por tópico y ACK de su SUB
                add_sub(&from, p.topic);
                mq_send_ack(s, &from, fl, p.hdr.seq);
            } break;
            case MQ_PUB: {
                // El publisher anuncia una publicación (podría usarse para metadata)
                printf("[broker] PUB topic='%s' de %s:%d\n", p.topic, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
                mq_send_ack(s, &from, fl, p.hdr.seq);
            } break;
            case MQ_DATA: {
                // Recibimos datos de publisher -> confirmamos al publisher
                // Luego reenviamos DATA de forma fiable a cada suscriptor del topic.
                mq_send_ack(s, &from, fl, p.hdr.seq); // confirmar al publisher

                // localizar suscriptores y reenviar
                int idxs[64], cnt = find_subs(p.topic, idxs, 64);
                for (int i=0;i<cnt;i++) {
                    subscriber_t* sub = &subs[idxs[i]];
                    mq_packet_t out = {0};
                    out.hdr.type = MQ_DATA;
                    out.hdr.seq  = p.hdr.seq; // REUTILIZA seq simple: en un diseño real habría space de packet numbers
                    out.hdr.topic_len = (uint16_t)strlen(p.topic);
                    out.hdr.data_len  = p.hdr.data_len;
                    strncpy(out.topic, p.topic, sizeof(out.topic)-1);
                    memcpy(out.data, p.data, p.hdr.data_len);

                    // Envío fiable (espera ACK del suscriptor)
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
