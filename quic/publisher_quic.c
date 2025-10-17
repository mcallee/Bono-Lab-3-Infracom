// publisher_quic.c
// Publisher: HELLO -> PUB(topic) (reliable) -> envía N mensajes DATA (reliable).
//
// COMENTARIOS EXPLICATIVOS (resumen):
// Este fichero implementa un cliente "publisher" que habla con un broker
// usando UDP y una pequeña capa de fiabilidad en espacio de usuario.
// Muchas ideas remiten a QUIC (uso de UDP + numeración de paquetes + ACKs +
// retransmisión con timeout), por eso es un "mini-QUIC" educativo:
//  - Se usan datagramas UDP para el transporte base (socket SOCK_DGRAM).
//  - La lógica de fiabilidad (esperar ACKs, timeout, retransmitir) se hace en
//    espacio de usuario mediante mq_send_reliable (análogo a retransmisiones en QUIC).
//  - Mensajes tienen header con type/seq/ack, y payloads serializados.
//
// Diferencias importantes respecto a QUIC real:
//  - No hay cifrado ni handshake TLS 1.3 integrado: HELLO/HELLO_OK es solo un
//    saludo de aplicación, no CRYPTO/TLS. QUIC integra TLS 1.3 dentro del
//    propio protocolo y deriva claves para proteger paquetes.
//  - No hay multiplexación por streams: cada DATA es un mensaje independiente.
//  - No hay control de congestión ni flow control (no CUBIC/BBR ni ventanas).
//  - No hay Connection IDs ni migración de path. Numeración de paquetes es simple.
//
// Diferencia respecto a "Lab 3":
//  - Si Lab 3 usaba TCP: allí la fiabilidad y CC vienen del kernel; aquí se
//    implementan en usuario sobre UDP (filosofía QUIC).
//  - Si Lab 3 usó UDP sin capa fiable, este archivo muestra una capa fiable
//    básica (ACK + retries) parecida conceptualmente a lo que QUIC hace, pero
//    simplificada.

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

#define MQ_MAX_PAYLOAD 1200   // límite práctico cercano a MTU, para que quepa en UDP
#define MQ_TIMEOUT_MS  500    // timeout para esperar ACK (simula PTO simplificado)
#define MQ_MAX_RETX    10     // número máximo de reintentos antes de fallar

typedef enum { MQ_HELLO=1, MQ_HELLO_OK, MQ_SUB, MQ_PUB, MQ_DATA, MQ_ACK } mq_type_t;

#pragma pack(push,1)
// Header simple: tipo + seq (packet number) + ack + tamaños de campos variables.
// En QUIC los headers son más complejos (long/short, connection_id, etc.).
typedef struct { uint8_t type; uint32_t seq, ack; uint16_t topic_len, data_len; } mq_hdr_t;
#pragma pack(pop)

typedef struct { mq_hdr_t hdr; char topic[128]; uint8_t data[MQ_MAX_PAYLOAD]; } mq_packet_t;

/* now_ms:
   - Utilidad para medir tiempos en ms.
   - En QUIC real hay timers más finos (PTO, handshake, retransmit), pero aquí
     usamos un único timeout simple para ACKs. */
static uint64_t now_ms(void){ struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts);
  return (uint64_t)ts.tv_sec*1000ull + (uint64_t)(ts.tv_nsec/1000000ull); }

/* mq_pack / mq_unpack:
   - Serializan y deserializan el header + topic + data en un buffer.
   - Se usan conversiones de orden de bytes (htonl/htons) para red.
   - En QUIC existen formats binarios y frames; esto es un análogo simplificado. */
static size_t mq_pack(uint8_t* b, size_t bl, const mq_packet_t* p){
  if (bl < sizeof(mq_hdr_t)) return 0;
  mq_hdr_t h=p->hdr; h.seq=htonl(h.seq); h.ack=htonl(h.ack);
  h.topic_len=htons(h.topic_len); h.data_len=htons(h.data_len);
  memcpy(b,&h,sizeof(h)); size_t off=sizeof(h);
  if (p->hdr.topic_len){ if (off+p->hdr.topic_len>bl) return 0; memcpy(b+off,p->topic,p->hdr.topic_len); off+=p->hdr.topic_len; }
  if (p->hdr.data_len){ if (off+p->hdr.data_len>bl) return 0; memcpy(b+off,p->data,p->hdr.data_len); off+=p->hdr.data_len; }
  return off;
}
static bool mq_unpack(const uint8_t* b, size_t l, mq_packet_t* o){
  if (l<sizeof(mq_hdr_t)) return false; memcpy(&o->hdr,b,sizeof(mq_hdr_t));
  o->hdr.seq=ntohl(o->hdr.seq); o->hdr.ack=ntohl(o->hdr.ack);
  o->hdr.topic_len=ntohs(o->hdr.topic_len); o->hdr.data_len=ntohs(o->hdr.data_len);
  size_t off=sizeof(mq_hdr_t);
  if (o->hdr.topic_len){ if (off+o->hdr.topic_len>l || o->hdr.topic_len>=sizeof(o->topic)) return false;
    memcpy(o->topic,b+off,o->hdr.topic_len); o->topic[o->hdr.topic_len]='\0'; off+=o->hdr.topic_len; }
  else o->topic[0]='\0';
  if (o->hdr.data_len){ if (off+o->hdr.data_len>l || o->hdr.data_len>MQ_MAX_PAYLOAD) return false;
    memcpy(o->data,b+off,o->hdr.data_len); }
  return true;
}

/* mq_send_ack:
   - Construye y envía un paquete MQ_ACK con el número de ack indicado.
   - En QUIC los ACKs son frames que pueden incluir ranges y delays; aquí es un
   - ACK simple que contiene el número confirmado. */
static int mq_send_ack(int s, const struct sockaddr_in* a, socklen_t al, uint32_t ack){
  mq_packet_t p={0}; p.hdr.type=MQ_ACK; p.hdr.ack=ack; uint8_t buf[64]; size_t n=mq_pack(buf,sizeof(buf),&p);
  return (sendto(s,buf,n,0,(const struct sockaddr*)a,al)<0)?-1:0;
}

/* mq_send_reliable:
   - Implementa envío fiable en espacio de usuario:
     1) Serializa el paquete y lo envía por UDP.
     2) Espera un ACK que contenga p->hdr.seq usando select() con timeout.
     3) Si no llega ACK en MQ_TIMEOUT_MS retransmite, hasta MQ_MAX_RETX intentos.
   - Simula la lógica básica de retransmisión de QUIC, pero sin detección de pérdida
     por reordenamiento, sin timers adaptativos complejos y sin contención.
   - Observaciones: el uso de select() aquí bloquea hasta recibir algo en el socket;
     en implementaciones más complejas habría un loop de eventos centralizado. */
static int mq_send_reliable(int s, const struct sockaddr_in* a, socklen_t al, mq_packet_t* p){
  uint8_t buf[1600]; size_t n=mq_pack(buf,sizeof(buf),p); if(!n) return -1; int tries=0;
  while(tries<MQ_MAX_RETX){
    if (sendto(s,buf,n,0,(const struct sockaddr*)a,al)<0){ perror("sendto"); return -1; }
    uint64_t start=now_ms();
    for(;;){
      uint64_t el=now_ms()-start; if(el>=MQ_TIMEOUT_MS) break;
      struct timeval tv={.tv_sec=(MQ_TIMEOUT_MS-el)/1000,.tv_usec=((MQ_TIMEOUT_MS-el)%1000)*1000};
      fd_set f; FD_ZERO(&f); FD_SET(s,&f);
      int r=select(s+1,&f,NULL,NULL,&tv);
      if(r>0 && FD_ISSET(s,&f)){
        uint8_t rb[1600]; struct sockaddr_in fr; socklen_t fl=sizeof(fr);
        ssize_t rn=recvfrom(s,rb,sizeof(rb),0,(struct sockaddr*)&fr,&fl);
        if(rn>0){ mq_packet_t ap; if(mq_unpack(rb,rn,&ap)&&ap.hdr.type==MQ_ACK&&ap.hdr.ack==p->hdr.seq) return 0; }
      } else if (r<0 && errno!=EINTR){ perror("select"); break; }
    }
    tries++;
  }
  fprintf(stderr,"[pub] timeout esperando ACK seq=%u\n", p->hdr.seq); return -1;
}

/* main:
   - Args: <host> <port> <topic> <num_msgs>
   - Crea socket UDP y envía:
       HELLO (no bloqueante de ACK aquí)
       PUB(topic) con seq=1 de forma fiable (mq_send_reliable)
       N mensajes DATA con seq=2..N+1 de forma fiable
   - Secuencia de números: simple contador secuencial usado para ACK matching.
   - En diseño real de QUIC, la numeración y espacios de números son más complejos. */
int main(int argc, char** argv){
  if(argc<5){ fprintf(stderr,"Uso: %s <host> <port> <topic> <num_msgs>\n",argv[0]); return 1; }
  const char* host=argv[1]; int port=atoi(argv[2]); const char* topic=argv[3]; int num=atoi(argv[4]);

  int s=socket(AF_INET,SOCK_DGRAM,0); if(s<0){ perror("socket"); return 1; }
  struct sockaddr_in srv={0}; srv.sin_family=AF_INET; srv.sin_port=htons(port);
  if(inet_pton(AF_INET,host,&srv.sin_addr)!=1){ fprintf(stderr,"Dirección inválida\n"); return 1; }

  // HELLO
  // En QUIC aquí habría un handshake CRYPTO/TLS; aquí solo un saludo sin criptografía.
  mq_packet_t hello={0}; hello.hdr.type=MQ_HELLO; uint8_t hb[64]; size_t hn=mq_pack(hb,sizeof(hb),&hello);
  sendto(s,hb,hn,0,(struct sockaddr*)&srv,sizeof(srv));

  // PUB(topic) seq=1 -> envío fiable (wait for ACK)
  mq_packet_t pub={0}; pub.hdr.type=MQ_PUB; pub.hdr.seq=1;
  pub.hdr.topic_len=(uint16_t)strlen(topic); strncpy(pub.topic,topic,sizeof(pub.topic)-1);
  if(mq_send_reliable(s,&srv,sizeof(srv),&pub)!=0){ fprintf(stderr,"Fallo al anunciar PUB\n"); return 1; }
  printf("[pub] publicando en '%s'\n", topic);

  // DATA seq=2..N+1 -> cada DATA se envía de forma fiable (mq_send_reliable)
  // En QUIC los STREAM frames permiten enviar datos de forma multiplexada y con
  // offsets; aquí cada DATA es un paquete independiente con seq propio.
  for(int i=0;i<num;i++){
    char msg[128]; snprintf(msg,sizeof(msg),"hello #%d", i+1);
    mq_packet_t d={0}; d.hdr.type=MQ_DATA; d.hdr.seq=(uint32_t)(2+i);
    d.hdr.topic_len=(uint16_t)strlen(topic); d.hdr.data_len=(uint16_t)strlen(msg);
    strncpy(d.topic,topic,sizeof(d.topic)-1); memcpy(d.data,msg,d.hdr.data_len);
    if(mq_send_reliable(s,&srv,sizeof(srv),&d)!=0){ fprintf(stderr,"Fallo DATA #%d\n",i+1); break; }
    printf("[pub] enviado seq=%u\n", d.hdr.seq);
  }
  (void)mq_send_ack; // silenciar warning si no se usa en este módulo
  return 0;
}
