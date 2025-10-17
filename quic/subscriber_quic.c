// subscriber_quic.c
// Cliente suscriptor: HELLO -> SUB(topic) (reliable) -> recibe DATA y responde ACK.

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

typedef enum { MQ_HELLO=1, MQ_HELLO_OK, MQ_SUB, MQ_PUB, MQ_DATA, MQ_ACK } mq_type_t;

#pragma pack(push,1)
typedef struct { uint8_t type; uint32_t seq, ack; uint16_t topic_len, data_len; } mq_hdr_t;
#pragma pack(pop)

typedef struct { mq_hdr_t hdr; char topic[128]; uint8_t data[MQ_MAX_PAYLOAD]; } mq_packet_t;

static uint64_t now_ms(void){ struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts);
  return (uint64_t)ts.tv_sec*1000ull + (uint64_t)(ts.tv_nsec/1000000ull); }

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
static int mq_send_ack(int s, const struct sockaddr_in* a, socklen_t al, uint32_t ack){
  mq_packet_t p={0}; p.hdr.type=MQ_ACK; p.hdr.ack=ack; uint8_t buf[64]; size_t n=mq_pack(buf,sizeof(buf),&p);
  return (sendto(s,buf,n,0,(const struct sockaddr*)a,al)<0)?-1:0;
}
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
  fprintf(stderr,"[sub] timeout esperando ACK seq=%u\n", p->hdr.seq); return -1;
}

int main(int argc, char** argv){
  if(argc<4){ fprintf(stderr,"Uso: %s <host> <port> <topic>\n",argv[0]); return 1; }
  const char* host=argv[1]; int port=atoi(argv[2]); const char* topic=argv[3];
  int s=socket(AF_INET,SOCK_DGRAM,0); if(s<0){ perror("socket"); return 1; }
  struct sockaddr_in srv={0}; srv.sin_family=AF_INET; srv.sin_port=htons(port);
  if(inet_pton(AF_INET,host,&srv.sin_addr)!=1){ fprintf(stderr,"Dirección inválida\n"); return 1; }

  // HELLO
  mq_packet_t hello={0}; hello.hdr.type=MQ_HELLO; uint8_t hb[64]; size_t hn=mq_pack(hb,sizeof(hb),&hello);
  sendto(s,hb,hn,0,(struct sockaddr*)&srv,sizeof(srv));

  // SUB(topic) seq=1
  mq_packet_t sub={0}; sub.hdr.type=MQ_SUB; sub.hdr.seq=1;
  sub.hdr.topic_len=(uint16_t)strlen(topic); strncpy(sub.topic,topic,sizeof(sub.topic)-1);
  if(mq_send_reliable(s,&srv,sizeof(srv),&sub)!=0){ fprintf(stderr,"Fallo al suscribirse\n"); return 1; }
  printf("[sub] suscrito a '%s'\n", topic);

  for(;;){
    uint8_t rb[2000]; struct sockaddr_in fr; socklen_t fl=sizeof(fr);
    ssize_t rn=recvfrom(s,rb,sizeof(rb),0,(struct sockaddr*)&fr,&fl);
    if(rn<=0) continue;
    mq_packet_t p; if(!mq_unpack(rb,rn,&p)) continue;
    if(p.hdr.type==MQ_DATA){
      printf("[sub] msg(topic=%s, seq=%u, len=%u): ", p.topic, p.hdr.seq, p.hdr.data_len);
      fwrite(p.data,1,p.hdr.data_len,stdout); printf("\n");
      mq_send_ack(s,&srv,sizeof(srv),p.hdr.seq);
    }
  }
}
