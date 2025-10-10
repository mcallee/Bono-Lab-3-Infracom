// broker_quic.c — Broker Pub/Sub sobre QUIC (MsQuic)
// - Acepta conexiones QUIC (TLS 1.3 sobre UDP).
// - Cada cliente abre 1 stream bidi.
// - SUBSCRIBE <topic>\n  => registra el stream como suscriptor.
// - PUBLISH <topic>|seq|ts|etype|payload => fan-out a subs del topic.
//
// Diferencias vs TCP/UDP previos:
// * No usamos socket()/send()/recv(); usamos la API de MsQuic (Listener/Connection/Stream).
// * QUIC ofrece confiabilidad/orden por stream (como TCP) pero corre sobre UDP.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <msquic.h>

#define MAX_SUBS 256
#define MAX_TOPIC 128
#define ALPN_STR "infracom"
#define CHECK_QUIC(st, msg) do{ if(QUIC_FAILED(st)){ fprintf(stderr,"%s: 0x%x\n",msg,st); exit(1);} }while(0)

static const QUIC_API_TABLE* MsQuic = NULL;
static HQUIC Registration = NULL;
static HQUIC Configuration = NULL;
static HQUIC Listener = NULL;
static volatile int running = 1;

typedef enum { ROLE_UNKNOWN=0, ROLE_SUB=1 } role_t;
typedef struct {
    HQUIC Connection;
    HQUIC Stream;
    role_t Role;
    char topic[MAX_TOPIC];
    int in_use;
} peer_t;

static peer_t subs[MAX_SUBS];

static void on_sigint(int s){ (void)s; running = 0; }

static void add_sub(HQUIC conn, HQUIC stream, const char* topic){
    for (int i=0;i<MAX_SUBS;i++) if(!subs[i].in_use){
        subs[i].in_use=1; subs[i].Connection=conn; subs[i].Stream=stream;
        subs[i].Role=ROLE_SUB; strncpy(subs[i].topic, topic, MAX_TOPIC-1);
        return;
    }
}
static void fanout_to_topic(const char* topic, const uint8_t* data, uint32_t len){
    for (int i=0;i<MAX_SUBS;i++) if(subs[i].in_use && subs[i].Role==ROLE_SUB
        && strncmp(subs[i].topic, topic, MAX_TOPIC)==0){
        QUIC_BUFFER qb; uint8_t* copy=(uint8_t*)malloc(len);
        if(!copy) continue; memcpy(copy,data,len);
        qb.Length=len; qb.Buffer=copy;
        MsQuic->StreamSend(subs[i].Stream,&qb,1,QUIC_SEND_FLAG_NONE,copy); // copy se libera en SEND_COMPLETE
    }
}

_Function_class_(QUIC_STREAM_CALLBACK)
static QUIC_STATUS QUIC_API StreamCb(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* E){
    (void)Context;
    switch(E->Type){
    case QUIC_STREAM_EVENT_RECEIVE: {
        for(uint32_t i=0;i<E->RECEIVE.BufferCount;i++){
            const uint8_t* buf=E->RECEIVE.Buffers[i].Buffer; uint32_t len=E->RECEIVE.Buffers[i].Length;
            if(len>=10 && !memcmp(buf,"SUBSCRIBE ",10)){
                char topic[MAX_TOPIC]={0};
                snprintf(topic,sizeof(topic),"%.*s",(int)(len-10),(const char*)buf+10);
                char* nl=strchr(topic,'\n'); if(nl)*nl=0;
                add_sub(NULL,Stream,topic);
                const char* ack="OK SUB\n"; QUIC_BUFFER qb={.Length=(uint32_t)strlen(ack),.Buffer=(uint8_t*)ack};
                MsQuic->StreamSend(Stream,&qb,1,QUIC_SEND_FLAG_NONE,NULL);
            }else if(len>=8 && !memcmp(buf,"PUBLISH ",8)){
                const char* msg=(const char*)buf+8;
                const char* bar=strchr(msg,'|'); if(!bar) continue;
                char topic[MAX_TOPIC]={0}; size_t tlen=(size_t)(bar-msg);
                if(tlen>=sizeof(topic)) tlen=sizeof(topic)-1; memcpy(topic,msg,tlen);
                fanout_to_topic(topic,(const uint8_t*)msg,(uint32_t)(len-8));
            }
        }
        MsQuic->StreamReceiveComplete(Stream,E->RECEIVE.TotalBufferLength);
        break;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        if(E->SEND_COMPLETE.ClientContext) free(E->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        for(int i=0;i<MAX_SUBS;i++) if(subs[i].in_use && subs[i].Stream==Stream) subs[i].in_use=0;
        break;
    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_CONNECTION_CALLBACK)
static QUIC_STATUS QUIC_API ConnCb(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* E){
    (void)Context;
    if(E->Type==QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED){
        MsQuic->SetCallbackHandler(E->PEER_STREAM_STARTED.Stream,(void*)StreamCb,NULL);
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_LISTENER_CALLBACK)
static QUIC_STATUS QUIC_API ListenerCb(HQUIC L, void* Ctx, QUIC_LISTENER_EVENT* E){
    (void)L; (void)Ctx;
    if(E->Type==QUIC_LISTENER_EVENT_NEW_CONNECTION){
        MsQuic->SetCallbackHandler(E->NEW_CONNECTION.Connection,(void*)ConnCb,NULL);
        return MsQuic->ConnectionSetConfiguration(E->NEW_CONNECTION.Connection, Configuration);
    }
    return QUIC_STATUS_SUCCESS;
}

int main(int argc,char**argv){
    if(argc<4){ fprintf(stderr,"Uso: %s <puerto> <cert.crt> <key.key>\n",argv[0]); return 1; }
    uint16_t port=(uint16_t)atoi(argv[1]); const char* cert=argv[2]; const char* key=argv[3];

    signal(SIGINT,on_sigint);

    CHECK_QUIC(MsQuicOpenVersion(QUIC_API_VERSION_2,(const void**)&MsQuic),"MsQuicOpenVersion");
    QUIC_REGISTRATION_CONFIG reg={ "InfracomQUIC", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    CHECK_QUIC(MsQuic->RegistrationOpen(&reg,&Registration),"RegistrationOpen");

    QUIC_SETTINGS set={0}; set.IsSet.PeerBidiStreamCount=TRUE; set.PeerBidiStreamCount=16;
    QUIC_BUFFER alpn={ .Length=(uint32_t)strlen(ALPN_STR), .Buffer=(uint8_t*)ALPN_STR };
    CHECK_QUIC(MsQuic->ConfigurationOpen(Registration,&alpn,1,&set,sizeof(set),NULL,&Configuration),"ConfigurationOpen");

    QUIC_CREDENTIAL_CONFIG cred={0};
    cred.Type=QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cred.Flags=0;
    cred.CertificateFile.CertificateFile=cert;
    cred.CertificateFile.PrivateKeyFile=key;
    CHECK_QUIC(MsQuic->ConfigurationLoadCredential(Configuration,&cred),"LoadCredential");

    CHECK_QUIC(MsQuic->ListenerOpen(Registration,ListenerCb,NULL,&Listener),"ListenerOpen");
    QUIC_ADDR addr={0}; QuicAddrSetFamily(&addr,QUIC_ADDRESS_FAMILY_INET); QuicAddrSetPort(&addr,port);
    CHECK_QUIC(MsQuic->ListenerStart(Listener,&alpn,1,&addr),"ListenerStart");

    printf("[broker_quic] escuchando en %u (ALPN=%s)\n",port,ALPN_STR);
    while(running){ usleep(200*1000); }

    MsQuic->ListenerStop(Listener); MsQuic->ListenerClose(Listener);
    MsQuic->ConfigurationClose(Configuration); MsQuic->RegistrationClose(Registration); MsQuicClose(MsQuic);
    return 0;
}
