// publisher_quic.c — Cliente QUIC que publica N mensajes:
// "PUBLISH <topic>|seq|timestamp|EVENT|mensaje\n"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <msquic.h>

#define ALPN_STR "infracom"
#define CHECK_QUIC(st,msg) do{ if(QUIC_FAILED(st)){ fprintf(stderr,"%s:0x%x\n",msg,st); exit(1);} }while(0)

static const QUIC_API_TABLE* MsQuic=NULL;
static HQUIC Registration=NULL, Configuration=NULL, Conn=NULL, Stream=NULL;
static volatile int done=0;

static void now_ts(char* b,size_t n){
    time_t t=time(NULL); struct tm tm; localtime_r(&t,&tm); strftime(b,n,"%Y-%m-%dT%H:%M:%S",&tm);
}

_Function_class_(QUIC_STREAM_CALLBACK)
static QUIC_STATUS QUIC_API StreamCb(HQUIC S, void* Ctx, QUIC_STREAM_EVENT* E){
    (void)S; (void)Ctx;
    if(E->Type==QUIC_STREAM_EVENT_SEND_COMPLETE){
        if(E->SEND_COMPLETE.ClientContext) free(E->SEND_COMPLETE.ClientContext);
    } else if(E->Type==QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE){
        done=1;
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_CONNECTION_CALLBACK)
static QUIC_STATUS QUIC_API ConnCb(HQUIC C, void* Ctx, QUIC_CONNECTION_EVENT* E){
    (void)C; (void)Ctx;
    if(E->Type==QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) done=1;
    return QUIC_STATUS_SUCCESS;
}

int main(int argc,char**argv){
    if(argc<5){ fprintf(stderr,"Uso: %s <host> <puerto> <topic> <n>\n",argv[0]); return 1; }
    const char* host=argv[1]; uint16_t port=(uint16_t)atoi(argv[2]);
    const char* topic=argv[3]; int n=atoi(argv[4]);

    CHECK_QUIC(MsQuicOpenVersion(QUIC_API_VERSION_2,(const void**)&MsQuic),"Open");
    QUIC_REGISTRATION_CONFIG reg={"InfracomQUIC",QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    CHECK_QUIC(MsQuic->RegistrationOpen(&reg,&Registration),"RegOpen");

    QUIC_SETTINGS set={0};
    QUIC_BUFFER alpn={.Length=(uint32_t)strlen(ALPN_STR),.Buffer=(uint8_t*)ALPN_STR};
    CHECK_QUIC(MsQuic->ConfigurationOpen(Registration,&alpn,1,&set,sizeof(set),NULL,&Configuration),"CfgOpen");

    QUIC_CREDENTIAL_CONFIG cred={0};
    cred.Type=QUIC_CREDENTIAL_TYPE_NONE;
    cred.Flags=QUIC_CREDENTIAL_FLAG_CLIENT|QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    CHECK_QUIC(MsQuic->ConfigurationLoadCredential(Configuration,&cred),"Cred");

    CHECK_QUIC(MsQuic->ConnectionOpen(Registration,ConnCb,NULL,&Conn),"ConnOpen");
    CHECK_QUIC(MsQuic->ConnectionStart(Conn,Configuration,QUIC_ADDRESS_FAMILY_UNSPEC,host,port),"ConnStart");

    CHECK_QUIC(MsQuic->StreamOpen(Conn,QUIC_STREAM_OPEN_FLAG_NONE,StreamCb,NULL,&Stream),"StreamOpen");
    CHECK_QUIC(MsQuic->StreamStart(Stream,QUIC_STREAM_START_FLAG_IMMEDIATE),"StreamStart");

    printf("PUBLISHER QUIC topic=%s enviando %d mensajes…\n",topic,n);
    for(int i=1;i<=n;i++){
        char ts[64]; now_ts(ts,sizeof(ts));
        char line[1024]; int m=snprintf(line,sizeof(line),"PUBLISH %s|%d|%s|EVENT|mensaje\n",topic,i,ts);
        uint8_t* copy=(uint8_t*)malloc((size_t)m); memcpy(copy,line,(size_t)m);
        QUIC_BUFFER qb={.Length=(uint32_t)m,.Buffer=copy};
        MsQuic->StreamSend(Stream,&qb,1,QUIC_SEND_FLAG_NONE,copy);
        usleep(150*1000);
    }
    MsQuic->StreamShutdown(Stream,QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,0);
    while(!done){ usleep(300*1000); }

    MsQuic->StreamClose(Stream); MsQuic->ConnectionClose(Conn);
    MsQuic->ConfigurationClose(Configuration); MsQuic->RegistrationClose(Registration); MsQuicClose(MsQuic);
    return 0;
}
