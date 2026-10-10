/* SPDX-License-Identifier: GPL-3.0-only */
/* One fd owner, root-only control socket, one non-replayed experiment per boot. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <linux/watchdog.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;
static int armed;
static void stop(int sig) { (void)sig; if (!armed) stopped = 1; }
static double mono(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
static int seconds(const char *s) {
    int v=0;
    if(!*s)return -1;
    for(;*s;s++){if(*s<'0' || *s>'9' || v>3600)return -1;v=v*10+(*s-'0');}
    return v>=5 && v<=3600?v:-1;
}
static int parse_request(char *request,char *kind,char *id,int *delay) {
    char *saveptr=NULL;
    char *a=strtok_r(request," \r\n",&saveptr),*b=strtok_r(NULL," \r\n",&saveptr),*c=strtok_r(NULL," \r\n",&saveptr);
    if(!a || !b || !c || strtok_r(NULL," \r\n",&saveptr) || strlen(a)>31 || strlen(b)!=36)return 0;
    strcpy(kind,a);strcpy(id,b);*delay=seconds(c);return *delay>0;
}
static int uuid_ok(const char *s) {
    if (strlen(s)!=36) return 0;
    for (int i=0;i<36;i++) {
        if (i==8 || i==13 || i==18 || i==23) {if(s[i]!='-')return 0;}
        else if (!((s[i]>='a' && s[i]<='f') || (s[i]>='0' && s[i]<='9')))return 0;
    }
    return 1;
}
static int save(const char *path,const char *json,int durable) {
    char tmp[512]; snprintf(tmp,sizeof(tmp),"%s.tmp.%d",path,getpid());
    int fd=open(tmp,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600);
    if(fd<0)return -1;
    size_t len=strlen(json); ssize_t n=write(fd,json,len);
    int ok=n==(ssize_t)len && (!durable || fsync(fd)==0);
    close(fd);
    if (!ok || rename(tmp,path)<0) {unlink(tmp);return -1;}
    if(durable) {
        char dir[512];snprintf(dir,sizeof(dir),"%s",path);char *slash=strrchr(dir,'/');
        if(slash)*slash=0;
        int d=open(dir,O_RDONLY|O_DIRECTORY);if(d<0)return -1;int r=fsync(d);close(d);if(r<0)return -1;
    }
    return 0;
}
static void info(char *dst,size_t cap,const char *file) {
    FILE *f=fopen(file,"r"); dst[0]=0;
    if(f){if(!fgets(dst,(int)cap,f))dst[0]=0;fclose(f);dst[strcspn(dst,"\r\n")]=0;}
}
int main(int argc,char **argv) {
    if(argc<4)return 2;
    int duration=seconds(argv[3]),kexec=strcmp(argv[1],"--kexec")==0;
    if(duration<10 || (!kexec && strcmp(argv[1],"--guard")) ||
       (kexec && argc!=4) || (!kexec && (argc!=5 || argv[4][0]!='/')))return 2;
    if(kexec) {
        char p[16]; info(p,sizeof(p),"/sys/module/watchdog/parameters/stop_on_reboot");
        if(strcmp(p,"0")){fprintf(stderr,"kexec requires watchdog.stop_on_reboot=0\n");return 1;}
    }
    int fd=open(argv[2],O_WRONLY|O_CLOEXEC);
    if(fd<0){perror("watchdog open");return 1;}
    int timeout=kexec?duration:30;
    if(ioctl(fd,WDIOC_SETTIMEOUT,&timeout)<0 || ioctl(fd,WDIOC_KEEPALIVE,0)<0){perror("watchdog arm");return 1;}
    fprintf(stderr,"watchdog armed: applied timeout=%d seconds\n",timeout);
    if(kexec) {
        sync();syscall(SYS_reboot,LINUX_REBOOT_MAGIC1,LINUX_REBOOT_MAGIC2,LINUX_REBOOT_CMD_KEXEC,NULL);
        perror("kexec");for(;;)pause();
    }
    signal(SIGTERM,stop);signal(SIGINT,stop);signal(SIGPIPE,SIG_IGN);
    mkdir("/run/armhpc",0755);
    struct sockaddr_un a={.sun_family=AF_UNIX};snprintf(a.sun_path,sizeof(a.sun_path),"/run/armhpc/watchdog-control.sock");
    int server=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    unlink(a.sun_path);
    if(server<0 || bind(server,(struct sockaddr*)&a,sizeof(a))<0 || chmod(a.sun_path,0600)<0 || listen(server,2)<0) {
        perror("guardian control socket");for(;;){ioctl(fd,WDIOC_KEEPALIVE,0);sleep(3);}
    }
    double started=mono(),last=started,at=0;
    char id[37]="",action[32]="",bid[80],json[1024],evidence[512]="";
    info(bid,sizeof(bid),"/proc/sys/kernel/random/boot_id");
    while(!stopped) {
        double current=mono();
        snprintf(json,sizeof(json),"{\"pid\":%d,\"boot_id\":\"%s\",\"owner\":\"0.3.4\",\"timeout_seconds\":%d,\"last_feed_monotonic\":%.6f,\"armed_test\":\"%s\",\"action\":\"%s\"}\n",getpid(),bid,timeout,last,id,action);
        save("/run/armhpc/watchdog-guardian.json",json,0);
        if(armed && current>=at) {
            snprintf(json,sizeof(json),"{\"test_id\":\"%s\",\"boot_id\":\"%s\",\"action\":\"%s\",\"stage\":\"triggered\",\"timeout_seconds\":%d,\"last_feed_monotonic\":%.6f,\"trigger_monotonic\":%.6f}\n",id,bid,action,timeout,last,current);
            if(save(evidence,json,1)<0){fprintf(stderr,"test evidence fsync failed; aborting injection and feeding\n");armed=0;at=0;continue;}
            sync();
            fprintf(stderr,"ARMHPC physical experiment %s %s triggered; fd remains owned\n",id,action);
            if(!strcmp(action,"direct-restart") || !strcmp(action,"panic")) {
                int trigger=open("/proc/sysrq-trigger",O_WRONLY);
                if(trigger>=0){const char *key=!strcmp(action,"panic")?"c":"b"; if(write(trigger,key,1)!=1)perror("sysrq");close(trigger);}
                else perror("sysrq open");
                /* Successful panic/restart never returns. Do not mislabel a failed
                   sysrq as success followed by an unrelated watchdog expiry. */
                snprintf(json,sizeof(json),"{\"test_id\":\"%s\",\"stage\":\"injection-returned\",\"action\":\"%s\"}\n",id,action);
                save(evidence,json,1);armed=0;at=0;continue;
            } else if(!strcmp(action,"reboot")) {
                pid_t child=fork();
                if(child==0){execl("/usr/bin/systemctl","systemctl","reboot",(char*)NULL);_exit(127);}
                /* Ordinary reboot is a baseline; continue feeding until shutdown. */
                armed=0;at=0;continue;
            }
            for(;;)pause(); /* No magic close, no kernel re-feed via a released fd. */
        }
        if(current-started>=duration && access(argv[4],F_OK)!=0 && !armed) {
            fprintf(stderr,"boot health deadline exceeded; allowing watchdog reset\n");for(;;)pause();
        }
        if(current-last>=3) {
            if(ioctl(fd,WDIOC_KEEPALIVE,0)<0){perror("watchdog feed");for(;;)pause();}
            last=mono();
        }
        struct pollfd p={.fd=server,.events=POLLIN};
        if(poll(&p,1,100)>0) {
            int client=accept4(server,NULL,NULL,SOCK_CLOEXEC);
            if(client<0)continue;
            struct ucred cred;socklen_t length=sizeof(cred);char request[256]={0},kind[32],tid[37];int delay;
            struct timeval tv={.tv_sec=2};setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
            ssize_t received=recv(client,request,sizeof(request)-1,0);
            int valid=received>0 && getsockopt(client,SOL_SOCKET,SO_PEERCRED,&cred,&length)==0 && cred.uid==0 &&
                parse_request(request,kind,tid,&delay) && uuid_ok(tid) && delay>=5 && delay<=30 &&
                (!strcmp(kind,"expire") || !strcmp(kind,"direct-restart") || !strcmp(kind,"panic") || !strcmp(kind,"reboot"));
            if(!valid || id[0]) {
                const char *no="REFUSED invalid or already consumed request\n";send(client,no,strlen(no),MSG_NOSIGNAL);
            } else {
                snprintf(evidence,sizeof(evidence),"/var/lib/armhpc/ota/watchdog/guardian-%s.json",tid);
                snprintf(json,sizeof(json),"{\"test_id\":\"%s\",\"boot_id\":\"%s\",\"stage\":\"accepted\",\"action\":\"%s\"}\n",tid,bid,kind);
                if(save(evidence,json,1)<0){const char *no="REFUSED durable evidence unavailable\n";send(client,no,strlen(no),MSG_NOSIGNAL);}
                else {
                    snprintf(id,sizeof(id),"%s",tid);snprintf(action,sizeof(action),"%s",kind);at=mono()+delay;armed=1;
                    char ack[128];snprintf(ack,sizeof(ack),"OK %s timeout=%d\n",id,timeout);send(client,ack,strlen(ack),MSG_NOSIGNAL);
                }
            }
            close(client);
        }
    }
    unlink(a.sun_path);close(server);
    int disable=WDIOS_DISABLECARD;
    if(ioctl(fd,WDIOC_SETOPTIONS,&disable)==0){if(write(fd,"V",1)!=1)return 1;close(fd);}
    return 0;
}
