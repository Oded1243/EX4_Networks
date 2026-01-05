#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> // socket(), bind(), listen(), accept()
#include <netinet/in.h> // struct sockaddr_in
#include <arpa/inet.h> // inet_pton()
#include <unistd.h> // close()
#include <string.h>
#include <fcntl.h> // fcntl()
#include <netdb.h> // getprotobyname()
#include <sys/wait.h>
#include <sys/time.h>
#define PACKET_SIZE 64
#define TIMEOUT 10000 // in milliseconds

struct iphdr {
    u_int8_t ihl:4;
    u_int8_t version:4;
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    struct in_addr saddr;
    struct in_addr daddr;
};

struct icmphdr {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  
  union {              
    struct {
      uint16_t id;     
      uint16_t sequence;
    } echo;            
    
    uint32_t gateway;  
    
    struct {
      uint16_t __unused;
      uint16_t mtu;
    } frag;            
  } un;
};

struct packet {
    struct icmphdr icmp;
    char msg[PACKET_SIZE - sizeof(struct icmphdr)];
};

int pid = -1;
int FlagC;
int flood = 0;
struct protoent *proto2 = NULL;

unsigned short checksum(void *b, int len) {    
    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void display(void *buf, int bytes) {
    int i;
   struct iphdr *ip = buf;
    struct icmphdr *icmp = buf+ip->ihl*4;
    printf("----------------\n");
    for ( i = 0; i < bytes; i++ )       {
        if ( !(i & 15) ) printf("\n%04X:  ", i);
        printf("%02X ", ((unsigned char*)buf)[i]);
    }
    printf("\n");
    printf("IPv%d: hdr-size=%d pkt-size=%d protocol=%d TTL=%d src=%s ",
           ip->version, ip->ihl*4, ntohs(ip->tot_len), ip->protocol,
           ip->ttl, inet_ntoa(ip->saddr));
    printf("dst=%s\n", inet_ntoa(ip->daddr));
    if ( icmp->un.echo.id == pid ) {
        printf("ICMP: type[%d/%d] checksum[%d] id[%d] seq[%d]\n",
               icmp->type, icmp->code, ntohs(icmp->checksum),
               icmp->un.echo.id, icmp->un.echo.sequence);
    }
}

void listener(void) {
    int sd, i;
    struct sockaddr_in r_addr;
    unsigned char buf[1024];
    
    struct timeval tv;
    tv.tv_sec = 10;  
    tv.tv_usec = 0;

    sd = socket(PF_INET, SOCK_RAW, proto2->p_proto);
    if (sd < 0) {
        perror("Socket creation failed");
        exit(0);
    }

    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Error setting timeout");
    }

    for (i = 0; i < FlagC; i++) {
        int bytes, len = sizeof(r_addr);
        bzero(buf, sizeof(buf));
        

        bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *)&r_addr, &len);
        
        if (bytes > 0) {
            display(buf, bytes);
        } else {

            printf("Request timed out or error receiving.\n");
        }
    }
    close(sd);
    exit(0);
}

void ping(struct sockaddr_in *addr) {
    printf("Ping function called\n");
    const int value = 255;
    int i, sd, cnt = 1;
    struct packet pckt;
    struct sockaddr_in r_addr;
    int len = sizeof(r_addr);

    sd = socket(PF_INET, SOCK_RAW, proto2->p_proto);
    if (sd < 0) {
        perror("Socket creation failed");
        return;
    }

    if (setsockopt(sd, SOL_IP, IP_TTL, &value, sizeof(value)) != 0) {
        perror("Set TTL option failed");
    }
    if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0) {
        perror("Request nonblocking I/O failed");
    }

    for (i = 0; i < FlagC; i++) {
        if (recvfrom(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)&r_addr, &len) > 0) {
            printf("***Got message!***\n");
        }

        
        bzero(&pckt, sizeof(pckt));
        pckt.icmp.type = 8; // ICMP_ECHO REQUEST
        pckt.icmp.code = 0;
        pckt.icmp.un.echo.id = pid;
        pckt.icmp.un.echo.sequence = cnt++;
        
        int msg_len = sizeof(pckt.msg) - 1;
        for (int k = 0; k < msg_len; k++)
            pckt.msg[k] = k + '0';
        pckt.msg[msg_len] = 0;

        pckt.icmp.checksum = checksum(&pckt, sizeof(pckt));

        if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)addr, sizeof(*addr)) <= 0)
            perror("sendto");
        
        if (flood == 0) {
            sleep(1);
        } else {
            usleep(1000);
        }
    }
}

int main() {
    char ip_str[100];
    struct sockaddr_in dest_addr;

    proto2 = getprotobyname("icmp");
    
    printf("Enter IP address to ping: ");
    scanf("%99s", ip_str);

    printf("How many pings to send: ");
    scanf("%d", &FlagC);

    printf("Enable Flood mode? (1 for Yes, 0 for No): ");
    scanf("%d", &flood);

    if (FlagC <= 0) {
        printf("Usage: invalid count\n");
        return 1;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    
    if (inet_pton(AF_INET, ip_str, &dest_addr.sin_addr) <= 0) {
        printf("Invalid IP address: %s\n", ip_str);
        return 1;
    }

    pid = getpid();

    if (fork() == 0) {
        listener(); 
    } else {
        ping(&dest_addr);
        wait(NULL);
    }

    return 0;
}