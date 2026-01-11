#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/mman.h> // REQUIRED for mmap (Shared Memory)

#define PACKET_SIZE 64
#define TIMEOUT 10000

struct iphdr
{
    u_int8_t ihl : 4;
    u_int8_t version : 4;
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

struct icmphdr
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union
    {
        struct
        {
            uint16_t id;
            uint16_t sequence;
        } echo;
        uint32_t gateway;
        struct
        {
            uint16_t __unused;
            uint16_t mtu;
        } frag;
    } un;
};

struct packet
{
    struct icmphdr icmp;
    char msg[PACKET_SIZE - sizeof(struct icmphdr)];
};

// CHANGE 1: 'suc_counter' is now a pointer so it can be shared between processes
int *suc_counter;
double *total_rtt;
double *max_time;
double *min_time;
int printing = 0;
int pid = -1;
int FlagC;
int flood = 0;
struct protoent *proto2 = NULL;

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void display(void *buf, int bytes)
{
    struct iphdr *ip = buf;
    struct icmphdr *icmp = (struct icmphdr *)((char *)buf + ip->ihl * 4);
    struct timeval tv_recv;
    gettimeofday(&tv_recv, NULL);
    double time_ms = 0;
    if (icmp->type == 0) // Echo Reply
    {
        printing = 1;
        if (bytes >= sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct timeval))
        {
            struct timeval *tv_sent = (struct timeval *)((char *)icmp + sizeof(struct icmphdr));
            time_ms = (tv_recv.tv_sec - tv_sent->tv_sec) * 1000.0 + (tv_recv.tv_usec - tv_sent->tv_usec) / 1000.0;
            *total_rtt += time_ms;
            if (*min_time > time_ms || *min_time == 0.0) // If current min is BIGGER than new time (or it's 0)
            {
                *min_time = time_ms; // Use SINGLE '=' for assignment
            }

            if (*max_time < time_ms) // If current max is SMALLER than new time
            {
                *max_time = time_ms; // Use SINGLE '=' for assignment
            }

            if (time_ms < 0)
                time_ms = 0;
        }
    }
    printf("%d bytes from %s: seq[%d] TTL=%d time=%.3fms\n",
           ntohs(ip->tot_len) - ip->ihl * 4, inet_ntoa(ip->saddr), icmp->un.echo.sequence, ip->ttl, time_ms);
}

void listener(void)
{
    int sd, i;
    struct sockaddr_in r_addr;
    unsigned char buf[1024];

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;

    sd = socket(PF_INET, SOCK_RAW, proto2->p_proto);
    if (sd < 0)
    {
        perror("Socket creation failed");
        exit(0);
    }

    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        perror("Error setting timeout");
    }

    for (i = 0; i < FlagC; i++)
    {
        int bytes;
        socklen_t len = sizeof(r_addr);
        bzero(buf, sizeof(buf));

        bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *)&r_addr, &len);

        if (bytes > 0)
        {
            display(buf, bytes);

            // CHANGE 2: Increment the value at the pointer address
            (*suc_counter)++;

            // CHANGE 3: Fixed printf format to use value of pointer
            // printf("%d\n ", *suc_counter); // Debug print if needed
        }
        else
        {
            printf("Request timed out or error receiving.\n");
        }
    }
    close(sd);
    exit(0);
}

void ping(struct sockaddr_in *addr)
{
    const int value = 255;
    int i, sd, cnt = 1;
    struct packet pckt;
    struct sockaddr_in r_addr;
    socklen_t len = sizeof(r_addr);

    sd = socket(PF_INET, SOCK_RAW, proto2->p_proto);
    if (sd < 0)
    {
        perror("Socket creation failed");
        return;
    }

    if (setsockopt(sd, SOL_IP, IP_TTL, &value, sizeof(value)) != 0)
    {
        perror("Set TTL option failed");
    }
    if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0)
    {
        perror("Request nonblocking I/O failed");
    }

    for (i = 0; i < FlagC; i++)
    {
        if (recvfrom(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)&r_addr, &len) > 0)
        {
            // Flush old packets
        }

        bzero(&pckt, sizeof(pckt));
        pckt.icmp.type = 8; // ICMP_ECHO REQUEST
        pckt.icmp.code = 0;
        pckt.icmp.un.echo.id = pid;
        pckt.icmp.un.echo.sequence = cnt++;

        struct timeval tv;
        gettimeofday(&tv, NULL);
        memcpy(pckt.msg, &tv, sizeof(tv));

        pckt.icmp.checksum = checksum(&pckt, sizeof(pckt));

        if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)addr, sizeof(*addr)) <= 0)
            perror("sendto");

        if (flood == 1)
            sleep(1);
        else
            usleep(1000); // 1ms delay for flood
    }
    close(sd);
}

int main(int argc, char *argv[])
{
    struct timeval start_t, end_t;
    gettimeofday(&start_t, NULL);

    struct sockaddr_in dest_addr;

    // שינוי 1: אתחול כמות הפינגים ל-4 כברירת מחדל
    FlagC = 4;   
    flood = 0;   
    char *ip_str = NULL; 
    
    int opt;

    while ((opt = getopt(argc, argv, "a:c:f")) != -1) 
    {
        switch (opt) 
        {
            case 'a':
                ip_str = optarg;
                break;
            case 'c':
                FlagC = atoi(optarg);
                break;
            case 'f':
                flood = 1;
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s -a <IP address> [-c <count>] [-f]\n", argv[0]);
                return 1;
        }
    }

    // שינוי 2: כעת רק הכתובת היא חובה
    // (אבל עדיין בודקים שהמשתמש לא הזין ידנית מספר שלילי או 0)
    if (ip_str == NULL)
    {
        printf("Missing IP address (-a is required).\n");
        printf("Usage: %s -a <IP address> [-c <count>] [-f]\n", argv[0]);
        return 1;
    }

    if (FlagC <= 0)
    {
        printf("Invalid count number: %d\n", FlagC);
        return 1;
    }

    proto2 = getprotobyname("icmp");

    // המשך הקוד זהה לחלוטין...
    suc_counter = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    total_rtt = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    min_time = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    max_time = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);

    *suc_counter = 0; 
    *total_rtt = 0.0;
    *min_time = 0.0;
    *max_time = 0.0;
    
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip_str, &dest_addr.sin_addr) <= 0)
    {
        printf("Invalid IP address: %s\n", ip_str);
        return 1;
    }

    pid = getpid();

    if (fork() == 0)
    {
        listener();
    }
    else
    {
        if (flood) 
            printf("FLOODING %s with %d bytes of data:\n", ip_str, PACKET_SIZE);
        else 
            printf("Pinging %s with %d bytes of data:\n", ip_str, PACKET_SIZE);
            
        ping(&dest_addr);

        wait(NULL);
    }

    printf("\t\e[4;32m--- %s ping statistics ---\e[0m\n", ip_str);

    gettimeofday(&end_t, NULL);
    double timer = (end_t.tv_sec - start_t.tv_sec) * 1000.0 +
                   (end_t.tv_usec - start_t.tv_usec) / 1000.0;

    printf("%d packets transmitted, %d recieved, time %.3fms\n", FlagC, *suc_counter, timer);
    
    if (*suc_counter > 0)
        printf("rtt min/avg/max = %.3f %.3f %.3f \n", *min_time, *total_rtt / *suc_counter, *max_time);
    else
        printf("rtt min/avg/max = 0.000 / 0.000 / 0.000\n");

    munmap(suc_counter, sizeof(int));
    munmap(min_time, sizeof(double));
    munmap(max_time,sizeof(double));
    munmap(total_rtt ,sizeof(double));
    return 0;
}
