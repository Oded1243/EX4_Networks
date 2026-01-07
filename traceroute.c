#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <poll.h>

#define PACKET_SIZE 64

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
    struct iphdr ip;
    struct icmphdr icmp;
    char msg[PACKET_SIZE - sizeof(struct icmphdr) - sizeof(struct iphdr)];
};

int reached_destination = 0;
uint32_t last_addr = 0;
int pid = -1;
int cnt = 0;
double *rtt;

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

void send_packet(int sd, struct sockaddr_in *addr, int ttl)
{
    cnt++;
    struct packet pckt;

    bzero(&pckt, sizeof(pckt));

    // IP Header
    pckt.ip.ihl = 5;
    pckt.ip.version = 4;
    pckt.ip.tos = 0;
    pckt.ip.tot_len = htons(sizeof(pckt));
    pckt.ip.id = htons(getpid());
    pckt.ip.frag_off = 0;
    pckt.ip.ttl = ttl;
    pckt.ip.protocol = IPPROTO_ICMP;
    pckt.ip.saddr.s_addr = INADDR_ANY;
    pckt.ip.daddr.s_addr = addr->sin_addr.s_addr;
    pckt.ip.check = checksum(&pckt.ip, sizeof(struct iphdr));

    // ICMP Header
    pckt.icmp.type = 8; // ICMP_ECHO REQUEST
    pckt.icmp.code = 0;
    pckt.icmp.un.echo.id = htons(getpid());
    pckt.icmp.un.echo.sequence = htons(ttl);
    pckt.icmp.checksum = checksum(&pckt.icmp, sizeof(struct icmphdr) + sizeof(pckt.msg));

    if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)addr, sizeof(*addr)) <= 0)
        perror("sendto");
}

int wait_for_reply(int sd, struct sockaddr_in *dest_addr, struct timeval *start_time)
{
    struct pollfd pfd; // poll structure
    pfd.fd = sd;
    pfd.events = POLLIN; // waiting for data

    int ret = poll(&pfd, 1, 1000); // timeout of 1 sec

    if (ret == 0) // no response
    {
        printf("* \t");
        return 0;
    }
    
    else if (ret < 0) // error
    {
        perror("poll error");
        return 0;
    }

    else // data is available
    {
        struct sockaddr_in r_addr; // received address
        unsigned char buf[1024];   // buffer for received packet
        socklen_t len = sizeof(r_addr);

        int bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *)&r_addr, &len); // receive packet

        if (bytes <= 0) // error in receiving
            return 0;

        struct timeval end_time; // end time for RTT calculation
        gettimeofday(&end_time, NULL);

        double rtt = (end_time.tv_sec - start_time->tv_sec) * 1000.0 + 
                     (end_time.tv_usec - start_time->tv_usec) / 1000.0; // calc for RTT

        struct iphdr *ip = (struct iphdr *)buf; // IP header
        int ip_len = ip->ihl * 4; // IP header length
        struct icmphdr *icmp = (struct icmphdr *)(buf + ip_len); // ICMP header

        if (icmp->type == 11 || icmp->type == 0) // Time Exceeded or Echo Reply
        {
            if (r_addr.sin_addr.s_addr == last_addr)
            {
                printf("  %.3f ms", rtt);
            }
            else
            {
                printf("  %s  %.3f ms", inet_ntoa(r_addr.sin_addr), rtt);
                last_addr = r_addr.sin_addr.s_addr;
            }
            if (r_addr.sin_addr.s_addr == dest_addr->sin_addr.s_addr && icmp->type == 0)
            {
                reached_destination = 1;
                return 1;
            }
        }
        return 0; // reacht to router
    }
}

int main(int argc, char *argv[])
{
    char *ip_str = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "a:")) != -1)
    {
        switch (opt)
        {
        case 'a':
            ip_str = optarg; // assign the IP address
            break;
        default:
            fprintf(stderr, "Usage: %s -a <IP address>\n", argv[0]);
            return 1;
        }
    }

    if (ip_str == NULL) // check if IP address is provided
    {
        fprintf(stderr, "Error: Missing IP address. Usage: %s -a <IP address>\n", argv[0]);
        return 1;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip_str, &dest_addr.sin_addr) <= 0) // validate IP address
    {
        fprintf(stderr, "Error: Invalid IP address '%s'\n", ip_str);
        return 1;
    }

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // create raw socket
    if (sd < 0)
    {
        perror("Socket creation failed (Did you run with sudo?)");
        return 1;
    }

    int on = 1; // define for pc that we include IP header ourselves
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt failed");
        close(sd);
        return 1;
    }

    printf("traceroute to %s, 30 hops max\n", ip_str);

    int res = 0;

    for (int ttl = 1; ttl <= 30; ttl++) // loop over TTL values
    {

        printf("%2d ", ttl);
        last_addr = 0; // reset last_addr for new TTL

        for (int retry = 0; retry < 3; retry++) // 3 attempts per TTL
        {
            struct timeval start_time;
            gettimeofday(&start_time, NULL);

            send_packet(sd, &dest_addr, ttl); // sand the packet

            res = wait_for_reply(sd, &dest_addr, &start_time); // wating for reply

            if (res == 1)
                reached_destination = 1;
        }

        printf("\n");

        if (ttl == 30 && res == 0)
        {
            printf("Reached maximum hops without reaching destination.\n");
        }

        if (reached_destination)
        {
            break;
        }
        
    }

    close(sd);
    return 0;
}