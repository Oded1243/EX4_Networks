#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <poll.h>
#include <ifaddrs.h>
#define FLAG_SYN 0x02 // 0000 0010
#define FLAG_RST 0x04 // 0000 0100
#define FLAG_ACK 0x10 // 0001 0000

typedef struct TCPHeader
{
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t reserved : 4;
    uint8_t data_offset : 4;

    uint8_t fin : 1;
    uint8_t syn : 1;
    uint8_t rst : 1;
    uint8_t psh : 1;
    uint8_t ack : 1;
    uint8_t urg : 1;
    uint8_t ece : 1;
    uint8_t cwr : 1;

    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} TCPHeader;

typedef struct IPHeader
{
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t tos; // Type of Service
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol; // Protocol (TCP=6, UDP=17)
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} IPHeader;

typedef struct UDPHeader
{
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t check;
} UDPHeader;

struct PseudoHeader
{
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder; // חייב להיות 0
    uint8_t protocol;    // חייב להיות IPPROTO_TCP (שזה 6)
    uint16_t tcp_length; // גודל ה-TCP Header + Data
};

uint32_t get_local_ip_via_interface()
{
    struct ifaddrs *ifaddr, *ifa;
    uint32_t final_ip = 0;

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return 0;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            // --- התיקון: בדיקה לפי שם הממשק ---
            // אם הממשק הוא lo (Loopback), דלג עליו מיד
            if (strcmp(ifa->ifa_name, "lo") == 0)
                continue;

            struct sockaddr_in *pAddr = (struct sockaddr_in *)ifa->ifa_addr;
            final_ip = pAddr->sin_addr.s_addr;

            printf("Found IP on interface %s: %s\n",
                   ifa->ifa_name, inet_ntoa(pAddr->sin_addr));

            // מצאנו ממשק אמיתי (כמו eth0 או wlan0), אפשר לעצור
            break;
        }
    }

    freeifaddrs(ifaddr);
    return final_ip;
}

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

// פונקציית עזר לחישוב Checksum עבור TCP
unsigned short calculate_tcp_checksum(struct TCPHeader *tcp, uint32_t src_ip, uint32_t dest_ip)
{
    struct PseudoHeader psh;

    // 1. מילוי ה-Pseudo Header
    psh.source_address = src_ip;
    psh.dest_address = dest_ip;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP; // הערך 6
    psh.tcp_length = htons(sizeof(struct TCPHeader));

    // 2. יצירת באפר זמני ("הסנדוויץ'") שמכיל גם את הפסאודו וגם את ה-TCP
    int psize = sizeof(struct PseudoHeader) + sizeof(struct TCPHeader);

    // הקצאת זיכרון לבאפר הזמני
    char *pseudogram = malloc(psize);
    if (!pseudogram)
    {
        perror("malloc failed");
        exit(1);
    }

    // 3. העתקת המידע לבאפר לפי הסדר
    memcpy(pseudogram, (char *)&psh, sizeof(struct PseudoHeader));
    memcpy(pseudogram + sizeof(struct PseudoHeader), tcp, sizeof(struct TCPHeader));

    // 4. קריאה לפונקציית ה-checksum שלך על כל הבאפר הזה
    unsigned short result = checksum((unsigned short *)pseudogram, psize);

    // 5. שחרור הזיכרון
    free(pseudogram);

    return result;
}

void send_packet_TCP(int sd, struct sockaddr_in *dest_addr, int port, uint32_t my_ip, int flags, uint32_t seq_num, uint32_t ack_num)
{
    char buffer[4096];
    memset(buffer, 0, 4096);

    struct TCPHeader *tcp = (struct TCPHeader *)buffer;

    tcp->source_port = htons(12345);
    tcp->dest_port = htons(port);

    // שינוי 1: שימוש בפרמטרים שהתקבלו
    tcp->seq_num = htonl(seq_num);
    tcp->ack_num = htonl(ack_num);

    tcp->reserved = 0;
    tcp->data_offset = 5;

    // שינוי 2: קביעת הדגלים לפי הפרמטר flags
    // אנו בודקים אם הביט הרלוונטי דלוק ב-flags
    tcp->fin = 0;
    tcp->syn = (flags & FLAG_SYN) ? 1 : 0; // אם ביקשנו SYN
    tcp->rst = (flags & FLAG_RST) ? 1 : 0; // אם ביקשנו RST
    tcp->psh = 0;
    tcp->ack = (flags & FLAG_ACK) ? 1 : 0; // אם צריך ACK (בדרך כלל עם RST לא צריך, אבל טוב שיש)
    tcp->urg = 0;
    tcp->ece = 0;
    tcp->cwr = 0;

    tcp->window_size = htons(5840);
    tcp->urgent_pointer = 0;
    tcp->checksum = 0;

    // חישוב Checksum ושליחה (נשאר אותו דבר)
    tcp->checksum = calculate_tcp_checksum(tcp, my_ip, dest_addr->sin_addr.s_addr);

    if (sendto(sd, buffer, sizeof(struct TCPHeader), 0, (struct sockaddr *)dest_addr, sizeof(*dest_addr)) < 0)
    {
        // perror("sendto failed"); // אפשר להחזיר את ההדפסה אם רוצים דיבאג
    }
}
void send_packet_UDP(int sd, struct sockaddr_in *dest_addr)
{
    // שולח פאקט ריק. המערכת תוסיף לבד כותרות UDP תקינות
    if (sendto(sd, NULL, 0, 0, (struct sockaddr *)dest_addr, sizeof(*dest_addr)) < 0)
    {
        perror("sendto UDP failed");
    }
}

int main(int argc, char *argv[])
{
    char *ip_str = NULL;
    char *type = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "a:t:")) != -1)
    {
        switch (opt)
        {
        case 'a':
            ip_str = optarg;
            break;
        case 't':
            type = optarg;
            break;
        default:
            fprintf(stderr, "Usage: %s -a <IP address> -t <type>\n", argv[0]);
            return 1;
        }
    }

    if (type != NULL && strcasecmp(type, "tcp") == 0)
    {
        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;

        if (inet_pton(AF_INET, ip_str, &dest_addr.sin_addr) <= 0)
        {
            fprintf(stderr, "Error: Invalid IP address '%s'\n", ip_str);
            return 1;
        }

        uint32_t my_ip = get_local_ip_via_interface();
        if (my_ip == 0)
        {
            printf("Error: Could not find local IP\n");
            return 1;
        }

        int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sd < 0)
        {
            perror("Socket creation failed (Did you run with sudo?)");
            return 1;
        }

        struct timeval tv;
        tv.tv_sec = 2; // שניה אחת
        tv.tv_usec = 0;
        if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv) < 0)
        {
            perror("Error setting socket timeout");
            return 1;
        }

        for (int port = 1; port <= 100; port++)
        {
            // printf("Scanning port %d...\n", port);

            // --- שינוי 1: קריאה לפונקציה המעודכנת עם דגל SYN ---
            // אנחנו שולחים: FLAG_SYN (או 2), מספר רצף אקראי, ו-0 ב-ack
            send_packet_TCP(sd, &dest_addr, port, my_ip, FLAG_SYN, rand(), 0);

            char recv_buffer[4096];
            struct sockaddr_in source_addr;
            socklen_t addr_len = sizeof(source_addr);

            int bytes_received = recvfrom(sd, recv_buffer, sizeof(recv_buffer), 0,
                                          (struct sockaddr *)&source_addr, &addr_len);

            if (bytes_received > 0)
            {
                struct IPHeader *ip_resp = (struct IPHeader *)recv_buffer;
                int ip_header_len = ip_resp->ihl * 4;

                if (bytes_received >= ip_header_len + sizeof(struct TCPHeader))
                {
                    struct TCPHeader *tcp_resp = (struct TCPHeader *)(recv_buffer + ip_header_len);

                    if (ntohs(tcp_resp->source_port) == port && source_addr.sin_addr.s_addr == dest_addr.sin_addr.s_addr)
                    {
                        printf("Port %d responded. Flags: SYN=%d, ACK=%d, RST=%d\n",
                               port, tcp_resp->syn, tcp_resp->ack, tcp_resp->rst);
                        if (tcp_resp->syn == 1 && tcp_resp->ack == 1)
                        {
                            printf("[+] Port %d is OPEN\n", port);

                            // --- שינוי 2: הוספת שליחת RST לסגירת החיבור ---
                            // אנחנו שולחים: FLAG_RST (או 4)
                            // ה-Sequence שלנו הוא ה-Ack שהשרת שלח לנו (ntohl)
                            send_packet_TCP(sd, &dest_addr, port, my_ip, FLAG_RST, ntohl(tcp_resp->ack_num), 0);
                        }
                        else if (tcp_resp->rst == 1)
                        {
                            printf("[-] Port %d is CLOSED\n", port);
                        }
                    }
                }
            }
        }

        close(sd);
    }
    else if (type != NULL && strcasecmp(type, "udp") == 0)
    {
        // סוקט לשליחת UDP ולקבלת תשובות UDP (במקרה של הצלחה)
        int udp_sd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_sd < 0)
        {
            perror("UDP Socket creation failed");
            return 1;
        }

        // סוקט לקבלת שגיאות ICMP (במקרה של פורט סגור)
        int icmp_sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (icmp_sd < 0)
        {
            perror("ICMP Socket creation failed");
            return 1;
        }

        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip_str, &dest_addr.sin_addr) <= 0)
        {
            fprintf(stderr, "Error: Invalid IP address\n");
            return 1;
        }

        printf("Starting UDP Scan on %s...\n", ip_str);
        char buffer[4096];

        for (int port = 1; port <= 150; port++) // סורק 100 פורטים
        {
            dest_addr.sin_port = htons(port);

            // שליחת הפאקט
            send_packet_UDP(udp_sd, &dest_addr);

            // --- התיקון: האזנה לשני הסוקטים ---
            struct pollfd fds[2];

            // ערוץ 1: האם קיבלנו UDP חזרה? (הצלחה)
            fds[0].fd = udp_sd;
            fds[0].events = POLLIN;

            // ערוץ 2: האם קיבלנו ICMP חזרה? (כישלון)
            fds[1].fd = icmp_sd;
            fds[1].events = POLLIN;

            // מחכים לתשובה באחד מהערוצים
            int ret = poll(fds, 2, 2000); // 2 שניות timeout

            if (ret > 0)
            {
                // בדיקה 1: התקבלה תשובה ב-UDP (פורט פתוח!)
                if (fds[0].revents & POLLIN)
                {
                    // חובה לקרוא את המידע כדי לנקות את הסוקט
                    recvfrom(udp_sd, buffer, sizeof(buffer), 0, NULL, NULL);
                    printf("[+] Port %d is OPEN\n", port);
                }
                // בדיקה 2: התקבלה הודעת ICMP (פורט סגור)
                else if (fds[1].revents & POLLIN)
                {
                    struct sockaddr_in source_addr;
                    socklen_t addr_len = sizeof(source_addr);
                    int bytes = recvfrom(icmp_sd, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_addr, &addr_len);

                    if (bytes > 0)
                    {
                        struct IPHeader *ip_header = (struct IPHeader *)buffer;
                        // וידוא שזה אכן ICMP
                        if (ip_header->protocol == 1)
                        {
                            // דילוג על ה-IP Header כדי להגיע ל-ICMP Header
                            int ip_len = ip_header->ihl * 4;
                            unsigned char *icmp_data = (unsigned char *)(buffer + ip_len);
                            int type = icmp_data[0];
                            int code = icmp_data[1];

                            // Type 3 = Dest Unreachable, Code 3 = Port Unreachable
                            if (type == 3 && code == 3)
                            {
                                printf("[-] Port %d is CLOSED (ICMP Port Unreachable)\n", port);
                            }
                            else
                            {
                                printf("[-] Port %d is FILTERED (ICMP Type %d)\n", port, type);
                            }
                        }
                    }
                }
            }
            else
            {
                // Timeout - לא התקבל כלום
                printf("[-] Port %d is CLOSED (Timeout)\n", port);
            }
        }
        close(udp_sd);
        close(icmp_sd);
    }
    else
    {
        fprintf(stderr, "Invalid type. Use tcp or udp.\n");
    }
    return 0;
}