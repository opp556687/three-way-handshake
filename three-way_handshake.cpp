#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <getopt.h>
using namespace std;

//Pseudo header needed for calculating the TCP header checksum
struct pseudohdr
{
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t TCP_len;
};

// use to parse argument
struct option long_options[] = {
    {"help", no_argument, NULL, 'H'},
    {"server-ip", no_argument, NULL, 's'},
    {"server-port", required_argument, NULL, 'p'},
    {"source-ip", required_argument, NULL, 'i'},
    {NULL, no_argument, NULL, 0},
};

// use to compute checksum
unsigned short checkSum(unsigned short *buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size)
        cksum += *(unsigned char *)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}

void print_help()
{
    cout << "usage:" << endl;
    cout << "-s set server ip" << endl;
    cout << "-p set server port (default 4096)" << endl;
    cout << "-i set host ip" << endl;
}

int main(int argc, char *argv[])
{
    srand(time(NULL));
    int command_option;
    in_port_t server_port = 4096;
    in_addr_t source_port = 3333 % (rand() % (50000 - 3333 + 1)); // random source port in 3333~50000
    char *server_ip, *source_ip, *interface;
    uint32_t sequence = 0;
    int socketfd;
    char send_packet[BUFSIZ], recv_packet[BUFSIZ];

    while ((command_option = getopt_long(argc, argv, "hp:s:i:", long_options, NULL)) != -1)
    {
        switch (command_option)
        {
        case '?':
            cout << "[!] use -h or --help to get more information" << endl;
            exit(0);
        case 'h':
        case 'H':
            print_help();
            exit(0);
        case 's':
            server_ip = new char[strlen(optarg) + 1];
            strncpy(server_ip, optarg, strlen(optarg));
            break;
        case 'p':
            sscanf(optarg, "%hu", &server_port);
            break;
        case 'i':
            source_ip = new char[strlen(optarg) + 1];
            strncpy(source_ip, optarg, strlen(optarg));
            break;
        default:
            cout << "[!] invalid argument" << endl;
            exit(0);
        }
    }

    if (source_ip == NULL)
    {
        cout << "[!] use -i to set host ip" << endl;
        exit(0);
    }

    if (server_ip == NULL)
    {
        cout << "[!] use -s to set server ip" << endl;
        exit(0);
    }

    // init buffer, ip, tcp
    memset(send_packet, 0, BUFSIZ);
    memset(recv_packet, 0, BUFSIZ);
    iphdr *ip = (iphdr *)send_packet;
    tcphdr *tcp = (tcphdr *)(send_packet + sizeof(iphdr));
    pseudohdr pse;

    // socket init
    sockaddr_in sin;
    sin.sin_family = PF_INET;
    sin.sin_port = htons(server_port);
    sin.sin_addr.s_addr = inet_addr(server_ip);

    // ip header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(iphdr) + sizeof(tcphdr);
    ip->id = 0x0000;
    ip->frag_off = 0;
    ip->ttl = 0x40;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0; // set 0 before compute checksum
    ip->saddr = inet_addr(source_ip);
    ip->daddr = sin.sin_addr.s_addr;
    ip->check = checkSum((unsigned short *)send_packet, ip->tot_len); // ip checksum

    //tcp header
    tcp->source = htons(source_port);
    tcp->dest = htons(server_port);
    tcp->seq = htonl(sequence);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->window = 0xffff;
    tcp->urg = 0;
    tcp->fin = 0;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->check = 0;
    tcp->urg_ptr = 0;

    // pseudo header for tcp cheksum
    pse.srcAddr = inet_addr(source_ip);
    pse.dstAddr = sin.sin_addr.s_addr;
    pse.protocol = IPPROTO_TCP;
    pse.zero = 0;
    pse.TCP_len = htons(sizeof(tcphdr));
    int psize = sizeof(pseudohdr) + sizeof(tcphdr);
    void *pse_header = malloc(psize);
    memcpy(pse_header, (void *)&pse, sizeof(pseudohdr));
    memcpy((uint8_t *)pse_header + sizeof(pseudohdr), tcp, sizeof(tcphdr));
    tcp->check = checkSum((unsigned short *)pse_header, psize);

    // create raw socket fd
    if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        perror("[!] fail to create raw_socket\n");
        exit(0);
    }

    int yes = 1;
    if (setsockopt(socketfd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes)) < 0) // do not create ip header in kernel
    {
        perror("[!] setsockopt fail\n");
        close(socketfd);
        exit(0);
    }

    if (sendto(socketfd, send_packet, ip->tot_len, 0, (sockaddr *)&sin, sizeof(sin)) < 0)
    {
        perror("[!] fail to send SYN\n");
        close(socketfd);
        exit(0);
    }
    std::cout << "[+] SYN send to server" << endl;

    int n = recv(socketfd, recv_packet, sizeof(recv_packet), 0);
    if (n == -1)
    {
        perror("[!] recv error\n");
        close(socketfd);
        exit(0);
    }
    cout << "[+] recv SYN ACK from server" << endl;

    iphdr *ip_recv = (iphdr *)(recv_packet);
    tcphdr *tcp_recv = (tcphdr *)(recv_packet + sizeof(tcphdr));
    tcp->ack_seq = htonl(ntohl(tcp_recv->seq) + 1);
    tcp->ack = 1;
    tcp->seq = htonl(sequence + 1);
    tcp->syn = 0;
    tcp->check = 0;
    // compute new checksum
    memcpy((uint8_t *)pse_header + sizeof(pseudohdr), tcp, sizeof(tcphdr));
    tcp->check = checkSum((unsigned short *)pse_header, psize);

    if (sendto(socketfd, send_packet, ip->tot_len, 0, (sockaddr *)&sin, sizeof(sin)) < 0)
    {
        perror("[!] send ACK fail\n");
        close(socketfd);
        exit(0);
    }
    cout << "[+] send ACK to server" << endl;

    close(socketfd);
    return 0;
}
