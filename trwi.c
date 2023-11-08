/*
 * WIP: For now this is simply an ICMP listener
 * It listens for any incoming ICMP packets and
 * extracts the sender IP (+ outputs the whole
 * packet as hex for debugging)
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFLEN 512
#define PORT 32768+666

/**
 * Creates a raw socket, receives ICMP packets, and prints information about the
 * received packets.
 */
int main() {
    int rx;
    int rx_bytes;
    struct sockaddr_in rx_sockaddr;

    int tx;
    struct sockaddr_in tx_sockaddr;

    char buf[BUFFLEN];
    socklen_t socklen = sizeof(struct sockaddr_in);

    /* Check if socket creation for either the ICMP or UDP socket failed. */
    rx = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (rx < 0 || tx < 0) {
        perror("socket failed");
        exit(1);
    }
    int ttl = 0;
    char curr_addr[INET_ADDRSTRLEN];
    
    
    while (ttl++ < IPDEFTTL) {
        printf("Sending empty UDP packet...\n");



        printf("Waiting for ICMP packet...\n");
        rx_bytes = recvfrom(rx, buf, BUFFLEN, 0, (struct sockaddr *)&rx_sockaddr, &socklen);

        struct ip *ip_hdr = (struct ip *)buf;
        inet_ntop(AF_INET, &ip_hdr->ip_dst.s_addr, curr_addr, INET_ADDRSTRLEN);
        printf("IP %s\n", curr_addr);
        
    }

    close(rx);
    close(tx);

    return 0;
}
