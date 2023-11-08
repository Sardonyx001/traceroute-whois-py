/*
 * WIP: For now this is simply an ICMP listener
 * It listens for any incoming ICMP packets and
 * extracts the sender IP (+ outputs the whole
 * packet as hex for debugging)
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#define BUFFLEN 512
#define PORT 32768+666
#define TIMEOUT 2

/**
 * Sends UDP probes with increasing TTL while receiving ICMP packets until timeout 
 * or target is reached and prints information about route
 */
int main(int argc, char *argv[]) {
    /* Handle IO */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <destination_hostname>\n", argv[0]);
        return 1;
    }

    char* dest_name = argv[1];
    struct hostent* host = gethostbyname(dest_name);
    if (host == NULL) {
        fprintf(stderr, "Failed to resolve destination hostname\n");
        return 1;
    }
    char dest_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, host->h_addr, dest_addr, INET_ADDRSTRLEN);
    printf("Traceroute to %s (%s)\n", dest_name, dest_addr);
    printf("%-5s%-20s%-50s%-10s\n", "Hop", "IP Address", "Hostname", "Time (ms)");
    printf("--------------------------------------------------------------------------------\n");

    /* Define tx (UDP socket) */
    int tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (tx < 0) {
        perror("socket creation failed");
        exit(1);
    }
    struct sockaddr_in tx_sockaddr;
    tx_sockaddr.sin_family = AF_INET;
    tx_sockaddr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, dest_addr, &(tx_sockaddr.sin_addr)) <= 0) {
        perror("invalid address");
        close(tx);
        exit(1);
    }
    
    /* Define rx (ICMP socket) */
    int rx = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (rx < 0) {
        perror("socket creation failed");
        exit(1);
    }
    struct sockaddr_in rx_sockaddr;
    socklen_t rx_addr_len = sizeof(struct sockaddr_in);

    char curr_addr_str[INET_ADDRSTRLEN];
    double elapsed_time;
    struct timeval tv;
    tv.tv_sec = (int)TIMEOUT;
    tv.tv_usec = (int)((TIMEOUT - (int)TIMEOUT) * 1e6);
    char buf[BUFFLEN];

    for (int ttl = 1; ttl <= IPDEFTTL && strcmp(curr_addr_str, dest_addr)!=0; ++ttl) {
        setsockopt(tx, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        
        /* Get send time and set timeout*/
        struct timeval start_time;
        gettimeofday(&start_time, NULL);

        /* Send probe */
        if (sendto(tx, NULL, 0, 0,
                (struct sockaddr*)&tx_sockaddr, sizeof(tx_sockaddr)) < 0) 
        {
            perror("sendto failed");
            close(tx);
            exit(1);
        }
        /* Check ICMP response*/
        ssize_t rx_len = recvfrom(rx, buf, BUFFLEN, 0,
                (struct sockaddr*)&rx_sockaddr, &rx_addr_len);
        if (rx_len < 0) {
            elapsed_time = 0.0;
            printf("%-5d%-20s%-50s%-10.3f ms\n", ttl, curr_addr_str, "*", elapsed_time);
        } else {
            /* Get target IP address from response */
            struct ip *ip_hdr = (struct ip *)buf;
            inet_ntop(AF_INET, &(rx_sockaddr.sin_addr), curr_addr_str, INET_ADDRSTRLEN);

            /* Get recv time */
            struct timeval end_time;
            gettimeofday(&end_time, NULL);
            double elapsed_time = (end_time.tv_sec - start_time.tv_sec) * 1000.0 + (end_time.tv_usec - start_time.tv_usec) / 1000.0;
            
            /* Get hostname from target IP and display trace info*/
            struct hostent* host = gethostbyaddr(curr_addr_str, INET_ADDRSTRLEN, AF_INET);
            char* hostname = (host != NULL) ? host->h_name : "";
            printf("%-5d%-20s%-50s%-10.3f ms\n", ttl, curr_addr_str, hostname, elapsed_time);
        }
        memset(buf, 0, BUFFLEN);
    }

    close(rx);
    close(tx);

    return 0;
}
