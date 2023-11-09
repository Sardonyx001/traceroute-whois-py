#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFLEN 512
#define PORT 32768 + 666 /* Stolen from the BSD implementation*/
#define TIMEOUT 2

/* The `traceroute` function is responsible for performing a traceroute to a
specified destination. It takes in a `dest_name` parameter, which is the
hostname of the destination. */
void traceroute(const char* dest_name);

/* The `sendProbe` function is responsible for sending a probe packet with a
specified time-to-live (TTL) value to a destination address using a socket. */
int sendProbe(int ttl, int sockfd, const char* dest_addr,
              struct sockaddr_in* tx_sockaddr, struct timeval* start_time);

/* The `receiveResponse` function is responsible for receiving a response from a
socket and calculating the elapsed time since the start of the operation. */
double receiveResponse(int rx, char* curr_addr_str,
                       struct sockaddr_in* rx_sockaddr,
                       struct timeval* start_time);

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <destination_hostname>\n", argv[0]);
        return 1;
    }

    const char* dest_name = argv[1];
    traceroute(dest_name);

    return 0;
}

/**
 * The `traceroute` function performs a traceroute to a given destination
 * hostname, printing the hop number, IP address, hostname, and time taken for
 * each hop.
 *
 * Args:
 *   dest_name (char): The `dest_name` parameter is a string that represents the
 * destination hostname or IP address for which the traceroute is to be
 * performed.
 */
void traceroute(const char* dest_name) {
    struct hostent* host = gethostbyname(dest_name);
    if (host == NULL) {
        fprintf(stderr, "Failed to resolve destination hostname\n");
        exit(1);
    }

    char dest_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, host->h_addr, dest_addr, INET_ADDRSTRLEN);
    printf("Traceroute to %s (%s)\n", dest_name, dest_addr);
    printf("%-5s%-20s%-50s%-10s\n", "Hop", "IP Address", "Hostname",
           "Time (ms)");
    printf(
        "---------------------------------------------------------------------"
        "-----------\n");

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

    int rx = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (rx < 0) {
        perror("socket creation failed");
        exit(1);
    }

    struct sockaddr_in rx_sockaddr;
    socklen_t rx_addr_len = sizeof(struct sockaddr_in);
    char curr_addr_str[INET_ADDRSTRLEN];
    struct timeval tv;
    tv.tv_sec = (int)TIMEOUT;
    tv.tv_usec = (int)((TIMEOUT - (int)TIMEOUT) * 1e6);
    char buf[BUFFLEN];

    for (int ttl = 1; ttl <= IPDEFTTL && strcmp(curr_addr_str, dest_addr) != 0;
         ++ttl) {
        setsockopt(tx, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        struct timeval start_time;
        gettimeofday(&start_time, NULL);

        if (sendProbe(ttl, tx, dest_addr, &tx_sockaddr, &start_time) < 0) {
            perror("sendto failed");
            close(tx);
            exit(1);
        }

        double elapsed_time =
            receiveResponse(rx, curr_addr_str, &rx_sockaddr, &start_time);

        if (elapsed_time == 0.0) {
            printf("%-5d%-20s%-50s%-10.3f ms\n", ttl, curr_addr_str, "*",
                   elapsed_time);
        } else {
            struct hostent* host =
                gethostbyaddr(curr_addr_str, INET_ADDRSTRLEN, AF_INET);
            char* hostname = (host != NULL) ? host->h_name : "";
            printf("%-5d%-20s%-50s%-10.3f ms\n", ttl, curr_addr_str, hostname,
                   elapsed_time);
        }

        memset(buf, 0, BUFFLEN);
    }

    close(rx);
    close(tx);
}

/**
 * The function sends a probe packet with a specified time-to-live (TTL) value
 * to a destination address using a socket.
 *
 * Args:
 *   ttl (int): The TTL (Time To Live) value to set for the probe packet. TTL
 * determines the maximum number of hops (routers) the packet can traverse
 * before being discarded. sockfd (int): The sockfd parameter is the socket file
 * descriptor, which is a unique identifier for a socket that is used to perform
 * various socket operations. dest_addr (char): The destination address to which
 * the probe is being sent. It is a string representation of the IP address.
 *   tx_sockaddr: The `tx_sockaddr` parameter is a pointer to a `struct
 * sockaddr_in` object. This structure contains the destination address and port
 * number to which the probe packet will be sent. start_time: The start_time
 * parameter is a pointer to a struct timeval variable. This variable is used to
 * store the start time of the probe.
 *
 * Returns:
 *   an integer value. If the sendto function call is successful, it returns 0.
 * Otherwise, it returns -1.
 */
int sendProbe(int ttl, int sockfd, const char* dest_addr,
              struct sockaddr_in* tx_sockaddr, struct timeval* start_time) {
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    if (sendto(sockfd, NULL, 0, 0, (struct sockaddr*)tx_sockaddr,
               sizeof(*tx_sockaddr)) < 0) {
        return -1;
    }

    gettimeofday(start_time, NULL);
    return 0;
}

/**
 * The function receives a response from a socket and calculates the elapsed
 * time since the start of the operation.
 *
 * Args:
 *   rx (int): The parameter "rx" is an integer representing the socket file
 * descriptor for receiving data. curr_addr_str (char): A character array that
 * will store the current address as a string. rx_sockaddr: The `rx_sockaddr`
 * parameter is a pointer to a `struct sockaddr_in` which represents the socket
 * address of the received packet. It is used to store the sender's IP address
 * and port number. start_time: A pointer to a struct timeval that represents
 * the start time of the operation.
 *
 * Returns:
 *   a double value, which represents the elapsed time in milliseconds.
 */
double receiveResponse(int rx, char* curr_addr_str,
                       struct sockaddr_in* rx_sockaddr,
                       struct timeval* start_time) {
    char buf[BUFFLEN];
    socklen_t rx_addr_len = sizeof(struct sockaddr_in);
    ssize_t rx_len = recvfrom(rx, buf, BUFFLEN, 0,
                              (struct sockaddr*)rx_sockaddr, &rx_addr_len);

    if (rx_len < 0) {
        return 0.0;
    }

    struct ip* ip_hdr = (struct ip*)buf;
    inet_ntop(AF_INET, &(rx_sockaddr->sin_addr), curr_addr_str,
              INET_ADDRSTRLEN);

    struct timeval end_time;
    gettimeofday(&end_time, NULL);

    double elapsed_time = (end_time.tv_sec - start_time->tv_sec) * 1000.0 +
                          (end_time.tv_usec - start_time->tv_usec) / 1000.0;
    return elapsed_time;
}