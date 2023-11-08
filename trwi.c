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

int main() {
  int sockfd, retval, n;
  socklen_t clilen;
  struct sockaddr_in cliaddr, servaddr;
  char buf[10000];
  int i;

  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
    perror("sock:");
    exit(1);
  }

  clilen = sizeof(struct sockaddr_in);
  while (1) {
    printf(" before recvfrom\n");
    n = recvfrom(sockfd, buf, 10000, 0, (struct sockaddr *)&cliaddr, &clilen);
    printf(" rec'd %d bytes\n", n);

    struct ip *ip_hdr = (struct ip *)buf;
    printf("IP header is %d bytes.\n", ip_hdr->ip_len * 4);
    char targetaddr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_dst.s_addr, targetaddr_str, INET_ADDRSTRLEN);
    printf("Target IP is %s\n", targetaddr_str);

    for (i = 0; i < n; i++) {
      printf("%02X%s", (uint8_t)buf[i], (i + 1) % 16 ? " " : "\n");
    }
    printf("\n");

    struct icmp *icmp_hdr =
        (struct icmp *)((char *)ip_hdr + (4 * ip_hdr->ip_len));
    printf("ICMP msgtype=%d, code=%d", icmp_hdr->icmp_type,
           icmp_hdr->icmp_code);
  }

  return 0;
}
