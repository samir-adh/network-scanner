#ifndef SCANNER_H
#define SCANNER_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#define LOCALHOST "127.0.0.1"
#define NETMASK_DEFAULT "255.255.255.0"
#define TIMEOUT 100000 // 100 000µs = 0.1s
#define DEBUG false

int scan_address(in_addr_t host_ip, int *ports_list, int ports_list_size,
                 bool stop_if_unreachable);
int scan_port(struct sockaddr_in *host_address, int port);

void scan_network(in_addr_t host_ip, int netmask_len, int *ports_list,
                  int ports_list_size, bool break_if_unreachable);

uint32_t get_next_ip(uint32_t current_ip);

in_addr_t get_net_addr(in_addr_t host_ip, int netmask_len);

in_addr_t get_brd_addr(in_addr_t host_ip, int netmask_len);

#endif
