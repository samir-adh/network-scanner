#ifndef CLIENT_H
#define CLIENT_H

#include "../scan_tools/scan_tools.h"
#include <arpa/inet.h>
#include <bits/getopt_core.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void print_help_msg(char *name);

void scan_network_default(in_addr_t host_ip, int netmask_len,
                          bool stop_if_unreachable);

#endif
