#include <stdio.h>
#ifndef DEFINITION_H
#define DEFINITION_H 1
#include <arpa/inet.h>  //inet_addr
#include <errno.h>      //indicate error on socket
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>  //strlen'
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>  // close()socket
#define DEFAULT_dns_server_ip "10.3.9.4"
// #include"function.h"
// #define DEFAULT_dns_server_ip "202.106.0.20"
// #define DEFAULT_dns_server_ip "10.3.179.119"
#define PORT 53
#define A 1
#define CNAME 5
#define ANS_RR_LEN 16
#define FLAG_RESPONSE 0x8180
#define FLAG_RESPONSE_ERROR 0x8183  // Rcode=3
#define OFFSET_TO_FIRST_QUR 0xC00C

#define BLOCKED_IP "0.0.0.0"

#define FILE_PATH_MAX_LEN 80
#define BUFFER_SIZE 9999
#define IP_LEN 16
#define DOMAIN_LEN 2048   // max len of url
#define MAX_QUESTION 10   // 1 question in a query
#define MAX_INURL_LEN 64  // each section of url should be less than 64byte
#define MAX_ANSWER 20
#define MAX_IP 5
#define ID_TABLE_SIZE 200
#define TTL_DNS 2000
#define WAIT_TIME 2
// IPv4 AF_INET sockets:
/*struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET, AF_INET6
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};

struct in_addr {
    unsigned long s_addr;          // load with inet_pton()
};

struct sockaddr {
    unsigned short    sa_family;    // address family, AF_xxx
    char              sa_data[14];  // 14 bytes of protocol address
};
*/
struct header_raw {
  unsigned ID : 16;  // ID
  unsigned QR : 1;   // 0:query 1:response
  unsigned Opcode : 4;
  unsigned AA : 1;  // authorized
  unsigned TC : 1;  // 1: trucanted
  unsigned RD : 1;
  unsigned RA : 1;
  unsigned Z : 3;
  unsigned RCODE : 4;
  unsigned QDCOUNT : 16;  // question count
  unsigned ANCOUNT : 16;  // answerc count
  unsigned NSCOUNT : 16;
  unsigned ARCOUNT : 16;
};
struct RR_raw {
  unsigned offset : 2;
  unsigned type : 2;
  unsigned _class : 2;
  unsigned ttl : 4;
  unsigned data_len : 2;
  unsigned dns : 4;
};
struct header {
  unsigned short ID;  // ID
  char QR;            // 0:query 1:response
  char Opcode;
  char AA;  // authorized
  char TC;  // trucanted
  char RD;
  char RA;
  char Rcode;  // 0:no error 3: url not exist
  unsigned int Question_count;
  unsigned int Ans_count;
  unsigned int Ns_count;
  unsigned int Ar_count;
};
struct question {
  char url[DOMAIN_LEN];
  char Qtype;
};
struct answer {
  char url[DOMAIN_LEN];
  char cname[DOMAIN_LEN];
  char type;
  unsigned int ttl;
  unsigned int data_len;
  long ip[MAX_IP];
};
struct dns_list {
  char domain[DOMAIN_LEN];
  unsigned long ip;
  int ttl;  // 0 for INF TTL
  struct dns_list* next;
};
struct head_dns_list {
  struct dns_list* next;
  int count;
};
struct id_table {
  struct sockaddr_in client;
  unsigned short old_id;
  unsigned short new_id;
  unsigned int ttl;
};
struct cache {
  char url[DOMAIN_LEN];
  char Cname[DOMAIN_LEN];
  unsigned long dns[MAX_IP];
  int dns_count;
  unsigned int ttl;
  struct cache* next;
};

socklen_t socketfd;
char dns_server_ip[16] = DEFAULT_dns_server_ip;
char config_path[FILE_PATH_MAX_LEN] = "dnsrelay.txt";
struct sockaddr_in server_addr, client_addr;
int debug_level = 0;
struct head_dns_list head_local_dns_list;
struct head_dns_list head_block_dns_list;
struct id_table ID_table[ID_TABLE_SIZE];
struct cache cache_head;
int len = -1;
#endif