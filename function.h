#ifndef FUNCTION_H
#define FUNCTION_H 1
#include "definition.h"
#include "list.h"
void init_dnsrelay(int argc, char* argv[]);
void init_socket();
void init_loadfile();
int check_local(char* url, unsigned long ans_dns[MAX_IP]);

void init_dnsrelay(int argc, char* argv[]) {
  // setting debug_level
  debug_level = 0;
  if (argc > 1 && argv[1][0] == '-') {
    if (argv[1][1] == 'd') {
      debug_level = 1;  //-d
    }
    if (argv[1][2] == 'd') {
      debug_level = 2;  //-dd
    }
  }
  // using custom dns_server_ip
  if (argc > 2) {
    strcpy(dns_server_ip, argv[2]);
  }
  // using custom config file
  if (argc > 3) {
    strcpy(config_path, argv[3]);
  }
  if (debug_level > 1) {
    printf("using DNS SERVER : %s \n", dns_server_ip);
  }
}

void init_socket() {
  // socket(domain, type, protocol)
  // AF_INET:ipv4 SOCK_DGRAM:UDP 0:IP
  socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socketfd <= 0) {
    printf("Could not create socket\n");
    exit(0);
  }
  fcntl(socketfd, F_SETFL, O_NONBLOCK);
  // int setsockopt(int socket, int level, int option_name
  //,const void *option_value, socklen_t option_len);
  // allow port reuse
  int reuse = 1;
  setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  // set up client and dns_server_ip address
  client_addr.sin_family = AF_INET;  // IPV4
  client_addr.sin_addr.s_addr =
      htonl(INADDR_ANY);               // random address for local server ip
  client_addr.sin_port = htons(PORT);  // port 53

  server_addr.sin_family = AF_INET;  // IPV4
  server_addr.sin_addr.s_addr = inet_addr(dns_server_ip);
  //   print_dns(server_addr.sin_addr.s_addr);  // random address for local
  //   server ip
  server_addr.sin_port = htons(PORT);  // port 53

  // bind port to socket
  if (((bind(socketfd, (const struct sockaddr*)&client_addr,
             sizeof(client_addr)))) < 0) {
    perror("Bind");
    exit(1);
  }

  // printf("%d\n",(bind(socketfd,(const struct sockaddr
  // *)&client_addr,sizeof(client_addr))));

  if (debug_level > 1) printf("Successfully create socket.\n");
}

void init_loadfile() {
  FILE* config;
  char ip[IP_LEN];
  char domain[DOMAIN_LEN];
  config = fopen(config_path, "r");
  if (!config) {
    printf("fail to open config file");
    exit(1);
  }

  if (debug_level > 1) printf("LOADING FILE\n");
  while (!feof(config)) {
    fscanf(config, "%s %s", ip, domain);
    // if (debug_level > 1)
    //     printf("ip:%s,domain:%s\n", ip, domain);
    if (strcmp(ip, BLOCKED_IP) == 0) {
      append_front_node_dns(&head_block_dns_list, ip, domain);
    } else {
      append_front_node_dns(&head_local_dns_list, ip, domain);
    }
  }
}
void init_id_table() {
  for (int i = 0; i < ID_TABLE_SIZE; i++) {
    ID_table[i].old_id = 0;
    ID_table[i].new_id = 0;
    ID_table[i].ttl = 0;
  }
}
void show_packet(char* buff, int len) {
  unsigned char temp;
  printf("the packet is:\n");
  for (int i = 0; i < len; i++) {
    temp = (unsigned char)buff[i];
    printf("%02X ", temp);
    if ((i + 1) % 16 == 0) printf("\n");
  }
  printf("\nlength of packet is %d\n", len);
}
void trans_url_to_raw(char* url, char* des);
void trans_raw_to_url(char** pos, char* url, char* buff) {
  // int i=**pos;
  // int curpos=0;
  // while(**pos>0){
  //     for(int q=0;q<i;q++){
  //         (*pos)++;
  //         url[curpos]=**pos;
  //         curpos++;
  //     }
  //     (*pos)++;
  //     i=**pos;
  //     url[curpos]='.';
  //     curpos++;
  // }
  int i = 0;
  unsigned char count = 0;
  count = **pos;
  (*pos)++;
  while (**pos) {
    if (!count) {  // is a count

      count = **pos;
      url[i] = '.';
      // printf("!!!!!count:%d!!!!!\n",count);
    } else {  // is a character
      url[i] = **pos;
      count--;
    }
    (*pos)++;
    i++;
    if (count >= MAX_INURL_LEN) {  // using offset
      // read offset
      (*pos)--;
      // printf("JUMP USING OFFSET\n");
      int offset;
      char* temp;
      offset = ntohs(*(unsigned short*)(*pos));
      // printf("!!!OFFSET: %d !!!\n",offset);
      temp = buff;
      temp = temp + (offset - 0xC000);
      trans_raw_to_url(&temp, url + i, buff);
      (*pos) += 1;
      break;
    }
  }
  (*pos)++;
}

void print_dns(unsigned long dns) {
  int temp[5];
  for (int i = 3; i >= 0; i--) {
    temp[i] = dns % 256;
    dns /= 256;
  }
  printf("DNS is : %d.%d.%d.%d\n", temp[0], temp[1], temp[2], temp[3]);
}
void read_header(char* buff, struct header* packet_header) {
  struct header_raw* raw_header;
  raw_header = (struct header_raw*)buff;
  packet_header->ID = ntohs(raw_header->ID);
  // printf("ID IS : %X\n",packet_header->ID);
  packet_header->QR = ntohs(raw_header->QR);
  // printf("QR is %d",packet_header->QR);
  packet_header->Opcode = ntohs(raw_header->Opcode);
  packet_header->AA = ntohs(raw_header->AA);
  packet_header->TC = ntohs(raw_header->TC);
  packet_header->RD = ntohs(raw_header->RD);
  packet_header->RA = ntohs(raw_header->RA);
  packet_header->Rcode = ntohs(raw_header->RCODE);
  packet_header->Question_count = ntohs(raw_header->QDCOUNT);
  packet_header->Ans_count = ntohs(raw_header->ANCOUNT);

  if (debug_level > 1) {
    printf("ID: %X  QR: %d   opcode: %d   Rcode: %d\n", packet_header->ID,
           packet_header->QR, packet_header->Opcode, packet_header->Rcode);
    printf("Question count:%d\n", packet_header->Question_count);
    printf("Ans count:%d\n", packet_header->Ans_count);
  }
}
void read_question(char** pos, struct question* packet_question, char* buff) {
  // int i = 0;
  //(*pos)++;//skip first count
  // read url
  memset(packet_question->url, '\0', DOMAIN_LEN);
  trans_raw_to_url(pos, packet_question->url, buff);
  // read Qtype
  packet_question->Qtype = ntohs((*(unsigned int*)(*pos)));
  (*pos) += 4;
  if (debug_level > 1) {
    printf("QUESTION:\n");
    printf("url:%s\nQtype:%d\n", packet_question->url, packet_question->Qtype);
  }
}
// read answer is not tested yet
void read_answer(char** pos, struct answer* ans, char* buff) {
  /*构造DNS报文资源记录（RR）区域
    0	 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |
  | /
  / /					  URL(using offset)
  / |
  |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |					  TYPE
  |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |					 CLASS
  |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |					  TTL
  |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |					RDLENGTH
  |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  /					 RDATA
  / /
  /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  | 1  1|                OFFSET                   |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


  */
  // if top 2 bits are both 1.then its using a offset to point to its url

  unsigned short offset;
  offset = ntohs(*(unsigned short*)(*pos));
  if (debug_level > 1) printf("OFFSET: %x\n", offset);
  if (offset >= 0xC000) {  // using an offset
    // offset is calculated from the head of the message
    char* temp = buff;
    temp = temp + (offset - 0xC000);
    trans_raw_to_url(&temp, ans->url, buff);
    (*pos) += 2;  // size of offset
  } else {        // using url present name
    trans_raw_to_url(pos, ans->url, buff);
  }

  ans->type = ntohs(*((unsigned short*)(*pos)));
  // printf("%x %x",ntohs(*((unsigned short*)(*pos))),*((unsigned
  // short*)(*pos+2)));
  (*pos) += 4;  // skip type and class

  ans->ttl = ntohl(*((unsigned int*)(*pos)));
  (*pos) += 4;  // skip ttl

  ans->data_len = ntohs(*((unsigned short*)(*pos)));
  (*pos) += 2;
  if (ans->type == A) {
    int i = 0;
    unsigned long temp;

    while (i * 4 < ans->data_len) {
      temp = ntohl(*((unsigned long*)(*pos)));
      // printf("!!!!DNS being : %lx!!!\n", temp);
      ans->ip[i] = temp;
      i++;
      (*pos) += 4;
    }
  }
  if (ans->type == CNAME) {
    trans_raw_to_url(pos, ans->cname, buff);
  }

  if (debug_level > 1) {
    printf("url:%s\n", ans->url);
    printf("TTL:%d  data_len:%d  ,type:%d\n", ans->ttl, ans->data_len,
           ans->type);
    if (ans->type == A) {
      for (int i = 0; i < ans->data_len / 4; i++) print_dns(ans->ip[i]);
    }
    if (ans->type == CNAME) {
      printf("CNAME:%s\n", ans->cname);
    }
  }
}
unsigned short genrate_new_id(unsigned short old_id) {
  return (old_id + clock()) % (USHRT_MAX);
}
int check_local(
    char* url,
    unsigned long ans_dns[]) {  // return 0.0.0.0 if not found,return
                                // 255.255.255.255 url is blocked

  if (debug_level > 1)
    printf("-----------CHECKING LOCAL------------\ntarget url:%s\n", url);
  int found = 0;                                       // specify if its found
  found = check_blocklist(&head_block_dns_list, url);  // return 2 if found
  if (found == 2 && debug_level > 1) printf("URL IS BLOCKED\n");
  // printf("FOUND:%d\n", found);
  if (found == 0) {
    found = check_cache(&cache_head, url, ans_dns);  // return 1 if found
    if (debug_level > 1) print_cache(&cache_head);
    if (found && debug_level > 1) printf("URL FOUND IN CACHE\n");
    if (!found) {
      found = check_dnslist(&head_local_dns_list, url, ans_dns);
      if (debug_level > 1) {
        if (found)
          printf("URL FOUND IN DNSLIST\n");
        else
          printf("URL NOT FOUND IN LOCAL\n");
      }
    }
  }
  // printf("ANS_DNS[0]:%d\n", ans_dns[0]);
  if (debug_level > 1)
    printf("-------------END OF CHECKING LOCAL-------------\n");
  return found;
}
int add_id_to_table(struct sockaddr_in* sender_addr, unsigned short old_id,
                    unsigned short new_id) {
  // find a slot
  int i = 0;
  while (ID_table[i].old_id && i < ID_TABLE_SIZE) {
    i++;
  }
  if (i < ID_TABLE_SIZE) {  // successfully find a
    ID_table[i].old_id = old_id;
    ID_table[i].new_id = new_id;
    ID_table[i].client.sin_addr.s_addr = sender_addr->sin_addr.s_addr;
    ID_table[i].client.sin_family = sender_addr->sin_family;
    ID_table[i].client.sin_port = sender_addr->sin_port;
    ID_table[i].ttl = clock() + TTL_DNS*CLOCKS_PER_SEC;
    return 1;
  } else
    return 0;
}
int find_newid_in_id_table(unsigned short id, struct sockaddr_in* addr,
                           unsigned short* old_id) {
  int i = 0;
  for (i = 0; i < ID_TABLE_SIZE; i++) {
    if (ID_table[i].ttl < clock()) {  // ID is overtime
      ID_table[i].old_id = 0;
      ID_table[i].new_id = 0;
    }
    if (id == ID_table[i].new_id) {
      addr->sin_addr.s_addr = ID_table[i].client.sin_addr.s_addr;
      addr->sin_port = ID_table[i].client.sin_port;
      *old_id = ID_table[i].old_id;
      ID_table[i].old_id = 0;
      ID_table[i].new_id = 0;
      return 1;
    }
  }
  return 0;
}
void print_id_table() {
  printf("----------printing ID_TABLE-----------\n");

  for (int i = 0; i < ID_TABLE_SIZE; i++) {
    printf("old:%d ", ID_table[i].old_id);
    printf("new:%d ", ID_table[i].new_id);
    if (i % 4 == 3) printf("\n");
  }
  printf("\n----------END OF ID_TABLE-----------\n");
}
void append_ans_to_packet(char* buff, char* pos, unsigned long ans_dns[MAX_IP],
                          int ans_num) {
  if (debug_level > 1) printf("APPENDING ANS TO PACKET\n");
  // modify header
  struct header_raw* head;
  unsigned short temp_shrt;
  unsigned long temp_lng;
  head = (struct header_raw*)buff;
  // head->QR = 1;                    // type = response
  temp_shrt = htons(FLAG_RESPONSE);
  memcpy(&buff[2], &temp_shrt, sizeof(unsigned short));
  // head->ANCOUNT = htons(ans_num);  // set answer count
  temp_shrt = htons(ans_num);
  memcpy(&buff[6], &temp_shrt, sizeof(unsigned short));
  temp_shrt = 0;
  // append ans

  for (int i = 0; i < ans_num; i++) {
    // str  // offset to first query
    temp_shrt = htons(OFFSET_TO_FIRST_QUR);
    memcpy(pos, &temp_shrt, sizeof(unsigned short));
    pos += 2;
    // ans->type = htons(1);
    temp_shrt = htons(1);
    memcpy(pos, &temp_shrt, sizeof(unsigned short));
    pos += 2;
    // ans->_class = htons(1);
    temp_shrt = htons(1);
    memcpy(pos, &temp_shrt, sizeof(unsigned short));
    pos += 2;
    // ans->ttl = htonl(TTL_DNS);
    temp_lng = htonl(TTL_DNS);
    memcpy(pos, &temp_lng, sizeof(unsigned long));
    pos += 4;
    // ans->data_len = htons(4);
    temp_shrt = htons(4);
    memcpy(pos, &temp_shrt, sizeof(unsigned short));
    pos += 2;
    // ans->dns = htonl(ans_dns[i]);
    temp_lng = htonl(ans_dns[i]);
    memcpy(pos, &temp_lng, sizeof(unsigned long));
    pos += 4;
  }
  if (debug_level > 1) show_packet(buff, 80);  // print packet
}
void process_server_request(char* buff, int len,
                            struct sockaddr_in* server_addr,
                            socklen_t addr_len) {
  //   char url[DOMAIN_LEN];
  char* pos;
  struct header packet_header;
  struct question packet_question[MAX_QUESTION];
  struct answer packet_answer[MAX_ANSWER];

  packet_header.Ar_count = 0;
  packet_header.Question_count = 0;
  if (debug_level > 1) {
    show_packet(buff, len);
  }

  read_header(buff, &packet_header);
  pos = buff + sizeof(struct header_raw);  // currposition of pointer
  if (debug_level == 1) {
    printf("recv packet %lx from server", packet_header.ID);

    print_dns(htonl(server_addr->sin_addr.s_addr));
  }
  for (int i = 0; i < packet_header.Question_count; i++) {
    read_question(&pos, &packet_question[i], buff);
  }
  // printf("%X %X %X %X\n",*pos,*(pos+1),*(pos+2),*(pos-2));
  for (int i = 0; i < packet_header.Ans_count; i++) {
    memset(packet_answer[i].cname, '\0', DOMAIN_LEN);
    read_answer(&pos, &packet_answer[i], buff);
    append_front_node_cache(&cache_head, &packet_answer[i]);
  }

  // find matched id in id table then transmission to client
  struct sockaddr_in des_addr;
  socklen_t des_addr_len;
  unsigned short old_id;
  old_id = 0;
  des_addr_len = sizeof(des_addr);
  if (find_newid_in_id_table(packet_header.ID, &des_addr, &old_id)) {
    old_id = htons(old_id);
    memcpy(buff, &old_id, sizeof(unsigned short));
    if (sendto(socketfd, buff, len, 0, (struct sockaddr*)&des_addr,
               des_addr_len) == -1 &&
        debug_level > 1) {
      perror("sendto");
    } else if (debug_level == 1) {
      printf("Packet %lx sent to Client ", htons(old_id));
      print_dns(htonl(des_addr.sin_addr.s_addr));
    }
  } else if (debug_level > 1) {
    printf("ID:%x not in ID TABLE\n", packet_header.ID);
  }
}

void process_client_request(char* buff, int len,
                            struct sockaddr_in* sender_addr,
                            socklen_t addr_len) {
  char url[DOMAIN_LEN];
  char* pos;
  struct header packet_header;
  struct question packet_question[MAX_QUESTION];
  // socklen_t size;
  //   struct answer packet_answer[MAX_ANSWER];

  packet_header.Ar_count = 0;
  packet_header.Question_count = 0;

  if (debug_level > 1) {
    show_packet(buff, len);
  }

  read_header(buff, &packet_header);
  pos = buff + sizeof(struct header_raw);  // currposition of pointer
  if (debug_level == 1) {
    printf("recv packet %lx from client", packet_header.ID);

    print_dns(htonl(sender_addr->sin_addr.s_addr));
  }
  for (int i = 0; i < packet_header.Question_count; i++) {
    read_question(&pos, &packet_question[i], buff);
  }
  // process question
  unsigned long ans_dns[MAX_IP] = {0};
  int flag = 0;

  for (int i = 0; i < packet_header.Question_count; i++) {
    flag = check_local(packet_question[i].url, ans_dns);
    int ans_num = 0;
    unsigned short new_id = 0;
    unsigned short temp_shrt;

    while (ans_dns[ans_num]) ans_num++;
    switch (flag) {
      case 0:  // not found in local
        new_id = genrate_new_id(packet_header.ID);
        if (add_id_to_table(sender_addr, packet_header.ID,
                            new_id)) {  // successfullyfind a slot
          // set packet's id to new_id
          new_id = htons(new_id);
          memcpy(buff, &new_id, sizeof(unsigned short));

          if (sendto(socketfd, buff, len, 0, (struct sockaddr*)&server_addr,
                     sizeof(server_addr)) == -1)
            perror("sendto");
          else if (debug_level == 1) {
            printf("Packet %lx sent to server ", htons(new_id));
            print_dns(htonl(server_addr.sin_addr.s_addr));
          }

          if (debug_level > 1) print_id_table();
        }
        break;
      case 1:  // found in local
        append_ans_to_packet(buff, pos, ans_dns, ans_num);
        len = len + ans_num * ANS_RR_LEN;
        // size = sizeof(sender_addr);
        sender_addr->sin_family = AF_INET;
        if (sendto(socketfd, buff, len, 0, (struct sockaddr*)sender_addr,
                   addr_len) == -1)
          perror("sendto");
        else if (debug_level == 1) {
          printf("Packet %lx sent to client ", packet_header.ID);
          print_dns(htonl(sender_addr->sin_addr.s_addr));
        }
        break;
      case 2:
        // struct header_raw* temp;
        // temp = (struct header_raw*)buff;
        // temp->RCODE = htons(3);  // Rcode = 3
        temp_shrt = htons(FLAG_RESPONSE_ERROR);
        memcpy(&buff[2], &temp_shrt, sizeof(unsigned short));
        if (sendto(socketfd, buff, len, 0, (struct sockaddr*)sender_addr,
                   addr_len) == -1) {
          perror("sendto");
        } else if (debug_level == 1) {
          printf("Packet %lx sent to client ", packet_header.ID);
          print_dns(htonl(sender_addr->sin_addr.s_addr));
        }
        break;
    }
  }
  // print_cache(&cache_head);
}

#endif