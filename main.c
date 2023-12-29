/*         notes
 1. report when dns server cant be reached
2. dns in cache in a single node may be duplicated-->fixed
3. 上次写到，修复对bit field 不能直接取地址->修复方式 直接对char*buff
操作，使用memcpy和地址指针使用
4. 在local中
所有dns以正常顺序存储。即转化为packet中的dns地址时需要使用ntohl（）转换
5.set ttl for id table
 */

#include "definition.h"
#include "function.h"
// int main(int argc, char* argv[]) {
//   init_dnsrelay(argc, argv);

//   init_socket();

//   init_loadfile();

//   init_id_table();

//   char buff[BUFFER_SIZE];
//   len = -1;
//   struct sockaddr_in temp_sockaddr_in;

//   socklen_t sockaddr_in_size = sizeof(temp_sockaddr_in);
//   fd_set read_fd_set;
//   struct timeval timeout;
//   int retval;
//   cache_head.next = NULL;
//   temp_sockaddr_in.sin_family = AF_INET;

//   for (;;) {
//     memset(buff, '0', BUFFER_SIZE);
//     len = -1;
//     // sendto(socketfd,buff,sizeof(buff),0,(struct
//     // sockaddr*)&server_addr,sockaddr_in_size);
//     // printf("sent success,destination being :%s\n", dns_server_ip);
//     FD_ZERO(&read_fd_set);
//     FD_SET(socketfd, &read_fd_set);
//     timeout.tv_sec = WAIT_TIME;
//     timeout.tv_usec = 0;
//     retval = select(socketfd + 1, &read_fd_set, NULL, NULL, &timeout);

//     if (retval == -1) {
//       perror("select");
//     } else if (retval) {
//       len = recvfrom(socketfd, buff, sizeof(buff), 0,
//                      (struct sockaddr*)&temp_sockaddr_in, &sockaddr_in_size);
//       if (debug_level > 1) printf("PACKET RECIEVED.SENDER :\n");
//       if (debug_level > 1)
//       print_dns(htonl(temp_sockaddr_in.sin_addr.s_addr)); if (len > 0) {  //
//       packet recived
//         if (temp_sockaddr_in.sin_port ==
//             htons(PORT)) {  // request from forign server
//           process_server_request(buff, len, &temp_sockaddr_in,
//                                  sockaddr_in_size);

//         } else {  // request from dns client
//           process_client_request(buff, len, &temp_sockaddr_in,
//                                  sockaddr_in_size);
//         }

//       } else if (debug_level > 1)
//         printf("len<0\n");
//       fflush(stdout);
//     } else if (debug_level > 0)
//       printf("NO DATA IN %d SECS\n", timeout.tv_sec);
//   }

//   close(socketfd);
//   free_list(&head_block_dns_list);
//   free_list(&head_local_dns_list);

//   return 0;
// }

int main() {
  char buff[BUFFER_SIZE];
  init_socket();
  memset(buff, '1', BUFFER_SIZE);
  sendto(socketfd, buff, 8000, 0, (struct sockaddr*)&server_addr,
         sizeof(server_addr));
  perror("send");
  return 0;
}