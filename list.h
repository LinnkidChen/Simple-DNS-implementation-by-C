#ifndef LIST_H
#define LIST_H 1
#include "definition.h"
#include "function.h"

extern void print_dns(unsigned long dns);
void append_front_node_dns(struct head_dns_list* head, char* ip, char* domain) {
  struct dns_list* temp_next;
  struct dns_list* temp_node;

  temp_node = (struct dns_list*)malloc(sizeof(struct dns_list));
  if (!temp_node) {
    printf("fail to malloc and append node\n");
  }

  // printf("%s %s \n",ip,domain);

  strcpy(temp_node->domain, domain);
  temp_node->ip = htonl(inet_addr(ip));
  temp_node->ttl = 0;
  if (debug_level > 1)
    printf("url:%s\n ip:%lx\n", temp_node->domain, temp_node->ip);

  head->count++;
  temp_next = head->next;
  head->next = temp_node;
  temp_node->next = temp_next;
}
void append_front_node_cache(struct cache* head, struct answer* ans) {
  struct cache* temp_next;
  struct cache* temp_node;

  temp_node = (struct cache*)malloc(sizeof(struct cache));
  temp_node->dns[0] = 0;
  temp_node->dns_count = 0;
  if (!temp_node) {
    printf("fail to malloc and append node\n");
  }

  strcpy(temp_node->url, ans->url);
  if (ans->type == A) {  // dns
    for (int i = 0; i < ans->data_len / 4; i++) {
      temp_node->dns[i] = ans->ip[i];
    }
    temp_node->dns_count = ans->data_len / 4;
  }

  if (ans->type == CNAME) {
    strcpy(temp_node->Cname, ans->cname);
  }
  temp_node->ttl = ans->ttl + clock() * CLOCKS_PER_SEC;

  temp_next = head->next;
  head->next = temp_node;
  temp_node->next = temp_next;
}
void print_cache(struct cache* head) {
  head = head->next;
  printf("---------PRINTING CACHE-----------\n");
  while (head) {
    printf("url:%s\n", head->url);
    if (strlen(head->Cname) > 0) printf("Cname:%s\n", head->Cname);
    if (head->dns_count > 0) {
      // printf("ip:\n");
      for (int i = 0; i < head->dns_count; i++) {
        print_dns(head->dns[i]);
      }
    }
    printf("ttl:%u\n", head->ttl);
    head = head->next;
  }
  printf("---------END OF CACHE-----------\n");
}
int check_duplicate(unsigned long ans[MAX_IP], unsigned long cur, int pos)
// check if cur is in ans[0]-ans[pos]
// return 1 for duplicate return 0 for not duplicate
{
  for (int i = 0; i <= pos; i++) {
    if (ans[i] == cur) return 1;
  }
  return 0;
}

int check_blocklist(struct head_dns_list* head, char* url) {
  struct dns_list* temp;
  int found = 0;
  temp = head->next;
  while (temp) {
    if (strcmp(url, temp->domain) == 0) found = 2;
    temp = temp->next;
  }
  return found;
}
int check_cache(struct cache* head, char* url, unsigned long ans_dns[MAX_IP]) {
  //	 use a recursion to set cNAMe nodes
  // ans_dns[0] = 999;
  // return 1;
  struct cache *cur, *pre;
  cur = head->next;
  pre = head;
  while (cur) {
    if (cur->ttl > clock())  // cur node is still valid basing on ttl
    {
      // printf("url:%s\ncur->url%s\n\n", url, cur->url);
      if (strcmp(url, cur->url) == 0) {  // found a match
        // printf("CACHE FIND A MATCH,url:%s\n", url);

        if (cur->dns_count == 0) {  // is a cname type
          unsigned long temp_dns[MAX_IP] = {0};
          check_cache(head, cur->Cname, temp_dns);
          for (int i = 0; i < MAX_IP; i++) {
            if (temp_dns[i] == 0) break;
            ans_dns[i] = temp_dns[i];
            cur->dns[i] = temp_dns[i];
            cur->dns_count++;
          }
          break;
        } else if (cur->dns_count > 0)  // is dns type
        {
          int q = 0;
          // find first place that is not written
          while (ans_dns[q]) q++;

          for (int i = 0; i < cur->dns_count && q < MAX_IP; i++) {
            if (!check_duplicate(ans_dns, cur->dns[i], i))
              ans_dns[q] = cur->dns[i];
            q++;
          }
        }
      }
      pre = cur;
      cur = cur->next;
    } else  // cur node is overtime.remove cur node
    {
      pre->next = cur->next;
      free(cur);
      cur = pre->next;
    }
  }
  if (ans_dns[0])
    return 1;
  else
    return 0;
}
int check_dnslist(struct head_dns_list* head, char* url,
                  unsigned long ans_dns[MAX_IP]) {
  struct dns_list* cur;
  cur = head->next;
  while (cur) {
    if (strcmp(url, cur->domain) == 0)  // url found
    {
      ans_dns[0] = cur->ip;
      if (debug_level > 1)
        printf("FOUND IN DNSLIST.url:%s\n,dnslist:%s\n", url, cur->domain);
      return 1;
      break;
    }
    cur = cur->next;
  }
  return 0;
}

void free_list(struct head_dns_list* head) {
  struct dns_list *temp0, *temp1;
  temp1 = NULL;
  temp0 = head->next;
  while (temp0) {
    temp1 = temp0->next;
    free(temp0);
    temp0 = temp1;
  }
}

void free_cache(struct cache* head) {
  struct cache *temp0, *temp1;
  temp1 = NULL;
  temp0 = head->next;
  while (temp0) {
    temp1 = temp0->next;
    free(temp0);
    temp0 = temp1;
  }
}
#endif