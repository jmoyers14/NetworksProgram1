#include <iostream>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

class ip
{

   #pragma pack(1)
   struct header {
      uint8_t versionIHL[1];
      uint8_t tos[1];
      uint16_t tol;
      uint8_t identification[2];
      uint8_t flags_frags[2];
      uint8_t ttl[1];
      uint8_t protocol[1];
      //uint8_t header_checksum[2];
      uint16_t header_checksum;
      uint8_t source_ip_address[4];
      uint8_t destination_ip_address[4];
   }__attribute__((packed));

   struct icmp {
      uint8_t type;
      uint8_t opcode;
      uint16_t checksum;
      uint32_t data;
   }__attribute__((packed));

   struct tcp {
      uint16_t source_port;
      uint16_t destination_port;
      uint32_t sequence_number;
      uint32_t ack_number;
      uint8_t offset_res_ns;
      uint8_t flags;
      #define TCP_FIN 0x01
      #define TCP_SYN 0x02
      #define TCP_RST 0x04
      uint16_t window_size;
      uint16_t checksum;
      uint16_t urgent_pointer;
   }__attribute__((packed));

   struct tcp_test {
      uint8_t ip_src[4];
      uint8_t ip_dst[4];
      uint8_t empty;
      uint8_t protocol;
      uint16_t len;
   }__attribute__((packed));

   struct udp {
      uint16_t source_port;
      uint16_t destination_port;
      uint16_t len;
      uint16_t checksum;
   }__attribute__((packed));

   struct tcp *tcp_header;
   struct header *head;

   void print_icmp(uint8_t *data);
   void print_tcp(uint8_t *data);
   void print_udp(uint8_t *data);
   public:
      ip (uint8_t *);
      void print_header(uint8_t *data);

      void print_checksum(uint8_t *data);
      unsigned short in_cksum(unsigned short *addr, int len, uint16_t t_sum);
};
