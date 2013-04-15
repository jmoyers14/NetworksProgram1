#include <iostream>
#include <string.h>

class arp
{
   struct header {
      uint8_t hardware_type[2];
      uint8_t protocol_type[2];
      uint8_t hardware_address_length[1];
      uint8_t protocol_address_length[1];
      uint8_t operation[2];
      uint8_t sender_hardware_address[6];
      uint8_t sender_ip_address[4];
      uint8_t target_hardware_address[6];
      uint8_t target_ip_address[4];
   };

   struct header *head;
   string opcode;

   public:
      arp (uint8_t *);
      void print_header();
};
