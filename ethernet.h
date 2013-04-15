#include <iostream>
#include <string.h>

class ethernet
{
   struct header {
      uint8_t destination_mac[6];
      uint8_t source_mac[6];
      uint8_t type[2];
   }__attribute__((packed));

   void test();

   struct header *head;
   string type;

   public:
      bool isARP;
      ethernet (uint8_t *);
      void print_header();
};

