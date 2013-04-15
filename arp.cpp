using namespace std;
#include "arp.h"
#include <stdio.h>
#include <string.h>

arp::arp(uint8_t *data)
{
   //memcpy(&head, data+14, sizeof(head)+1);
   head = (struct header *) (data + 14);
   if((head->operation[0]==0) && (head->operation[1]==1))
   {
      opcode = "Request";
   }
   else
   {
      opcode = "Reply";
   }
}

void arp::print_header()
{
   cout << "        ARP header" << endl;
   cout << "                Opcode: ";
   cout << opcode;
   cout << endl;

   cout << "                Sender MAC: ";
   for(int i = 0; i < 6; i++)
   {
      cout << hex << int(head->sender_hardware_address[i]);
      if(i < 5) cout << ":";
   }
   cout << endl;

   cout << "                Sender IP: ";
   for(int i = 0; i < 4; i++)
   {
      cout << dec << int(head->sender_ip_address[i]);
      if(i<3) cout << ".";
   }
   cout << endl;

   cout << "                Target MAC: ";
   for(int i = 0; i < 6; i++)
   {
      cout << hex << int(head->target_hardware_address[i]);
      if(i<5) cout << ":";
   }
   cout << endl;

   cout << "                Target IP: ";
   for(int i = 0; i < 4; i++)
   {
      cout << dec << int(head->target_ip_address[i]);
      if(i<3) cout << ".";
   }
   cout << endl;

}
