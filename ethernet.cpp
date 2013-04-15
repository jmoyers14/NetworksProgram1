using namespace std;
#include "ethernet.h"
#include <stdio.h>
#include <string.h>

ethernet::ethernet(uint8_t *data)
{
   //memcpy(&head, data, sizeof(head)+1);
   head = (struct header *) data;
   if((head->type[0] == 8) && (head->type[1] == 0))
   {
      type = "IP";
      isARP = 0;
   }
   else
   {
      type = "ARP";
      isARP = 1;
   }

}


void ethernet::print_header()
{
   cout << "        Ethernet Header" << endl;
   cout << "                Dest MAC: ";
   for(int i=0;i<6;i++)
   {
      cout << hex << int(head->destination_mac[i]);
      if(i < 5) cout << ":";
   }
   cout << endl;

   cout << "                Source MAC: ";
   for(int i=0;i<6;i++)
   {
      cout << hex << int(head->source_mac[i]);
      if(i < 5) cout << ":";
   }

   cout << endl;
   cout << "                Type: " << type;
   cout << endl;
   cout << endl;

}

void ethernet::test() {

   cout << "test" << endl;
}

