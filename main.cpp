using namespace std;
#include <iostream>
#include <pcap.h>
#include "ethernet.h"
#include "arp.h"
#include "ip.h"

int main(int argc, char *argv[])
{
   char *file = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];

   //open trace file
   pcap_t *trace;
   trace = pcap_open_offline(argv[1], errbuf);
   if(trace == NULL)
   {
      cout << "Error opening file " << file << endl;
      exit (EXIT_FAILURE);
   }

   int next_return;
   struct pcap_pkthdr *header;
   const u_char *pkt_data;
   //uint8_t data[100];
   uint8_t *data;


   int i = 1;
   while((next_return = pcap_next_ex(trace, &header, &pkt_data)) > 0)
   {


      //memcpy(&data, pkt_data, sizeof(data)+1);
      data = (uint8_t*)pkt_data;
      ethernet eth(data);

      cout << "Packet number: " << dec << i << "  Packet Len: " << header->len << endl << endl;

      eth.print_header();
      i++;

      if(eth.isARP)
      {
         arp a(data);
         a.print_header();
      }
      else
      {
         ip i_p(data);
         i_p.print_header(data);
      }



/*
      for (int i=1; i < (header->caplen + 1); i++)
      {
         cout <<  hex << int(data[i-1]) << " ";
         if((i % 32) == 0) printf("\n");
      }
*/
      cout << endl;
   }
   pcap_close(trace);
   return 0;
}

