/*
 * Copyright (c) 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

using namespace std;
#include "ip.h"
#include <stdio.h>
#include <string.h>
#include <bitset>
#include <stdlib.h>
#include <sys/types.h>
#include <iomanip>

ip::ip(uint8_t *data)
{
   head = (struct header*) (data+14);
   tcp_header = (struct tcp*) (data+34);
   //memcpy(&head, data+14, sizeof(head)+1);
   //memcpy(&tcp_header, data+34, sizeof(tcp_header));

}

void ip::print_header(uint8_t *data)
{
   //struct header head;
   cout << "        IP Header" << endl;
   cout << "                TOS: 0x";
   for(int i=0; i<1; i++)
      cout << hex << int(head->tos[i]);
   cout << endl;

   cout << "                TTL: ";
   for(int i=0;i<1;i++)
     cout << dec << int(head->ttl[i]);
   cout << endl;

   cout << "                Protocol: ";
   if(int(head->protocol[0]) == 1)
      cout << "ICMP";
   else if(int(head->protocol[0] == 6))
      cout << "TCP";
   else if(int(head->protocol[0] == 17))
      cout << "UDP";
   else
      cout << "Unknown";
   cout << endl;

   print_checksum(data);

   cout << "                Sender IP: ";
   for(int i=0;i<4;i++)
   {
      cout << dec << int(head->source_ip_address[i]);
      if(i<3) cout << ".";
   }
   cout << endl;

   cout << "                Dest IP: ";
   for(int i=0;i<4;i++)
   {
      cout << dec << int(head->destination_ip_address[i]);
      if(i<3) cout << ".";
   }
   cout << endl;
   cout << endl;

   if(int(head->protocol[0]) == 1)
      print_icmp(data);
   else if(int(head->protocol[0] == 6))
      print_tcp(data);
   else if(int(head->protocol[0] == 17))
      print_udp(data);
}

void ip::print_icmp(uint8_t *data)
{
    struct icmp *icmp_header = (struct icmp*) (data + 34);

    cout << "        ICMP Header" << endl;
    cout << "                Type: ";
    if(icmp_header->type == 0 && icmp_header->opcode == 0)
    {
       cout << "Reply"; 
    }
    else if(icmp_header->type == 8 && icmp_header->opcode == 0) 
    {
      cout << "Request";
    }
    else
    {
      cout << "Unknown";
    }
    cout << endl;
    
}

void ip::print_udp(uint8_t *data)
{
    struct udp *udp_header = (struct udp*) (data + 34);

    cout << "        UDP Header" << endl;
    cout << "                Source Port: " << ntohs(udp_header->source_port);
    cout << endl;
    cout << "                Dest Port: " << ntohs(udp_header->destination_port); 
}

void ip::print_tcp(uint8_t *data)
{
   //struct tcp tcp_header;

/*
   cout << "check data" << endl;
   for(int i=0;i<62;i++)
   {
      cout << hex << int(data[i]) << " ";
   }
*/


   cout << "        TCP Header" << endl;
   cout << "                Source Port: ";
   if(ntohs(tcp_header->source_port) == 80)
      cout << "HTTP";
   else
      cout << dec << ntohs(tcp_header->source_port); 
   cout << endl;

   cout << "                Dest Port: ";
   if(ntohs(tcp_header->destination_port) == 80)
      cout << "HTTP";
   else
      cout << ntohs(tcp_header->destination_port);
   cout << endl;

   cout << "                Sequence Number: ";
   cout << ntohl(tcp_header->sequence_number);
   cout << endl;

   cout << "                ACK Number: ";
   cout << dec << ntohl(tcp_header->ack_number);
   cout << endl;

   cout << "                SYN Flag: ";
   cout << (tcp_header->flags & TCP_SYN ? "Yes" : "No");
   cout << endl;
   cout << "                RST Flag: ";
   cout << (tcp_header->flags & TCP_RST ? "Yes" : "No");
   cout << endl;
   cout << "                FIN Flag: ";
   cout << (tcp_header->flags & TCP_FIN ? "Yes" : "No");
   cout << endl;

   cout << "                Window Size: ";
   cout << ntohs(tcp_header->window_size);
   cout << endl;


   //checksum
   struct tcp_test *tcp_t;
   uint8_t ip_head_len = 20;
   uint16_t ip_len = ntohs(head->tol);

   tcp_t = (struct tcp_test *) calloc(1, sizeof(struct tcp_test));

   memcpy(tcp_t->ip_src,  head->source_ip_address, sizeof(uint8_t[4]));
   memcpy(tcp_t->ip_dst, head->destination_ip_address, sizeof(uint8_t[4]));
   tcp_t->empty = 0;
   tcp_t->protocol = 6;
   tcp_t->len = htons(ip_len - ip_head_len);
   uint16_t checksum;
   checksum = in_cksum((unsigned short*)tcp_t, (unsigned)sizeof(struct tcp_test), 0);

   checksum = in_cksum((unsigned short*) (data+34), ntohs(tcp_t->len), (uint16_t)~checksum);



   cout << "                Checksum: ";
   if(int(checksum) == 0)
   {
      cout << "Correct(0x";
   }
   else
   {
      cout << "Incorrect(0x";
   }

   cout << hex << ntohs(int(tcp_header->checksum)) << ")";
   cout << endl;

   free(tcp_t);
}



void ip::print_checksum(uint8_t *data)
{
   unsigned short insum[10];
   memcpy(&insum, data+14, sizeof(insum) + 1);

   for(int i=0;i<10;i++)
   {
      insum[i] = ntohs(insum[i]);
   }

   unsigned short result = in_cksum(insum, 20, 0);
   if(result==0)
   {
      cout << "                Checksum: Correct (0x";
   }
   else
   {
      cout << "                Checksum: Incorrect (0x";
   }
   //for(int i=0;i<2;i++) {
   //   cout << hex << setw(2) << setfill('0') << int(head->header_checksum[i]);
   //}
   cout << hex << int(ntohs(head->header_checksum));
   cout << ")" << endl;
}

unsigned short ip::in_cksum(unsigned short *addr,int len, uint16_t t_sum)
{
        register int sum = t_sum;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        
        if (nleft == 1) {

                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}


