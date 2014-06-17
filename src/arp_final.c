/**
	@Author  Dai Yang, Clemens Jonischkeit
	@institute TU Munich Faculty of Computer Science
	@version 1.0

	*Linux program builds up and send a ARP Request packet
	*usage ./run -s sourceip -d destip -m sourcemac
*/

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>		//TCP/IP Protocol Suite for Linux
#include <net/if.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define ETH_ALEN	6				//Octets in one ethernet address
#define ETH_HLEN	14				//Total octets in heater
#define	ETH_FRAME_LEN	1514		//Max. octets in fram sans FCS
#define ETH_DATA_LEN	1500		//Max. octets in payload
//These defines are copy from if_ether.h

struct packet{
	unsigned short _hardware_type;				//hardware address type
	unsigned short _protocol_type;				//protocol adress type
	unsigned char _hardware_address_length;		//hardware address length
	unsigned char _protocol_address_length;		//Protokoll adress length
	unsigned short _opcode;						//Operation
	unsigned char _src_mac[ETH_ALEN];			//source MAC (Ethernet Address)
	unsigned char _src_ip[4];					//source IP
	unsigned char _dest_mac[ETH_ALEN];			//destination MAC (Ethernet Address)
	unsigned char _dest_ip[4];					//destination IP 
	char fill[18];								//Padding, ARP-Requests are quite small (<64)
};


//falls ein fehler beim aufruf des programs geschar (falsche / zu wenig argumente)
void usage_err(){
	printf("Mini-ARP-Sniffer Version 1.0\n");
	printf("Author: Clemens Jonischkeit, Dai Yang\n");
	printf("Technical University Munich\n");
	printf("Wrong Usage encounterd.\n");
	printf("Usage: ./run -s source_ip -m destination_ip -m source_MAC");
}

int main(int argc, char* argv[])
{
	char eth_cache[ETH_FRAME_LEN];  		//Cache ethernet packet
	struct ethhdr *p_eth_header;			//build up ethernet header, from if_ether.h
	char eth_dest[ETH_ALEN]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};    //Ethernet dest. Address
    char eth_dest_dummy[ETH_ALEN]={0x00,0x00,0x00,0x00,0x00,0x00};
	
	int sock = socket(AF_INET,SOCK_PACKET,htons(0x0003));		//open the socket (Ethernet)
	p_eth_header = (struct ethhdr*)eth_cache;				//build up the ethernet packet
	memcpy(p_eth_header->h_dest, eth_dest, ETH_ALEN);
	p_eth_header->h_proto=htons(0x0806);				//0x0806 for Address Resolution Packet

	struct packet*p_arp;							//build up the arp packet
	p_arp = eth_cache + ETH_HLEN;					//start address in mem
	p_arp->_hardware_type = htons(0x1);				//0x0001 for 802.3 Frames
	p_arp->_protocol_type = htons (0x800);
	p_arp->_hardware_address_length = ETH_ALEN;			// 6 for eth-mac addr
	p_arp->_protocol_address_length = 4;				//4 for IPv4 addr
	p_arp->_opcode = htons(0x0001);			//0x0001 for ARP Request
   
    	//Parse command Line arguments
	int i,a;
    	struct in_addr in;
    	struct in_addr dest;
	if(argc!=7){					//arguments are path to executable, -s .. -d .. -m ..
		usage_err();
		exit(-1);
	}

	uint8_t val = 0;

	//iterate over all arguments
	for(i = 0;i<argc-1;i++){
		if(strcmp(argv[i],"-s")==0){
            		in.s_addr = inet_addr(argv[i+1]);		//interpret next argument as IPv4 addr
           		memcpy(p_arp->_src_ip,&in.s_addr,4);		//copy to arp-header as source addr
			val|=1;						//set lowest bit to show "-s" argument was parsed 
			continue;
		}
		if(strcmp(argv[i],"-d")==0){				//like -s argument but
            		dest.s_addr = inet_addr(argv[i+1]);		
			memcpy(p_arp->_dest_ip,&dest.s_addr,4);		//its copyed to destinaton addr
			val|=2;						//set corresponding bit
			continue;
		}
		if(strcmp(argv[i],"-m")==0){
			unsigned char mac[6];
			sscanf(argv[i+1],"%x:%x:%x:%x:%x:%x",&mac[0],&mac[1]	//interpret as mac
							    ,&mac[2],&mac[3]
							    ,&mac[4],&mac[5]);
			memcpy(p_arp->_src_mac,&mac,6);				//copy to source mac in arp geader
			memcpy(p_eth_header->h_source,&mac,6); 			//and als in ethernet header
			val|=4;							//set corresponding bit
		}
	}    
	if(val != 7){				//if not all bits set (1 argument missing)
		usage_err();			//error
		exit(-1);
	}
	//Set destination mac in arp-header to 00:00:00:00:00:00
	memcpy(p_arp->_dest_mac,eth_dest_dummy,ETH_ALEN);		
	bzero(p_arp->fill,18);
	//Zero fill the packet until 64 bytes reached
	
	struct sockaddr to;
	strcpy(to.sa_data,"eth0");
	//Send to the eth0 interface

	int n=0;
	//send packet
	n = sendto(sock,&eth_cache,64,0,&to,sizeof(to));
	printf("Sent data: %d\n",n);

	char buffer[65535];
	struct packet * arp_rply;
	arp_rply = (struct packet*)(buffer+14);
	while(recv(sock,buffer,sizeof(buffer),0)){
		if((((buffer[12])<<8)+buffer[13])!=ETH_P_ARP){	//if it's not an ARP-PKT
			continue;}
		if(ntohs(arp_rply->_opcode)!=2){		//or not an ARP replay
			continue;}
//		if(memcmp(p_arp->_dest_mac,arp_rply->_src_mac,ETH_ALEN) != 0){	//or if the replay is not for this host
//			continue;}				//discard packet
		printf("Reply from: %u.%u.%u.%u\n", arp_rply->_src_ip[0], //else print ip
                                            arp_rply->_src_ip[1],
                                            arp_rply->_src_ip[2],
                                            arp_rply->_src_ip[3]);
		char message[20];
		sprintf(message,"%x:%x:%x:%x:%x:%x",arp_rply->_src_mac[0], //and mac
                                            arp_rply->_src_mac[1],
                                            arp_rply->_src_mac[2],
                                            arp_rply->_src_mac[3],
                                            arp_rply->_src_mac[4],
                                            arp_rply->_src_mac[5]);
		printf("\tHis MAC is: %s\n",message);		//to standard output
		break;
	}
	//close socket
	close(sock);
	//exit programm
	return 0;
}
