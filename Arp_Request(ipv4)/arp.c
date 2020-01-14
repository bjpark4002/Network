#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUF_SIZ		65536
#define SEND 0
#define RECV 1
#define SENDARP 2


#define ETHERNET_HEADER_SIZE 14
#define ARP_HEADER_SIZE 28
#define IP_HEADER_SIZE 20

#define IP4_HDRLEN 20         // IPv4 header length
#define TCP_HDRLEN 20         // TCP header length, excludes options data


// char datagram[4096];
// char pheader[1024];

int16_t ip_checksum(void* vdata,size_t length) { 
	char* data=(char*)vdata;
	uint32_t acc=0xffff;
	for (size_t i=0;i+1<length;i+=2) { 
		uint16_t word;
		memcpy(&word,data+i,2);
		acc+=ntohs(word);
		if (acc>0xffff) {
			acc-=0xffff;
		}
	}
	if (length&1) {
		uint16_t word=0; 
		memcpy(&word,data+length-1,1);
		acc+=ntohs(word);
		if (acc>0xffff) {
			acc-=0xffff;
		}
	}
	return htons(~acc);
}


struct arp_hdr {
	uint16_t ar_hrd;	// hardware address format
	uint16_t ar_pro;	// protocol address format
	unsigned char ar_hln; // hardware address length
	unsigned char ar_pln; // protocol address length
	uint16_t ar_op;		// arp opcode (command)
	unsigned char ar_sha[6]; // sender hardware address
	unsigned char ar_sip[4]; // sender ip address
	unsigned char ar_tha[6]; // target hardware address
	unsigned char ar_tip[4]; // target ip address 
	
};

unsigned long get_ip_saddr (char *if_name, int sockfd){
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_idx)<0)
		perror("SIOCGIFADDR");
	return ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr;
}


unsigned int get_netmask(char *if_name, int sockfd){ 
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq)); 
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1); 
	if((ioctl(sockfd, SIOCGIFNETMASK, &if_idx)) == -1)
		perror("ioctl():");
	return ((struct sockaddr_in *)&if_idx.ifr_netmask)->sin_addr.s_addr;
}


struct arp_hdr generate_parse_ARP_request(char if_name[], char shd_add[], unsigned long sip_add, unsigned long tip_add, char thd_add[]){
	struct arp_hdr arpRequest;

	printf("generating ARP Request\n");
    arpRequest.ar_hrd = htons(1);
    arpRequest.ar_pro = htons(ETH_P_IP);
    arpRequest.ar_hln = 6;
    arpRequest.ar_pln = 4;
    arpRequest.ar_op = htons(0x01);
	memcpy(arpRequest.ar_sha,shd_add,6);
	memcpy(arpRequest.ar_sip, (char*)&sip_add,4);
	memcpy(arpRequest.ar_tha, thd_add,6 );
	memcpy(arpRequest.ar_tip, (char*)&tip_add,4);
	return arpRequest;
}



struct iphdr generate_ip_header(struct in_addr dst, char if_name[], int sockfd, int bufsize) 
{
   //http://www.winlab.rutgers.edu/~zhibinwu/html/c_prog.htm
	printf("constructing IP header...\n");
	printf("bufsize = %d\n",bufsize);
	struct iphdr ip_hdr ;// (struct iphdr*);
	ip_hdr.ihl = 5;//IP4_HDRLEN / sizeof (uint32_t);; //5; //// header length with no option.    5 x 32-bit words in the header
	ip_hdr.version = 4; //ipv4
	ip_hdr.tos = 0; // 6bits
	ip_hdr.tot_len =  htons(IP4_HDRLEN  + bufsize) ;//htons(IP_HEADER_SIZE);//+bufsize);//IP_HEADER_SIZE; sizeof(struct iphdr)+ bufsize;// IP_HEADER_SIZE //htons(IP_HEADER_SIZE+bufsize);
	ip_hdr.id = htons(54321);//htons(54321); // 16 bit id
	ip_hdr.frag_off = 0x00;//htons(0x4000);//0x00;
	ip_hdr.ttl = 225;// 0xFF;// 0x40;
	ip_hdr.protocol = 6;// It can be tcp (6), udp (17), icmp (1),
	ip_hdr.check = 0;
	ip_hdr.saddr = get_ip_saddr(if_name,sockfd);   // 1694607552  // 192.168.1.101   // h1x1 ip 
	ip_hdr.daddr = dst.s_addr;   						   // 1711276042  // 10.0.0.102		 // h3x2 ip
	// printf(" ip_hdr.saddr = %u    ip_hdr.daddr = %u\n",ip_hdr.saddr, ip_hdr.daddr);
	ip_hdr.check = ip_checksum(&ip_hdr, 20);
	printf("IP header constructed...\n");
	return ip_hdr;
}
void send_message(char if_name[], unsigned char buf[], char hw_addr[], struct sockaddr_ll sk_addr, int sockfd, struct ether_header ethernetHeaderFormat, struct ifreq if_idx, int ethType, int totalSize){

	printf(" total Size = %d\n",totalSize);
	if (ethType == 1){// arp
		printf("etherType == arp\n");
		ethernetHeaderFormat.ether_type = htons(ETH_P_ARP); // 2 bytes
		//totalSize = ETHERNET_HEADER_SIZE+totalSize;
		
	}else{
		printf("ether type == ip\n");
		ethernetHeaderFormat.ether_type = htons(ETH_P_IP); // 2 bytes

	}
	printf(" send Message In\n");
	printf("source MAC = [%X %X %X %X %X %X]\n", ethernetHeaderFormat.ether_shost[0], ethernetHeaderFormat.ether_shost[1],ethernetHeaderFormat.ether_shost[2],ethernetHeaderFormat.ether_shost[3], ethernetHeaderFormat.ether_shost[4], ethernetHeaderFormat.ether_shost[5]  );
	printf("dst    MAC = [%X %X %X %X %X %X]\n", ethernetHeaderFormat.ether_dhost[0], ethernetHeaderFormat.ether_dhost[1],ethernetHeaderFormat.ether_dhost[2],ethernetHeaderFormat.ether_dhost[3], ethernetHeaderFormat.ether_dhost[4], ethernetHeaderFormat.ether_dhost[5]  );
	

	// for(int i = 0 ; i < totalSize; i++){
	// 	printf(" %X   %c\n",buf[i], buf[i]);
	// }
	
	unsigned char temBuf[BUF_SIZ];
	char *frame = (char*)&ethernetHeaderFormat;
    memcpy(temBuf,frame,14);
    memcpy(&temBuf[14], buf, totalSize); //strlen(buf)+1);
	memset(&sk_addr, 0, sizeof(struct sockaddr_ll)); 
	sk_addr.sll_ifindex = if_idx.ifr_ifindex; 
	sk_addr.sll_halen = ETH_ALEN;

	//temBuf contains    [[Ethernet Heather] + [Arp Heather] + [Message]]
	//					[Dst_MAC + Src_MAC + Type] +  [types + SHA, SIP, THA, TIP]     + [ Message]
	//							14 								28							vary
	

	// for(int i = 0 ; i < totalSize+14; i++){
	// 	printf(" %X   %c\n",temBuf[i], temBuf[i]);
	// }
	int byteSent = sendto(sockfd, temBuf, 14+totalSize, 0, (struct sockaddr*)&sk_addr, sizeof(struct sockaddr_ll));	

	printf("%d bytes Sent\n\n", byteSent);
}

void recv_message(char if_name[], struct sockaddr_ll sk_addr){

	//Do something here
	

	int sockfd = -1;
	if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){
		perror("socket() failed!");
	}

	struct ifreq if_idx;
   	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1); 
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");



   if (ioctl(sockfd, SIOCGIFHWADDR, &if_idx) < 0)
		perror("SIOCGIFHWADDR");




	int sk_addr_size = sizeof(struct sockaddr_ll);
	char buf[BUF_SIZ];
 	memset(&sk_addr, 0, sk_addr_size);

	printf("------------------------------------\nReceiving ...\n");
    int recvLen = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, &sk_addr_size );

	printf("%d bytes were received\n",recvLen);

	unsigned char src_mac[6];
	memcpy(src_mac, &buf, 6);

	unsigned char dst_mac[6];
	memcpy(dst_mac, &buf[6], 6);

	unsigned short net_port = htons(ETH_P_IP);

	char message[recvLen];
	printf("Source      MAC: [%X][%X][%X][%X][%X][%X]\n",dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
	printf("Destination MAC: [%X][%X][%X][%X][%X][%X]\n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
	printf("Type: %x\n",  net_port);
	printf("Data: %s \n", &buf[14]);
}

int main(int argc, char *argv[])
{
	int mode;
	char hw_addr[6];
	char interfaceName[IFNAMSIZ];
    char broadcast[6] ={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	char h3x2[6] = {0,0,0,0,0,0x32};
	struct in_addr destIP, routerIP;
	// unsigned long destIp, routerIp;
	char buf[BUF_SIZ];

	memset(buf, 0, BUF_SIZ);
	
	int correct=0;
	if (argc > 1){
		if(strncmp(argv[1],"Send", 4)==0){
			if (argc == 6){
				mode=SEND; 
				// 0:a.out    1:Send/Recv     2: Interface     3:destIP    4:routerIP      5:message

				inet_aton(argv[3],&destIP); // destIP
				inet_aton(argv[4],&routerIP); // routerIP
				strncpy(buf, argv[5], BUF_SIZ);
				correct=1;	
			}
		}
		else if(strncmp(argv[1],"Recv", 4)==0){
			if (argc == 3){
				mode=RECV;
				correct=1;
			}
		}
		strncpy(interfaceName, argv[2], IFNAMSIZ);
	 }	
	 if(!correct){
		fprintf(stderr, "./455_proj2 Send <InterfaceName> <DestIP> <RouterIP> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
		exit(1);
	 }

	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
    // struct in_addr addr;


	if(mode == SEND){
		printf("\nSEND\n");
		int sockfd; // make socket
        if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0){ 
            perror("socket() failed");
        }

        struct ifreq if_idx;   // connect Sender interface
        memset(&if_idx, 0, sizeof(struct ifreq));
        strncpy(if_idx.ifr_name, interfaceName, IFNAMSIZ-1); 
        if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
            perror("SIOCGIFINDEX");

        struct ifreq if_hw_MAC_addr; //get Sender MAC address
        memset(&if_hw_MAC_addr, 0, sizeof(struct ifreq));
        strncpy(if_hw_MAC_addr.ifr_name, interfaceName, IFNAMSIZ-1); 
        if (ioctl(sockfd, SIOCGIFHWADDR, &if_hw_MAC_addr) < 0)
            perror("SIOCGIFHWADDR");
	
        //set ethernet frame;

        struct ether_header ethernetHeaderFormat;

        memset(&ethernetHeaderFormat, 0, sizeof(struct ether_header));
        memcpy(ethernetHeaderFormat.ether_dhost, broadcast, 6);   //destination host MAC address 6 bytes
        memcpy(ethernetHeaderFormat.ether_shost, if_hw_MAC_addr.ifr_hwaddr.sa_data,6);	//source host MAC address 6 bytes


		printf(" socket fd = %d\n",sockfd);

		//send_message(interfaceName, buf, hw_addr, sk_addr);
        
		unsigned long senderNetMask = get_netmask(interfaceName,sockfd);
		unsigned long senderIp = get_ip_saddr(interfaceName,sockfd);
		struct arp_hdr arpRequest;
		int etherFrameType;

		printf(" destIP = %u \n",destIP.s_addr);
		printf(" sender routerIP = %u \n",routerIP.s_addr);
		printf(" sender Netmask = %lu\n",senderNetMask);
		printf(" sender Ip = %lu \n",senderIp);
		printf(" len of buf = %ld\n",strlen(buf));
		int k = 0 ; 
		int networkSwitch =0 ;
		

		if (   (senderIp & senderNetMask) == ( destIP.s_addr & senderNetMask )   ){
			printf("in the same netmask\n");
			networkSwitch = 1;
			arpRequest = generate_parse_ARP_request( interfaceName, if_hw_MAC_addr.ifr_hwaddr.sa_data, senderIp, destIP.s_addr, broadcast );
		}else
		{
			printf("in the different netmask\n");
			networkSwitch = 0;
			arpRequest = generate_parse_ARP_request( interfaceName, if_hw_MAC_addr.ifr_hwaddr.sa_data, senderIp, routerIP.s_addr, broadcast );
		}

		unsigned char payload[ARP_HEADER_SIZE+BUF_SIZ];
        char *arp = (char*)&arpRequest;
        memcpy(payload, arp, ARP_HEADER_SIZE);
        memcpy(&payload[ARP_HEADER_SIZE],buf,strlen(buf));  // arp header + buf.


		etherFrameType = 1; // this indicates arp request type
        send_message(interfaceName, payload, broadcast, sk_addr, sockfd, ethernetHeaderFormat, if_idx, etherFrameType, ARP_HEADER_SIZE+strlen(buf));
		
		printf("send out \n");

        unsigned char response[BUF_SIZ];
        unsigned char destinationMAC[6];
        int recLev;
        int sk_addr_size = sizeof(struct sockaddr_ll);
		char targetip[4];

        while(1)
        {   
           // sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
            memset(&sk_addr, 0, sk_addr_size);
			printf("recv arp mode\n");
            recLev = recvfrom(sockfd, response, BUF_SIZ, 0 , (struct sockaddr*)&sk_addr, &sk_addr_size );
			printf(" %d bytes received \n",recLev);

			if(response[12] == 0x08 && response[13] == 0x06 && response[20] == 0x00 && response[21] == 0x02){ //arpSS
				memcpy(destinationMAC, &response[22], 6);   
				//memcpy(targetip, &response[38],4);
				// 	printf("Source      MAC: [%X][%X][%X][%X][%X][%X]\n",(unsigned char)if_hw_MAC_addr.ifr_hwaddr.sa_data[0],(unsigned char)if_hw_MAC_addr.ifr_hwaddr.sa_data[1],(unsigned char)if_hw_MAC_addr.ifr_hwaddr.sa_data[2],(unsigned char)if_hw_MAC_addr.ifr_hwaddr.sa_data[3],(unsigned char)if_hw_MAC_addr.ifr_hwaddr.sa_data[4],(unsigned char)if_hw_MAC_addr.ifr_hwaddr.sa_data[5]);
				printf(" Destination MAC: [%X][%X][%X][%X][%X][%X]\n",destinationMAC[0],destinationMAC[1],destinationMAC[2],destinationMAC[3],destinationMAC[4],destinationMAC[5]); //router
				//printf(" Target Ip =[%u] [%u] [%u] [%u] \n",targetip[0],targetip[1],targetip[2],targetip[3]); //192,168,1,101 this is sender ip
				break;
			}
        }

		// memcpy(ethernetHeaderFormat.ether_dhost, broadcast, 6);   //destination host MAC address 6 bytes
        // memcpy(ethernetHeaderFormat.ether_shost, destinationMAC,6);	//source host MAC address 6 bytes


		// send IP packet
		memset(&sk_addr,0,sk_addr_size);
		struct iphdr ip_hdr;
		struct tcphdr tcp_hdr;
		if((senderIp & senderNetMask) == (destIP.s_addr & senderNetMask)){
			ip_hdr = generate_ip_header(destIP, interfaceName, sockfd, strlen(buf) );//  destIP.s_addr, interfaceName, sockfd, strlen(buf));
		}
		else{
			ip_hdr = generate_ip_header(destIP, interfaceName, sockfd, strlen(buf));
		}

		// struct in_addr destIP, routerIP;

		//tcp_hdr = generate_tcp_header(sockfd,sk_addr,ip_hdr);

		//printf("test tcp header size = %d\n",sizeof(tcp_hdr));

		//ip_hdr.check = ip_checksum(&ip_hdr, 20);

		char ip_payload[IP_HEADER_SIZE+TCP_HDRLEN+strlen(buf)];
		char *ip = (char *)&ip_hdr;
		char *tcph = (char *)&tcp_hdr;
		memcpy(ip_payload, ip, IP_HEADER_SIZE);
		memcpy(&ip_payload[IP_HEADER_SIZE],buf,strlen(buf));
		// memcpy(&ip_payload[IP_HEADER_SIZE], tcph, TCP_HDRLEN);
		// memcpy(&ip_payload[IP_HEADER_SIZE+TCP_HDRLEN], buf, strlen(buf));
		for(int i = 0 ; i < 6; i++){
			ethernetHeaderFormat.ether_dhost[i] = destinationMAC[i];
		}

		etherFrameType = 2;
		// for(int i = 0 ; i < IP_HEADER_SIZE+TCP_HDRLEN+strlen(buf) ; i++ ){
		// 	printf(" %X  %d  %c \n",ip_payload[i] , ip_payload[i], ip_payload[i]);
		// }
        // send_message(interfaceName, ip_payload, destinationMAC, sk_addr, sockfd, ethernetHeaderFormat, if_idx, etherFrameType, IP_HEADER_SIZE+TCP_HDRLEN+strlen(buf));
        send_message(interfaceName, ip_payload, destinationMAC, sk_addr, sockfd, ethernetHeaderFormat, if_idx, etherFrameType, IP_HEADER_SIZE+strlen(buf));
	}
	else if (mode == RECV){
        printf("\nRECV\n");


		unsigned char fromMAC[6];
		unsigned char toMAC[6];
		unsigned char message[BUF_SIZ];
		int sockfd;
		if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){
			perror("socket() failed!");
		}
		unsigned char response[BUF_SIZ];
		char targetIP[4];
		int sk_addr_size = sizeof(struct sockaddr_ll);
		while(1){
			memset(&sk_addr,0,sk_addr_size);
			int recvLen = recvfrom(sockfd, response, BUF_SIZ, 0 , (struct sockaddr*)&sk_addr, &sk_addr_size);
			if(response[12] == 0x08 && response[13] == 0x06){//} && response[20] == 0x00 && response[21] == 0x01){
				printf("arp request\n");
				for(int i =0 ; i < recvLen; i++){
					printf("[%X]",response[i]);
				}
			}
			else{
				memcpy(fromMAC,response,6);
				memcpy(toMAC,&response[6],6);

				memcpy(message, &response[ETHERNET_HEADER_SIZE+IP4_HDRLEN],BUF_SIZ);
				printf("Message\n");
				for(int i =0 ; i < strlen(message); i++){
					printf("%c",message[i]);
				}
				// printf(" from MAC \n");
				// for(int i = 0 ; i < 6; i++){
				// 	printf(" %X ",fromMAC[i]);
				// }
				// printf("\n");
				// for(int i = 0 ; i < 6; i++){
				// 	printf(" %X ",toMAC[i]);
				// }
			}
			printf("\n\n\n");	
			break;
		}
	}


	return 0;
}

