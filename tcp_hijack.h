/*
 * pcap_example.h
 *
 *  Created on: Apr 28, 2016
 *      Author: jiaziyi
 */

#ifndef PCAP_EXAMPLE_H_
#define PCAP_EXAMPLE_H_

#define BUF_SIZE 65536

#define LINKTYPE_NULL 0
#define LINKTYPE_ETH 1
#define LINKTYPE_WIFI 127

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);


#endif /* PCAP_EXAMPLE_H_ */
