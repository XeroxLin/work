#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#define ETH_HEADER_LEN 14 
#define IP_HEADER_PROTOCOL_BYTE 9 
#define TCP_HEADER_LEN_BYTE 12

int trim_payload(const u_char* packet,
			int caplen,
			const u_char** payload_packet) {
	int ip_header_len;
	int tcp_header_len;
	int header_len;
	int payload_len;
	const u_char* ip_header;
	const u_char* tcp_header;

	ip_header = packet + ETH_HEADER_LEN;
	ip_header_len = (*ip_header) & 0x0F;
	ip_header_len *= 4;

	tcp_header = packet + ETH_HEADER_LEN + ip_header_len;
	tcp_header_len = ((*(tcp_header + TCP_HEADER_LEN_BYTE)) & 0xF0) >> 4;
	tcp_header_len *= 4;

	header_len = ETH_HEADER_LEN + ip_header_len + tcp_header_len;
	payload_len = caplen - header_len;
	if (payload_len <= 0)
		return 0;

	*payload_packet = packet + header_len;
	return payload_len;
}

int check_tcp_packet(const u_char* packet) {
	struct ether_header* eth_header;
	u_char protocol;

	eth_header = (struct ether_header *)packet;
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
		printf(" This isn't IP packet\n ");
		return 0;
	}
	protocol = *(packet + ETH_HEADER_LEN + IP_HEADER_PROTOCOL_BYTE);
	if (protocol != IPPROTO_TCP) {
		printf(" This isn't TCP packet\n ");
		return 0;
	}
	return 1;
}

void ftd_packet_handler(u_char* args, const struct pcap_pkthdr *header, const u_char* packet) {
	int payload_len;
	static int packet_cnt = 0;
	const u_char* payload_packet = NULL;

	packet_cnt++;

	if (!check_tcp_packet(packet))
		return;

	payload_len = trim_payload(packet, header->caplen, &payload_packet);
	if (payload_len <= 0)
		return;
	if (*payload_packet == 0x01) {
		printf("FTDTypeFTDC at No.%d\n", packet_cnt);
	} else if (*payload_packet == 0x02) {
		printf("FTDTypeCompressed at No.%d\n", packet_cnt);
	}
	return;
}

void main() {
	char error_buffer[PCAP_ERRBUF_SIZE];
	//const u_char* packet;
	//const u_char* payload_packet = NULL;
	//struct pcap_pkthdr packet_header;

	pcap_t *handle = pcap_open_offline("alltraffic.pcap", error_buffer);
/*
	packet = pcap_next(handle, &packet_header);

	printf("Packet capture length: %d\n", packet_header.caplen);
	printf("Packet length: %d\n", packet_header.len);

	if (!check_tcp_packet(packet))
		return;

	payload_len = trim_payload(packet, packet_header.caplen, &payload_packet);
	for(i = 0; i < payload_len; i++)
		printf("Payload data: %x\n", *(payload_packet + i));
*/
	pcap_loop(handle, 0, ftd_packet_handler, NULL);

	return;
}
