#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#define ETH_HEADER_LEN 14 
#define IP_HEADER_PROTOCOL_BYTE 9 
#define TCP_HEADER_LEN_BYTE 12
#define FTDTypeFTDC  0x01
#define FTDTypeCompressed  0x02

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

int check_ftd_packet(const u_char* packet, int payload_len) {
	int ftd_header_len = 4;
	int ftd_ext_cmd_len = 0;
	int ftd_data_len = 0;

	ftd_ext_cmd_len = *(packet+1) & 0x7F;
	ftd_data_len = ((*(packet+2) & 0x1F) << 4) | (*(packet+3) & 0xFF);

	return (payload_len == ftd_header_len + ftd_ext_cmd_len + ftd_data_len)?1:0;
}

int decompress_ftdc(const u_char* ori_packet, u_char* de_data, int ftd_data_len) {
	int ftdc_len = 0;
	int i, j;

	for(i = 0, j = 0; i < ftd_data_len; i++, j++, ftdc_len++) {
		if((ori_packet[i] < 0xe0) | (ori_packet[i] > 0xef)) {
			de_data[j] = ori_packet[i];
		} else {
			if(ori_packet[i] == 0xe0) {
				i++;
				de_data[j] = ori_packet[i];
			} else if (ori_packet[i] == 0xe1){
				continue;
			} else {
				ftdc_len += ori_packet[i] - 0xe1;
				j += ori_packet[i] - 0xe1;
			}
		}
	}
	//printf("%x %x %x %x ", *de_data, *(de_data + 1), *(de_data + 2), *(de_data + 3));
	return ftdc_len;
}

void parse_ftdc(const u_char* packet, int payload_len) {
	const u_char* ftd_data;
	//u_char* de_ftdc_data;
	u_char de_ftdc_data[4096];
	int ftd_ext_cmd_len = 0;
	int ftd_data_len = 0;
	int de_ftdc_len = 0;
	int i;

	ftd_ext_cmd_len = *(packet+1) & 0x7F;
	ftd_data_len = ((*(packet+2) & 0x1F) << 4) | (*(packet+3) & 0xFF);

	ftd_data = (packet + 4 + ftd_ext_cmd_len);
	//printf("%x %x %x %x ", *ftd_data, *(ftd_data + 1), *(ftd_data + 2), *(ftd_data + 3));

	de_ftdc_len = decompress_ftdc(ftd_data, de_ftdc_data, ftd_data_len);
	printf("de_ftdc_len=%d\n", de_ftdc_len);
	for(i = 0; i < de_ftdc_len; i++) {
		printf("%x ", *(de_ftdc_data + i));
		if((i % 10) == 0)
			printf("\n");
	}
	//printf("%x %x %x %x ", *de_ftdc_data, *(de_ftdc_data + 1), *(de_ftdc_data + 2), *(de_ftdc_data + 3));

	printf("\n");
	return;
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

	if(!check_ftd_packet(payload_packet, payload_len))
		return;

	switch(*payload_packet) {
		case FTDTypeCompressed:
			printf("FTDTypeCompressed at No.%d\n", packet_cnt);
			parse_ftdc(payload_packet, payload_len);
			break;
		case FTDTypeFTDC:
			printf("FTDTypeFTDC at No.%d\n", packet_cnt);
			break;
		default:
			break;
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
