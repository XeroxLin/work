#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#define DEBUG 0

#define FILE_PCAP "alltraffic.pcap"
#define OUTPUT_FILE "final_results.csv"

#define ETH_HEADER_LEN 14 
#define IP_HEADER_PROTOCOL_BYTE 9 
#define TCP_HEADER_LEN_BYTE 12
#define FTDTypeFTDC  0x01
#define FTDTypeCompressed  0x02
#define FTD_HEADER_LEN 22
#define FTDC_FieldCnt_BYTE_H 14
#define FTDC_FieldCnt_BYTE_L 15
#define FID_OrderStatusField_OrderStatus 175
#define FID_OrderStatusField_UserOrderLocalID 26
#define FID_OrderStatusField_UserOrderLocalID_LEN 12
#define FID_OrderStatusField_LimitPrice 156
#define FID_OrderStatusField_LimitPrice_LEN 14
#define FID_OrderStatusField_Direction 109
#define FID_OrderStatusField_InstrumentID 50
#define FID_OrderStatusField_InstrumentID_LEN 8
#define FID_OrderStatusField_H 0x25
#define FID_OrderStatusField_L 0x08

#define ASCII_SPACE 0x20
#define ASCII_ZERO 0x30
#define ASCII_NINE 0x39

/* Trim to payload from the packets */
int trim_payload(const u_char* packet, int caplen,
			const u_char** payload_packet) {
	int ip_header_len;
	int tcp_header_len;
	int header_len;
	int payload_len;
	const u_char* ip_header;
	const u_char* tcp_header;

	/* Calculate ip header length  */
	ip_header = packet + ETH_HEADER_LEN;
	ip_header_len = (*ip_header) & 0x0F;
	ip_header_len *= 4;

	/* Calculate tcp header length  */
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

/* Check tcp packet type */
int check_tcp_packet(const u_char* packet) {
	struct ether_header* eth_header;
	u_char protocol;

	eth_header = (struct ether_header *)packet;

	/* Check whether packet is IP packet */
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
		return 0;

	protocol = *(packet + ETH_HEADER_LEN + IP_HEADER_PROTOCOL_BYTE);

	/* Check whether packet is TCP packet */
	if (protocol != IPPROTO_TCP)
		return 0;

	return 1;
}

int check_ftdc_len(const u_char* packet) {
	u_char temp[18] = {0};
	int i, j;

	for(i = 4, j = 0; j < 18; i++, j++) {
		if((packet[i] < 0xe0) | (packet[i] > 0xef)) {
			temp[j] = packet[i];
		} else {
			if(packet[i] == 0xe0) {
				i++;
				temp[j] = packet[i];
			} else if (packet[i] == 0xe1){
				continue;
			} else {
				j += (packet[i] - 0xe1);
			}
		}
	}
	return (temp[12] << 8) | (temp[13]);
}

/*
 * Decompress the FTDC packet
 * It will compress '00' into '0xe[1-f]' depend on number of '00'
 * The 0xe5 will decompress to '00 00 00 00 00'
 * If native value during 0xe0~0xef, it will add 0xe0 behind it.
 * The 0xe6 will compress to '0xe0 0xe6'
 */
u_char* decompress_ftdc(const u_char* ori_packet, int ftd_data_len) {
	int ftdc_len = 0;
	int i, j;
	u_char* de_data = NULL;

	ftdc_len = check_ftdc_len(ori_packet) + FTD_HEADER_LEN;
	de_data = malloc(sizeof(u_char)*ftdc_len);
	memset(de_data, 0, sizeof(u_char)*ftdc_len);

	for(i = 0, j = 0; i < ftd_data_len; i++, j++) {
		if((ori_packet[i] < 0xe0) | (ori_packet[i] > 0xef)) {
			de_data[j] = ori_packet[i];
		} else {
			if(ori_packet[i] == 0xe0) {
				i++;
				de_data[j] = ori_packet[i];
			} else if (ori_packet[i] == 0xe1){
				continue;
			} else {
				j += (ori_packet[i] - 0xe1);
			}
		}
	}
	return de_data;
}

/* parse information from CFTDOrderField */
void parseOrderStatusField(const u_char* field_packet) {
	FILE *fd;
	int i = 0, redundant_zero_check = 0;

	fd = fopen(OUTPUT_FILE, "a");

	fprintf(fd, "%c,", (*(field_packet + FID_OrderStatusField_OrderStatus)));
	for(i = 0; i < FID_OrderStatusField_UserOrderLocalID_LEN; i++) {
		if(*(field_packet + FID_OrderStatusField_UserOrderLocalID + i) != ASCII_SPACE)
			fprintf(fd, "%c", *(field_packet + FID_OrderStatusField_UserOrderLocalID + i));
	}
	fprintf(fd, ",");

	for(i = 0, redundant_zero_check = 0; i < FID_OrderStatusField_LimitPrice_LEN; i++) {
		if((*(field_packet + FID_OrderStatusField_LimitPrice + i) < ASCII_ZERO)
			||(*(field_packet + FID_OrderStatusField_LimitPrice + i) > ASCII_NINE))
			continue;

		if((i < 9) && (redundant_zero_check == 0) && *(field_packet + FID_OrderStatusField_LimitPrice + i) == ASCII_ZERO)
			continue;

		if(i == 10)
			fprintf(fd, ".");
		fprintf(fd, "%c", *(field_packet + FID_OrderStatusField_LimitPrice + i));
	}
	fprintf(fd, ",");

	fprintf(fd, "%c,", *(field_packet + FID_OrderStatusField_Direction));
	for(i = 0; i < FID_OrderStatusField_InstrumentID_LEN; i++)
		fprintf(fd, "%c", *(field_packet + FID_OrderStatusField_InstrumentID + i));
	fprintf(fd, "\n");

	fclose(fd);
}

/* dump and analysis packet */
void dump(u_char* de_ftdc_data) {
	int i = 0, j, k, fieldcnt, fieldlen;

	printf("Version: %02x\n", *(de_ftdc_data + i++));
	printf("Type: %02x\n", *(de_ftdc_data + i++));
	printf("UnEncodelen: %02x\n", *(de_ftdc_data + i++));
	printf("Chain: %02x\n", *(de_ftdc_data + i++));
	printf("TID: %02x%02x\n", *(de_ftdc_data + i), *(de_ftdc_data + i + 1));
	i = i + 2;
	printf("Unknow: %02x%02x%02x%02x\n", *(de_ftdc_data + i), *(de_ftdc_data + i + 1), *(de_ftdc_data + i + 2), *(de_ftdc_data + i +3));
	i = i + 4;
	printf("Unknow: %02x%02x%02x%02x\n", *(de_ftdc_data + i), *(de_ftdc_data + i + 1), *(de_ftdc_data + i + 2), *(de_ftdc_data + i +3));
	i = i + 4;
	printf("FieldCnt: %02x%02x\n", *(de_ftdc_data + i), *(de_ftdc_data + i + 1));
	fieldcnt = *(de_ftdc_data + i + 1);
	i = i + 2;
	printf("FTDCContentLength: %02x%02x\n", *(de_ftdc_data + i), *(de_ftdc_data + i + 1));
	i = i + 2;
	printf("Unknow: %02x%02x%02x%02x\n", *(de_ftdc_data + i), *(de_ftdc_data + i + 1), *(de_ftdc_data + i + 2), *(de_ftdc_data + i +3));
	i = i + 4;

	for(j = 0; j < fieldcnt; j++) {
		printf("FieldId: %02x%02x\n", *(de_ftdc_data + i), *(de_ftdc_data + i + 1));
		i = i + 2;
		fieldlen = ((*(de_ftdc_data + i)) << 8) | (*(de_ftdc_data + i + 1));
		printf("FieldLength: %02x%02x (%d)\n", *(de_ftdc_data + i), *(de_ftdc_data + i + 1), fieldlen);
		i = i + 2;
		for(k = 0;k < fieldlen; i++, k++) {
			printf("%02x ", *(de_ftdc_data + i));
			if(((i % 10) == 0) && i != 0)
				printf("\n");
		}
		printf("\n");
	}
}

/* parse FTDC packet */
void parse_ftdc(const u_char* packet, int payload_len) {
	const u_char* pFTD = NULL;
	const u_char* pFID = NULL;
	u_char* de_ftdc_data = NULL;
	int ftd_ext_cmd_len = 0;
	int ftd_data_len = 0;
	int fieldCnt = 0;
	int field_len = 0;
	int i = 0;

	do {
		if(pFTD != NULL)
			pFTD = pFTD + ftd_data_len;
		ftd_ext_cmd_len = *(packet+1) & 0x7F;
		ftd_data_len = ((*(packet+2) & 0x1F) << 8) | (*(packet+3) & 0xFF);

		pFTD = (packet + 4 + ftd_ext_cmd_len);

		payload_len = payload_len - 4 - ftd_ext_cmd_len - ftd_data_len;

		if(payload_len < 0) {
			if(DEBUG)
				printf("Data broken\n");
			return;
		}

		//assign pointer to next packet
		packet = packet + 4 + ftd_ext_cmd_len + ftd_data_len;

		de_ftdc_data = decompress_ftdc(pFTD, ftd_data_len);

		if(DEBUG)
			dump(de_ftdc_data);

		fieldCnt = (*(de_ftdc_data + FTDC_FieldCnt_BYTE_H) << 8) | (*(de_ftdc_data + FTDC_FieldCnt_BYTE_L));

		pFID = de_ftdc_data + FTD_HEADER_LEN;

		for(i = 0, field_len = 0; i < fieldCnt ; i++) {
			pFID = pFID + field_len;
			if((*(pFID) == FID_OrderStatusField_H)
					&& (*(pFID + 1) == FID_OrderStatusField_L)) {
				parseOrderStatusField(pFID);
			}
			field_len = (*(pFID + 2) << 8) | (*(pFID + 3)) + 4;
		}
		free(de_ftdc_data);
		de_ftdc_data = NULL;
	} while(payload_len > 0);
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

	switch(*payload_packet) {
		case FTDTypeCompressed:
			if(DEBUG)
				printf("FTDTypeCompressed at No.%d  payload_len=%d\n", packet_cnt, payload_len);
			parse_ftdc(payload_packet, payload_len);
			break;
		case FTDTypeFTDC:
			if(DEBUG)
				printf("FTDTypeFTDC at No.%d  payload_len=%d\n", packet_cnt, payload_len);
			break;
		default:
			break;
	}
	return;
}

void main() {
	char error_buffer[PCAP_ERRBUF_SIZE];

	pcap_t *handle = pcap_open_offline(FILE_PCAP, error_buffer);

	pcap_loop(handle, 0, ftd_packet_handler, NULL);

	return;
}
