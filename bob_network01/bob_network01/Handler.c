#include "packetH.h"

#define SIZE_ETHERNET 14

//
void printReport(ether_header *eh, ip_header *ih, tcp_header *th);
void printPacket(const struct pcap_pkthdr *header, const u_char *pkt_data);

/* 패킷이 캡처 됬을때, 호출되는 콜백 함수 */
void packet_handler(u_char *param,                    //파라미터로 넘겨받은 값 
	const struct pcap_pkthdr *header, //패킷 정보 
	const u_char *pkt_data)           //실제 캡처된 패킷 데이터
{
	// 아이피, 포트를 구하기 위한 변수
	ether_header *eh;
	ip_header *ih;
	//udp_header *uh;
	tcp_header *th;
	u_int ip_len;
	/* retireve the position of the ip header */


	eh = (ether_header *)pkt_data;
	ih = (ip_header *)(pkt_data + SIZE_ETHERNET); //length of ethernet header
	ip_len = (ih->ver_ihl & 0xf) * 4;
	th = (tcp_header *) ( pkt_data + SIZE_ETHERNET + ip_len );

	//uh = (udp_header *)((u_char*)ih + ip_len);

	printReport(eh, ih, th);
	printPacket(header, pkt_data);

}

void printReport(ether_header *eh, ip_header *ih, tcp_header *th) {

	printf("Ethernet MAC src >> %x:%x:%x:%x:%x:%x\n", eh->src_host[0], eh->src_host[1], eh->src_host[2], eh->src_host[3], eh->src_host[4], eh->src_host[5]);
	printf("Ethernet MAC dst >> %x:%x:%x:%x:%x:%x\n", eh->dst_host[0], eh->dst_host[1], eh->dst_host[2], eh->dst_host[3], eh->dst_host[4], eh->dst_host[5]);
	printf("IP src >> %d.%d.%d.%d\n", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
	printf("IP dst >> %d.%d.%d.%d\n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
	printf("TCP src PORT >> %d\n", ntohs(th->sport));
	printf("TCP dst PORT >> %d\n\n", ntohs(th->dport));
}


void printPacket(const struct pcap_pkthdr *header, const u_char *pkt_data) {
	int i;

	printf("Hex Dump\n");
	for (i = 1; (i < header->caplen + 1); i++)
	{
		printf("%.2x ", pkt_data[i - 1]);
		if ((i % 16) == 0) printf("\n");
	}
	printf("\n\n");

}