#include "packetH.h"
//
int main()
{
	int packetCnt = 1;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *filter = "port 80";	//tcpdump filter ��Ģ
	struct bpf_program fcode;
	bpf_u_int32 NetMask;

	/* ��Ʈ��ũ �ٹ��̽� ����� �����´�. */
	/* alldevs�� ����Ʈ ���·� ����Ǹ�, ������ errbuf�� ���� ���� ���� */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��Ʈ��ũ �ٹ��̽����� ����Ѵ�. */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	/* ���� ó�� */
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	/* ĸó�� ��Ʈ��ũ ����̽� ���� */
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	/* �Է°��� ��ȿ�� �Ǵ� */
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* ��ġ ��� ���� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* ����ڰ� ������ ��ġ��� ���� */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);
	/* ���� ��Ʈ��ũ ����̽��� ���� */
	if ((adhandle = pcap_open_live(d->name, // ����̽���
		65536,   // �ִ� ĸó���� 
				 // 65536 -> ĸó�ɼ� �ִ� ��ü ���� 
		1,    // 0: �ڽſ��� �ش�Ǵ� ��Ŷ�� ĸó
			  // 1: ������ ��� ��Ŷ ĸó
		1000,   // read timeout 
		errbuf   // �������� ���庯�� 
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* ��ġ ��� ���� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s...\n\n", d->description);
	/* �ݸ���ũ ����,  */
	NetMask = 0xffffff;
	// ����ڰ� ���� ���� ������
	if (pcap_compile(adhandle, &fcode, filter, 1, NetMask) < 0)
	{
		fprintf(stderr, "\nError compiling filter: wrong syntax.\n");
		pcap_close(adhandle);
		return -3;
	}
	// ����ڰ� ���� ���� ����
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter\n");
		pcap_close(adhandle);
		return -4;
	}
	/* ��ġ ��� ���� */
	pcap_freealldevs(alldevs);
	/* ĸó ���� */
	pcap_loop(adhandle,      // pcap_open_live���� ���� ��Ʈ��ũ ����̽� �ڵ�
		packetCnt,     // 0 : ���ѷ���
					   // �������� : ĸó�� ��Ŷ�� 
		packet_handler,  // ��Ŷ�� ĸó������, ȣ��� �Լ� �ڵ鷯 
		NULL);           // �ݹ��Լ��� �Ѱ��� �Ķ����
	pcap_close(adhandle);    // ��Ʈ��ũ ����̽� �ڵ� ����
	return 0;

}
