#include <iostream>
#include <pcap.h>
#include <unordered_map>
//#include <map>
//#include "tcpsession.h"
#include "printflow.h"

extern FLOW_MAP tcpmap;
extern FLOW_MAP udpmap;


void usage() {
    printf("syntax: pcap-test <packetfile.pcap>\n");
    printf("sample: pcap-test gilgil.pcap\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    const char* fname = argv[1];
    printf("file name : %s\n",fname);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(fname, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) return nullptr - %s\n", fname, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        printf("packet startinn\n");
        if (res == 0) {
            printf("res = 0\n");
            continue;
        }
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("res : %d\n",res);

        struct ethernet_hdr *etherPacket = (struct ethernet_hdr *)packet;
        if(ntohs(etherPacket->ether_type)!=ETHERTYPE_IP){
            std::cout<<"this is not ipv4Packet\n";
            continue;
        }
        flow(packet, header);    //packet flow 처리하기
    }
   
    std::cout<<"\n----------\n";
    std::cout<<"print tcp";
    PrintFlow(&tcpmap);
    std::cout<<"\n----------\n";
    std::cout<<"print udp";
    PrintFlow(&udpmap);
}

