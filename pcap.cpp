#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>          //for socket
#include <sys/socket.h>         //for socket
#include <sys/ioctl.h>          //for ioctl function
#include <arpa/inet.h>
#include <sys/ioctl.h> 
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include "headers.h"
#include "link.h"

int getMy_IP(char *my_ip);
void usage() {
    printf("syntax: pcap-test <packetfile.pcap>\n");
    printf("sample: pcap-test gilgil.pcap\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* fname = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(fname, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_offline(%s) return nullptr - %s\n", fname, errbuf);
        return -1;
    }
    char *my_ip;
    getMy_IP(my_ip);
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct libnet_ethernet_hdr* etherPacket = (struct libnet_ethernet_hdr*)packet;
        if(ntohs(etherPacket->ether_type) != ETHERTYPE_IP)      //ethertype이 IPv4가 아니면 다음패킷ㄱㄱ
            continue;
        struct libnet_ipv4_hdr *ipPacket = (struct libnet_ipv4_hdr *)packet+14;                   //ip부분으로 ㄱㄱ
        if(ntohs(ipPacket->ip_p)==P_TCP){                       //ip protocol이 tcp일 때
            tcp_insert(ipPacket, my_ip, packet);
        }
        else if(ntohs(ipPacket->ip_p)==P_UDP){                  //ip protocol이 UDP일 때
            udp_insert(ipPacket, my_ip, packet);
        }
        else continue;                                          //ip protocol이 tcp, udp 둘다 아니면 다음패킷 ㄱㄱ
        
        printf("%u bytes captured\n", header->caplen);
    }
    printStatistic();                         // 패킷 다 읽으면 출력내기
    pcap_close(handle);
}

int getMy_IP(char *my_ip)
{
    int sock;
    struct ifreq ifr;
    char *my_ip;

    sock = socket(AF_PACKET, SOCK_DGRAM, 0);
    if (sock < 0){
        perror("socket");
        close(sock);
        return -1;
    }
    printf("socket good\n");
    strcpy(ifr.ifr_name, "enp0s3");
    if (ioctl(sock, SIOCGIFADDR, &ifr)< 0){
        perror("ioctl() - get ip");
        close(sock);
        return -1;
    }
    struct sockaddr_in *addr;
    addr =(struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(my_ip, inet_ntoa(addr-> sin_addr), sizeof(ifr.ifr_addr));
    close(sock);
    return 0;
}
void printStatistic(){
    listpointer temp, freetemp;
	temp = TCPfirst;                              //temp에 tcp link list first주소 저장
	printf("TCP Packet\n");
	printf("Address A\t| PortA | Address B\t| PortB | Packets | Bytes | Packets A->B | Bytes A->B | Packet B->A | Bytes B->A |\n");
    for (; temp; temp = temp->link){
		printf("%s | %d | %s | %d | %d | %d | %d | %d | %d | %d | \n", inet_ntoa(temp->data.A_address), temp->data.Aport, 
        inet_ntoa(temp->data.B_address), temp->data.Bport, 
        temp->data.packetnum_AtoB + temp->data.packetnum_BtoA, temp->data.bytes_AtoB + temp->data.bytes_BtoA,
        temp->data.packetnum_AtoB, temp->data.bytes_AtoB,
        temp->data.packetnum_BtoA, temp->data.bytes_BtoA );
        freetemp=temp;
        free(freetemp);
	}
	printf("----------------------------------------------------------------------------------------------------------------------------------------\n");
    temp = UDPfirst;                             //temp에 udp link list first주소 저장
	printf("UDP Packet\n");
	printf("Address A\t| PortA | Address B\t| PortB | Packets | Bytes | Packets A->B | Bytes A->B | Packet B->A | Bytes B->A |\n");
    for (; temp; temp = temp->link){
		printf("%s | %d | %s | %d | %d | %d | %d | %d | %d | %d | \n",  inet_ntoa(temp->data.A_address), temp->data.Aport, 
        inet_ntoa(temp->data.B_address), temp->data.Bport, 
        temp->data.packetnum_AtoB + temp->data.packetnum_BtoA, temp->data.bytes_AtoB + temp->data.bytes_BtoA,
        temp->data.packetnum_AtoB, temp->data.bytes_AtoB,
        temp->data.packetnum_BtoA, temp->data.bytes_BtoA );
        freetemp=temp;
        free(freetemp);
	}
}