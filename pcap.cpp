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

int getMy_IP(char* my_ip);
void printStatistic(listpointer first);
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
    char *my_ip;
    getMy_IP(my_ip);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        printf("packet startinn\n");
        if (res == 0) {
            printf("res = 0\n");
            continue;
        }
        //if (res == -1) {
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("res : %d\n",res);
        
        struct libnet_ethernet_hdr* etherPacket = (struct libnet_ethernet_hdr*)packet;
        if(ntohs(etherPacket->ether_type) != ETHERTYPE_IP)      //ethertype이 IPv4가 아니면 다음패킷ㄱㄱ
        {
            printf("this is not ethernetpacket\n");
            continue;
        }
        printf("this is ethernetpacket\n");
        struct libnet_ipv4_hdr *ipPacket = (struct libnet_ipv4_hdr *)(packet+14);                   //ip부분으로 ㄱㄱ
        if(ipPacket->ip_p==P_TCP){                       //ip protocol이 tcp일 때
            printf("this is tcp packet\n");
            tcp_insert(packet, ipPacket, my_ip, header);
        }
        else if(ipPacket->ip_p==P_UDP){                  //ip protocol이 UDP일 때
            printf("this is udp packet\n");
            udp_insert(packet, ipPacket, my_ip, header);
        }
        else{
            printf("this is nothing\n");
            continue;                                          //ip protocol이 tcp, udp 둘다 아니면 다음패킷 ㄱㄱ
        }
        printf("%u bytes captured\n", header->caplen);
        printf("---------------------------------\n");
    }
    printf("\n\nTCP Packet\n");
    printStatistic(TCPfirst);                         // 패킷 다 읽으면 출력내기
	printf("---------------------------------\n");
    printf("\n\nUDP Packet\n");
    printStatistic(UDPfirst);                         // 패킷 다 읽으면 출력내기
    pcap_close(handle);
}

int getMy_IP(char* my_ip)
{
    int sock;
    struct ifreq ifr;

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
    printf("ip is : %s\n", my_ip);
    return 0;
}
void printStatistic(listpointer first){
    listpointer temp, freetemp;
	temp = first;                              //temp에 tcp link list first주소 저장
    for (; temp; temp = temp->link){
        printf("Address A : %s\n",inet_ntoa(temp->data.A_address));
        printf("PortA : %d\n",ntohs(temp->data.Aport));
        printf("Address B : %s\n",inet_ntoa(temp->data.B_address));
        printf("PortB : %d\n",ntohs(temp->data.Bport));
        printf("Packets : %d\n", temp->data.packetnum_AtoB + temp->data.packetnum_BtoA);
        printf("Bytes : %u\n", temp->data.bytes_AtoB + temp->data.bytes_BtoA);
        printf("Packets A->B : %d\n", temp->data.packetnum_AtoB);
        printf("Bytes A->B : %u\n", temp->data.bytes_AtoB);
        printf("Packets B->A : %d\n", temp->data.packetnum_BtoA);
        printf("Bytes B->A : %u\n\n\n", temp->data.bytes_BtoA);
        freetemp=temp;
        free(freetemp);
	}
}