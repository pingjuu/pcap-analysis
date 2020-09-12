#include <iostream>
#include <pcap.h>
#include <unordered_map>
#include <arpa/inet.h>
#include "headers.h"
#include "flow.h"

void usage() {
    printf("syntax: pcap-test <packetfile.pcap>\n");
    printf("sample: pcap-test gilgil.pcap\n");
}

extern std::unordered_map<int, flow_Content*> tcpmap;
extern std::unordered_map<int, flow_Content*> udpmap;

int ToCompare(std::unordered_map<int, flow_Content*> *map);
void Print_Conversation(std::unordered_map<int, flow_Content*> *map);
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
        //if (res == -1) {
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
        flow(packet, header);
    }
    std::cout<<"\n-------\n";
    std::cout<<"compare tcp\n";
    std::cout<<"\n-------\n";
    ToCompare(&tcpmap);
    std::cout<<"\n-------\n";
    std::cout<<"compare udp\n";
    std::cout<<"\n-------\n";
    ToCompare(&udpmap);
    std::cout<<"\n-------\n";
    std::cout<<"print tcp\n";
    std::cout<<"\n-------\n";
    Print_Conversation(&tcpmap);
    std::cout<<"\n-------\n";
    std::cout<<"print udp\n";
    std::cout<<"\n-------\n";
    Print_Conversation(&udpmap);
}

int ToCompare(std::unordered_map<int, flow_Content*> *map) {
    flow_Content *temp;
    int mapsize = (*map).size();

   for(int i=1; i<mapsize+1; i++){
        if((*map)[i]==0) {std::cout<<"i mapout\n"; continue;}
        for(int j=i+1; j <= mapsize+1; j++){
            if((*map)[j]==0) {std::cout<<"j mapout\n"; continue;}
            if((*map)[i]->operator<((*map)[j])){
                (*map)[i]->PacketNumPlus();
                (*map)[i]->AddBytes((*map)[j]);
                temp=(*map)[j];
                (*map).erase(j);
                delete temp;
            }
            else if((*map)[i]->operator!=((*map)[j])){ //역방향 비교  true이면 역방향이다.
                (*map)[i]->rPacketNumPlus();
                (*map)[i]->rAddBytes((*map)[j]);
                temp=(*map)[j];
                (*map).erase(j);
                delete temp;
            }
        }
   }
}

void Print_Conversation(std::unordered_map<int, flow_Content*> *map){
    std::cout<<"\n---------------------------------------------------------------------------------------------------------------------------\n";
    std::cout<<"Address A\tPortA\tAddress B\tPort B\tPacket\tBytes\tPacket A->B\tBytes A->B\tPacket B->A\tBytes B->A\n";
    std::cout<<"---------------------------------------------------------------------------------------------------------------------------\n";
    int mapsize = (*map).size();
    for(int i=1; i<=mapsize; i++){
        if((*map)[i]==0)
            continue;
        std::cout<<ipp((*map)[i]->_addressA())<<"\t"<<htons((*map)[i]->_PortA())<<"\t"<<ipp((*map)[i]->_addressB())<<"\t"<<htons((*map)[i]->_PortB())
        <<"\t"<<(*map)[i]->_Packet()+(*map)[i]->_rPacket()<<"\t"<<(*map)[i]->_bytes()+(*map)[i]->_rbytes()<<"\t\t"<<(*map)[i]->_Packet()
        <<"\t\t"<<(*map)[i]->_bytes()<<"\t\t"<<(*map)[i]->_rPacket()<<"\t"<<(*map)[i]->_rbytes()<<std::endl;
        delete (*map)[i];
    }
}
