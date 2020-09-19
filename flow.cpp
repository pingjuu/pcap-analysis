#include "flow.h"
//#define FLOW_MAP std::map<flowInfo, flowContent>

FLOW_MAP tcpmap;
FLOW_MAP udpmap;

flowInfo::flowInfo(){
    this->th_flags = 0;
}
void flowInfo::flowinsert(u_int32_t _addressA, u_int16_t _PortA, u_int32_t _addressB, u_int16_t _PortB, u_int8_t  _th_flags){
    this->addressA=_addressA;
    this->PortA=_PortA;
    this->addressB=_addressB;
    this->PortB=_PortB;
    this->th_flags = _th_flags;
}
flowInfo flowInfo::reverseflow(){
    flowInfo reverse;
    reverse.addressA = this->addressB;
    reverse.PortA = this->PortB;
    reverse.addressB = this->addressA;
    reverse.PortB = this-> PortA;
    return reverse;
        //if unordered map안에 역방향 플로우가 있으면 만들어서 맨뒤에 달아준다.
}
u_int32_t flowInfo::_addressA(){return addressA;}
u_int16_t flowInfo::_PortA(){return PortA;}
u_int32_t flowInfo::_addressB(){return addressB;}
u_int16_t flowInfo::_PortB(){return PortB;}
bool flowInfo::operator<(const flowInfo flow) const{
    if(this->addressA != flow.addressA) return this->addressA < flow.addressA;
    if(this->PortA != flow.PortA) return this->PortA < flow.PortA;
    if(this->addressB != flow.addressB) return this->addressB < flow.addressB;
    return this->PortB < flow.PortB;
}
flowContent::flowContent(){
    this->Packet = 0;
    this->bytes = 0;
};
flowContent::~flowContent(){};
void flowContent::flowAdd(bpf_u_int32 bytes){
    this->Packet++;
    this-> bytes += bytes;
};
unsigned int flowContent::_Packet(){return Packet;} 
bpf_u_int32 flowContent::_bytes(){return bytes;}

void flow(const u_char* packet, struct pcap_pkthdr* header){
    struct ipv4_hdr *ipPacket = (struct ipv4_hdr*)(packet + 14);
    if(ipPacket->ip_p == P_TCP){
        std::cout<<"this packet is tcp \n";
        struct tcp_hdr *Packet = (struct tcp_hdr* )(packet + 14 + (ipPacket->ip_hl<<2));
        //struct tcp_hdr *tcpPacket = (struct tcp_hdr* )(ipPacket + (ipPacket->ip_hl<<2));
        //받아온 packet이 flow와 같으면 삽입
        map_insert(packet, header, &tcpmap);
    }
    else if(ipPacket->ip_p == P_UDP){
        std::cout<<"this packet is udp \n";
        struct udp_hdr *Packet = (struct udp_hdr* )(packet + 14 + (ipPacket->ip_hl<<2));
        map_insert(packet, header, &udpmap);
    }
}

void map_insert(const u_char* packet, struct pcap_pkthdr* header, FLOW_MAP *map){  //packet을 flow에 삽입
    struct ipv4_hdr *ipPacket = (struct ipv4_hdr*)(packet + 14);
    //flow에 받아온 패킷의 ip와 port 삽입
    flowInfo f;
    if(ipPacket->ip_p == P_TCP){
        struct tcp_hdr *Packet = (struct tcp_hdr *)(packet + 14 + (ipPacket->ip_hl<<2));
        //struct tcp_hdr *Packet = (struct tcp_hdr *)(ipPacket + (ipPacket->ip_hl<<2));
        f.flowinsert(ipPacket->ip_src, Packet->sport, ipPacket->ip_dst, Packet->dport, Packet->th_flags);

    }
    else{
        struct udp_hdr *Packet = (struct udp_hdr *)(packet + 14 + (ipPacket->ip_hl<<2));
        //struct udp_hdr *Packet = (struct udp_hdr *)(ipPacket + (ipPacket->ip_hl<<2));
        f.flowinsert(ipPacket->ip_src, Packet->sport, ipPacket->ip_dst, Packet->dport, 0);
    }   
    FLOW_MAP::iterator iter = map->find(f);     //map에 flow가 있는지 없는지 확인
    //flow안에 th_flag확인하기
    if(iter==map->end()){     //tcpmap 안에 같은 플로우가 존재하지 않으면 
        flowContent content;    //새로 value 값을 만들어서 map에 넣기
        map->insert(std::pair<flowInfo, flowContent>(f, content));
        iter=map->find(f);
    }
    //tcp 안에 같은 플로우가 존재하면, iter의 flow 더하기
    //존재 안했으면 위에서 만든 값 더하기
    iter->second.flowAdd(header->caplen);
    TCPsession(f);      
}