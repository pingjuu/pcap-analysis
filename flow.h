#include <stdint.h>
#include <pcap.h>
#include <string>

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

class flow_Content{
private:
    u_int32_t addressA;
    u_int16_t PortA;
    u_int32_t addressB;
    u_int16_t PortB;
    unsigned int Packet;        //정방향
    bpf_u_int32 bytes;
    unsigned int rPacket;       //역방향
    bpf_u_int32 rbytes;
public:
    flow_Content(){
        Packet = 0;
        bytes = 0;
        rPacket = 0;
        rbytes = 0;
    };
    ~flow_Content(){};
    void flowinsert(u_int32_t _addressA, u_int16_t _PortA, u_int32_t _addressB, u_int16_t _PortB, bpf_u_int32 _bytes);
    void PacketNumPlus(){
        Packet++;
    };
    void AddBytes(flow_Content* sameflow){
        bytes += sameflow->bytes;
    }
    void rPacketNumPlus(){      //역방향
        rPacket++;
    };
    void rAddBytes(flow_Content* sameflow){
        rbytes += sameflow->bytes;
    }
    bool operator<(const flow_Content* flow)const;
    bool operator!=(const flow_Content* flow)const;
    u_int32_t _addressA() {return this->addressA;}
    u_int16_t _PortA(){return this->PortA;}
    u_int32_t _addressB(){return this->addressB;}
    u_int16_t _PortB(){return this->PortB;}
    unsigned int _Packet(){return Packet;}        //정방향
    bpf_u_int32 _bytes(){return bytes;}
    unsigned int _rPacket(){return rPacket;}         //역방향
    bpf_u_int32 _rbytes(){return rbytes;}
};

void flow_Content::flowinsert(u_int32_t _addressA, u_int16_t _PortA, u_int32_t _addressB, u_int16_t _PortB, bpf_u_int32 _bytes){
    addressA=_addressA;
    PortA=_PortA;
    addressB=_addressB;
    PortB=_PortB;
    Packet ++;
    bytes += _bytes;
}

bool flow_Content::operator<(const flow_Content* flow) const{
    if((this->addressA == flow->addressA)&&(this->PortA==flow->PortA)&&(this->addressB==flow->addressB)&&(this->PortB==flow->PortB)){
        return true;
    }
    else return false;
}
bool flow_Content::operator!=(const flow_Content* flow) const{
    if((this->addressA == flow->addressB)&&(this->PortA==flow->PortB)&&(this->addressB==flow->addressA)&&(this->PortB==flow->PortA))
        return true;
    else return false;
}
std::unordered_map<int, flow_Content*> tcpmap;
std::unordered_map<int, flow_Content*> udpmap;

void flow(const u_char* packet, struct pcap_pkthdr* header);
flow_Content* insert(const u_char* packet, struct pcap_pkthdr* header);

void flow(const u_char* packet, struct pcap_pkthdr* header){
    struct ipv4_hdr *ipPacket = (struct ipv4_hdr*)(packet + 14);
    if(ipPacket->ip_p == P_TCP){
        std::cout<<"this packet is tcp \n";
        tcpmap[tcpmap.size()+1]=insert(packet, header);
    }
    else if(ipPacket->ip_p == P_UDP){
        std::cout<<"this packet is udp \n";
        udpmap[udpmap.size()+1]=insert(packet, header);
    }
}
flow_Content* insert(const u_char* packet, struct pcap_pkthdr* header){  //packet을 flow에 삽입
    flow_Content *f = new flow_Content;
    struct ipv4_hdr *ipPacket = (struct ipv4_hdr*)(packet + 14);
    //flow에 받아온 패킷의 ip와 port 삽입
    if(ipPacket->ip_p == P_TCP){
        struct tcp_hdr *Packet = (struct tcp_hdr *)(packet + 14 + (ipPacket->ip_hl<<2));
        f->flowinsert(ipPacket->ip_src, Packet->sport, ipPacket->ip_dst, Packet->dport, header->caplen);
    }
    else{
        struct udp_hdr *Packet = (struct udp_hdr *)(packet + 14 + (ipPacket->ip_hl<<2));
        f->flowinsert(ipPacket->ip_src, Packet->sport, ipPacket->ip_dst, Packet->dport, header->caplen);
    }
    return f;   //flow 반환 
}