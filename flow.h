#pragma once
#include <stdint.h>
#include <array>
#include <pcap.h>
#include <string>
#include <unordered_map>
#include <arpa/inet.h>
//#include <map>
#include "headers.h"
#include "tcpsession.h"
#define FLOW_MAP std::unordered_map<flowInfo, flowContent, MyHashFunction>


//extern FLOW_MAP tcpmap;
//extern FLOW_MAP udpmap;

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;



class flowInfo{
private:
    u_int32_t addressA;
    u_int16_t PortA;
    u_int32_t addressB;
    u_int16_t PortB;
    u_int8_t  th_flags;     //for tcp session, if udp => 0
public:
    //bool operator==(const flowInfo flow)const;
    flowInfo();
    void flowinsert(u_int32_t _addressA, u_int16_t _PortA, u_int32_t _addressB, u_int16_t _PortB, u_int8_t  _th_flags);

    flowInfo reverseflow();
    u_int32_t _addressA();
    u_int16_t _PortA();
    u_int16_t _PortA() const;
    u_int32_t _addressB();
    u_int16_t _PortB();
    u_int8_t  _th_flags();
    bool operator<(const flowInfo flow) const;
    bool operator==(const flowInfo flow) const;
};

class MyHashFunction{
public:
    uint operator()(const flowInfo f) const;
};


class flowContent{
private:
    unsigned int Packet;        //정방향
    bpf_u_int32 bytes;
    u_int8_t  th_flags;
public:
    flowContent();
    ~flowContent();
    void flowAdd(bpf_u_int32 bytes);
    unsigned int _Packet();
    bpf_u_int32 _bytes();
};

void flow(const u_char* packet, struct pcap_pkthdr* header);
void map_insert(const u_char* packet, struct pcap_pkthdr* header, FLOW_MAP *map); 
