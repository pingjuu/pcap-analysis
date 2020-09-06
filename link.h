#include <stdlib.h>

#pragma
typedef struct Conversation {
    in_addr A_address;
    in_addr B_address;
    u_int16_t Aport;
    u_int16_t Bport;
    bpf_u_int32 bytes_AtoB=0;
    uint packetnum_AtoB=0;
    bpf_u_int32 bytes_BtoA=0;
    uint packetnum_BtoA=0;
};

typedef struct listNode *listpointer;
typedef struct listNode {
	struct Conversation data;
	listpointer link;
};
listpointer TCPfirst = NULL;		//TCP linklist의 처음을 나타내는 first노드
listpointer UDPfirst = NULL;		//UDP linklist의 처음을 나타내는 first노드
void tcp_insert(const u_char* packet, struct libnet_ipv4_hdr *ipPacket, char *my_ip, struct pcap_pkthdr* header);
bool TCP_initial(const u_char* packet, listpointer temp, struct libnet_ipv4_hdr *ipPacket, char *my_ip, struct pcap_pkthdr* header);
listpointer toCompare(listpointer temp, listpointer first);
void udp_insert(const u_char* packet, struct libnet_ipv4_hdr* ipPacket, char *my_ip, struct pcap_pkthdr* header);
bool UDP_initial(const u_char* packet, listpointer temp, struct libnet_ipv4_hdr *ipPacket, char *my_ip, struct pcap_pkthdr* header);
void tcp_insert(const u_char* packet, struct libnet_ipv4_hdr *ipPacket, char *my_ip, struct pcap_pkthdr* header){
	listpointer temp=(listNode*)malloc(sizeof(listNode));	 //추가할 노드의 메모리 할당
	if(!(TCP_initial(packet, temp, ipPacket, my_ip, header))){	//겹치는 노드없어 새로 추가
		if(TCPfirst){             			//first노드가 존재할 때
			temp->link = TCPfirst;
			TCPfirst = temp;
		}
		else{                        //노드가 아무것도 존재하지 않음. =>추가할 노드가 첫노드
			temp->link = NULL;
			TCPfirst = temp;
		}
	}
}

bool TCP_initial(const u_char* packet, listpointer temp, struct libnet_ipv4_hdr *ipPacket, char *my_ip, struct pcap_pkthdr* header){
	struct libnet_tcp_hdr* tcpPacket = (struct libnet_tcp_hdr*)(packet + 14 + (ipPacket->ip_hl<<2));
	if(strcmp(my_ip, inet_ntoa(ipPacket->ip_src))==0){	//내 ip주소를 찾아서 A에 때려박기		
		temp->data.A_address=ipPacket->ip_src;
		temp->data.B_address=ipPacket->ip_dst;
		temp->data.Aport=tcpPacket->th_sport;
		temp->data.Bport=tcpPacket->th_dport;
			//linklist에 존재하는 노드와 비교하는 함수
		listpointer plusnode = toCompare(temp, TCPfirst);
		if(plusnode==NULL){			//list에 겹치는게 없으면 false
			temp->data.bytes_AtoB += header->caplen;
			temp->data.packetnum_AtoB++;
			return false;
		}
		else {						//list에 이미 존재하면 true
			plusnode->data.bytes_AtoB += header->caplen;
			plusnode->data.packetnum_AtoB++;
			free(temp);			//1
			return true;
		}
	}
	else {
		temp->data.A_address=ipPacket->ip_dst;
		temp->data.B_address=ipPacket->ip_src;
		temp->data.Aport=tcpPacket->th_dport;
		temp->data.Bport=tcpPacket->th_sport;
			//linklist에 존재하는 노드와 비교하는 함수
		listpointer plusnode = toCompare(temp, TCPfirst);
		if(plusnode==NULL){			//list에 겹치는게 없으면 false
			temp->data.bytes_BtoA += header->caplen;
			temp->data.packetnum_BtoA++;
			return false;
		}
		else {						//list에 이미 존재하면 true
			plusnode->data.bytes_BtoA += header->caplen;
			plusnode->data.packetnum_BtoA++;
			free(temp);			//1
			return true;
		}
	}

}

listpointer toCompare(listpointer temp, listpointer first){
	listpointer comparefirst = first;
	for (; comparefirst; comparefirst = comparefirst->link){
		if((strcmp(inet_ntoa(comparefirst->data.A_address), inet_ntoa(temp->data.A_address))==0)
		&&(strcmp(inet_ntoa(comparefirst->data.B_address),inet_ntoa(temp->data.B_address))==0)
		&&(comparefirst->data.Aport==temp->data.Aport)&&(comparefirst->data.Bport==temp->data.Bport)){	
			//list안에 겹치는게 있으면 겹치는 노드값 리턴
			return first;
		}
	}
	//겹치는게 없으면 NULL리턴
	return NULL;
}
void udp_insert(const u_char* packet, struct libnet_ipv4_hdr* ipPacket, char *my_ip, struct pcap_pkthdr* header){
	listpointer temp=(listNode*)malloc(sizeof(listNode));	 //추가할 노드의 메모리 할당
	//MALLOC(temp, sizeof(*temp));            //추가할 노드의 메모리 할당
	if(!(UDP_initial(packet, temp, ipPacket, my_ip, header))){	//겹치는 노드없어 새로 추가
		if (UDPfirst) {             			//first노드가 존재할 때
			temp->link = UDPfirst;
			(UDPfirst) = temp;
		}
		else {                        //노드가 아무것도 존재하지 않음. =>추가할 노드가 첫노드
			temp->link = NULL;
			UDPfirst = temp;
		}
	}
}
bool UDP_initial(const u_char* packet, listpointer temp, struct libnet_ipv4_hdr *ipPacket, char *my_ip, struct pcap_pkthdr* header){
	struct libnet_udp_hdr* udpPacket = (struct libnet_udp_hdr*)(packet + 14 + (ipPacket->ip_hl<<2));
	if(strcmp(my_ip, inet_ntoa(ipPacket->ip_src))==0){	//내 ip주소를 찾아서 A에 때려박기		
		temp->data.A_address=ipPacket->ip_src;
		temp->data.B_address=ipPacket->ip_dst;
		temp->data.Aport=udpPacket->uh_sport;
		temp->data.Bport=udpPacket->uh_dport;
			//linklist에 존재하는 노드와 비교하는 함수
		listpointer plusnode = toCompare(temp, UDPfirst);
		if(plusnode==NULL){			//list에 겹치는게 없으면 false
			temp->data.bytes_AtoB += header->caplen;
			temp->data.packetnum_AtoB++;
			return false;
		}
		else {						//list에 이미 존재하면 true
			plusnode->data.bytes_AtoB += header->caplen;
			plusnode->data.packetnum_AtoB++;
			free(temp);
			return true;
		}
	}
	else {
		temp->data.A_address=ipPacket->ip_dst;
		temp->data.B_address=ipPacket->ip_src;
		temp->data.Aport=udpPacket->uh_dport;
		temp->data.Bport=udpPacket->uh_sport;
		listpointer plusnode = toCompare(temp, UDPfirst);
		if(plusnode==NULL) {			//list에 겹치는게 없으면 false
			temp->data.bytes_BtoA += header->caplen;
			temp->data.packetnum_BtoA++;
			return false;
		}
		else {						//list에 이미 존재하면 true
			plusnode->data.bytes_BtoA += header->caplen;
			plusnode->data.packetnum_BtoA++;
			free(temp);
			return true;
		}
	}
}