#include <stdlib.h>
#include "headers.h"
#define MALLOC(p, s)\
if(!((p)=malloc(s)))\
{\
fprintf(stderr,"Insufficient memory");\
exit(1);\
}			//malloc 함수 매크로 함수로 선언
/*
class Conversation {
public:
    in_addr A_address;
    in_addr B_address;
    u_int16_t Aport;
    u_int16_t Bport;
    int bytes_AtoB;
    int packetnum_AtoB;
    int bytes_BtoA;
    int packetnum_BtoA;
};

typedef struct listNode *listpointer;
typedef struct listNode {
	Conversation data;
	listpointer link;
};
*/

typedef struct Conversation {
    in_addr A_address;
    in_addr B_address;
    u_int16_t Aport;
    u_int16_t Bport;
    int bytes_AtoB;
    int packetnum_AtoB;
    int bytes_BtoA;
    int packetnum_BtoA;
};

typedef struct listNode *listpointer;
typedef struct listNode {
	struct Conversation data;
	listpointer link;
};
listpointer TCPfirst = NULL;		//TCP linklist의 처음을 나타내는 first노드
listpointer UDPfirst = NULL;		//UDP linklist의 처음을 나타내는 first노드

void tcp_insert(struct libnet_ipv4_hdr *ipPacket, char *my_ip, const u_char* packet){
	listpointer temp=(listNode*)malloc(sizeof(listNode));	 //추가할 노드의 메모리 할당
	//MALLOC(temp, sizeof(*temp));            //추가할 노드의 메모리 할당

	if(!(TCP_initial(temp, ipPacket, my_ip, packet))){	//겹치는 노드없어 새로 추가
		if (TCPfirst) {             			//first노드가 존재할 때
			temp->link = TCPfirst;
			TCPfirst = temp;
		}
		else {                        //노드가 아무것도 존재하지 않음. =>추가할 노드가 첫노드
			temp->link = NULL;
			TCPfirst = temp;
		}
	}
}

bool TCP_initial(listpointer temp, struct libnet_ipv4_hdr *ipPacket, char *my_ip, const u_char* packet){
	
	struct libnet_tcp_hdr* tcpPacket = (struct libnet_tcp_hdr*)(ipPacket) + (ipPacket->ip_hl <<2);
	if(my_ip==inet_ntoa(ipPacket->ip_src)){	//내 ip주소를 찾아서 A에 때려박기		
		temp->data.A_address=ipPacket->ip_src;
		temp->data.B_address=ipPacket->ip_dst;
		temp->data.Aport=ntohs(tcpPacket->th_sport);
		temp->data.Bport=ntohs(tcpPacket->th_dport);
			//linklist에 존재하는 노드와 비교하는 함수
		listpointer plusnode = toCompare(temp, packet, TCPfirst);
		if(plusnode==NULL)			//list에 겹치는게 없으면 false
			return false;
		else						//list에 이미 존재하면 true
			plusnode->data.bytes_AtoB += sizeof(*packet);
			plusnode->data.packetnum_AtoB++;
			return true;
	}
	else {
		temp->data.A_address=ipPacket->ip_dst;
		temp->data.B_address=ipPacket->ip_src;
		temp->data.Aport=ntohs(tcpPacket->th_dport);
		temp->data.Bport=ntohs(tcpPacket->th_sport);
			//linklist에 존재하는 노드와 비교하는 함수
		listpointer plusnode = toCompare(temp, packet, TCPfirst);
		if(plusnode==NULL)			//list에 겹치는게 없으면 false
			return false;
		else						//list에 이미 존재하면 true
			plusnode->data.bytes_BtoA += sizeof(*packet);
			plusnode->data.packetnum_BtoA++;
			return true;
	}
}

listpointer toCompare(listpointer temp, const u_char* packet, listpointer first){
	//listpointer first = TCPfirst;
	for (; first; first = first->link){
		if((strcmp(inet_ntoa(first->data.A_address), inet_ntoa(temp->data.A_address))==0)
		&&(strcmp(inet_ntoa(first->data.B_address),inet_ntoa(temp->data.B_address))==0)
		&&(first->data.Aport==temp->data.Aport)&&(first->data.Bport==temp->data.Bport)){	
			//list안에 겹치는게 있으면 겹치는 노드값 리턴
			return first;
		}
	}
	//겹치는게 없으면 NULL리턴
	return NULL;
}
void udp_insert(struct libnet_ipv4_hdr* ipPacket, char *my_ip, const u_char* packet){
	listpointer temp=(listNode*)malloc(sizeof(listNode));	 //추가할 노드의 메모리 할당
	//MALLOC(temp, sizeof(*temp));            //추가할 노드의 메모리 할당

	if(!(UDP_initial(temp, ipPacket, my_ip, packet))){	//겹치는 노드없어 새로 추가
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
bool UDP_initial(listpointer temp, struct libnet_ipv4_hdr *ipPacket, char *my_ip, const u_char* packet){
	struct libnet_udp_hdr* udpPacket = (struct libnet_udp_hdr*)(ipPacket) + (ipPacket->ip_hl <<2);
	if(my_ip==inet_ntoa(ipPacket->ip_src)){	//내 ip주소를 찾아서 A에 때려박기		
		temp->data.A_address=ipPacket->ip_src;
		temp->data.B_address=ipPacket->ip_dst;
		temp->data.Aport=ntohs(udpPacket->uh_sport);
		temp->data.Bport=ntohs(udpPacket->uh_dport);
			//linklist에 존재하는 노드와 비교하는 함수
		listpointer plusnode = toCompare(temp, packet, UDPfirst);
		if(plusnode==NULL)			//list에 겹치는게 없으면 false
			return false;
		else						//list에 이미 존재하면 true
			plusnode->data.bytes_AtoB += sizeof(*packet);
			plusnode->data.packetnum_AtoB++;
			return true;
	}
	else {
		temp->data.A_address=ipPacket->ip_dst;
		temp->data.B_address=ipPacket->ip_src;
		temp->data.Aport=ntohs(udpPacket->uh_sport);
		temp->data.Bport=ntohs(udpPacket->uh_dport);
			//linklist에 존재하는 노드와 비교하는 함수
		listpointer plusnode = toCompare(temp, packet, UDPfirst);
		if(plusnode==NULL)			//list에 겹치는게 없으면 false
			return false;
		else						//list에 이미 존재하면 true
			plusnode->data.bytes_BtoA += sizeof(*packet);
			plusnode->data.packetnum_BtoA++;
			return true;
	}
}

/*
void insert( )			//노드를 추가하는 함수
{
	listpointer temp;	//temp는 추가할 노드, x는 추가할 노드의 앞에 있는 노드
	MALLOC(temp, sizeof(*temp));            //추가할 노드의 메모리 할당
	
    printf("추가할 노드의 데이터를 입력하시오. : ");
	scanf_s("%d", &temp->data);

	if (*first) {             			//first노드가 존재할 때
		temp->link = *first;
		(*first) = temp;
	}
	else {                        //노드가 아무것도 존재하지 않음. =>추가할 노드가 첫노드
		temp->link = NULL;
		*first = temp;
	}
	avail++;			//linklist크기 1증가
}

void deleteNode( )      //delete_node는 제거할 노드,delete_node은 x의 앞 노드.
{
	listpointer delete_node, trail;
	
	delete_node = *first;
	*first = (*first)->link;
	
	free(delete_node);          		 //메모리 반납
	avail--;					//linklist크기 -1
}

void printlist()                	  //노드 출력함수
{
	listpointer temp;
	temp = *first;                              //temp에 first주소 저장
	printf("The list contains : ");
	for (; temp; temp = temp->link){
		printf("%4d", temp->data);
	}
	printf("\n");
} 
*/