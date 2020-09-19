#include "printflow.h"

void PrintFlow(std::unordered_map<flowInfo, flowContent, MyHashFunction> *map){
//map안에 있는 값들 한개씩 스윽 보면서
// flow 출력 하고 만약 역방향 플로우가 있으면 출력
// 없으면 넘어가기
    std::cout<<"\n---------------------------------------------------------------------------------------------------------------------------\n";
    std::cout<<"Address A\tPortA\tAddress B\tPort B\tPacket\tBytes\tPacket A->B\tBytes A->B\tPacket B->A\tBytes B->A\n";
    std::cout<<"---------------------------------------------------------------------------------------------------------------------------\n";
    FLOW_MAP::iterator iter=map->begin();
    FLOW_MAP::iterator reverse_iter;
    while(map->size()>0){
        flowInfo flow = iter->first;
        flowContent content = iter->second;
        flowInfo reverseflow = flow.reverseflow();      //flow의 역방향 flow
        flowContent reverseContent;
        reverse_iter = map->find(reverseflow);       //map에셔 역방향 찾기
        if(reverse_iter!=map->end()){               //map에 역방향 flow가 있으면 값을 넣어준다.
            reverseflow=reverse_iter->first;
            reverseContent=reverse_iter->second;
            //역방향이 존재하니 tcp session이 종료된 것인지 확인한다.
            if(session_check(flow, reverseflow)){   //session이 종료 되었다면 정, 역 방향 모두 지우고 다른 flow 비교
                iter=map->erase(iter);
                map->erase(reverse_iter); 
                continue;
            }
        }                                                               //없으면 초기화된 0값이 들어감
        
        //역방향 flow가 map안에 없으면 0으로 초기화 되어있으니 0값으로 나옴 함께 출력
        
        std::cout<<ipp(flow._addressA())<<"\t"<<htons(flow._PortA())<<"\t"<<ipp(flow._addressB())<<"\t"<<htons(flow._PortB())
        <<"\t"<<content._Packet()+reverseContent._Packet()<<"\t"<<content._bytes()+reverseContent._bytes()<<"\t\t"<<content._Packet()
        <<"\t\t"<<content._bytes()<<"\t\t"<<reverseContent._Packet()<<"\t"<<reverseContent._bytes()<<std::endl;
        iter=map->erase(iter);
        if(reverse_iter!=map->end()){
            map->erase(reverse_iter); 
        }
    }

}
std::string ipp(uint32_t address){
    char buf[32]; // enough size
	sprintf(buf, "%u.%u.%u.%u",
		(address & 0x000000FF),
        (address & 0x0000FF00) >> 8,
        (address & 0x00FF0000) >> 16,
        (address & 0xFF000000) >> 24);
	return std::string(buf);
}