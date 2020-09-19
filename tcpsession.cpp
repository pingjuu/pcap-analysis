#include "tcpsession.h"

std::array<int,2> tcpflag = {0,0};
std::map<flowInfo, std::array<int,2>={0,0}> session; 
std::map<flowInfo, std::array<int,4>> session; 

void TCPsession(class flowInfo f){        //패킷의 tcp session 에 필요한 tcp flag 넣기
    if(f._th_flags()==TH_FIN)
        session[f][0]=TH_FIN;
    else if(f._th_flags()==TH_ACK)
        session[f][1]=TH_ACK;
}
//정방향의 session 0, 1과 역방향의 session 0, 1이 th fin, th ack이면 세션이 종료된 flow

bool session_check(class flowInfo flow, class flowInfo reverseflow){
    return (session[flow][0]==TH_FIN)&&(session[flow][1]==TH_ACK)&&
    (session[reverseflow][0]==TH_FIN)&&(session[reverseflow][1]==TH_ACK);
}