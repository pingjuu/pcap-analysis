#pragma once
#include <unordered_map>
//#include <map>
#include <arpa/inet.h>
#include "flow.h"
#include "tcpsession.h"

void PrintFlow(std::unordered_map<flowInfo, flowContent, MyHashFunction> *map);
std::string ipp(uint32_t address);