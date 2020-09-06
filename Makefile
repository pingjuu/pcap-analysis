all: pcap_analysis

pcap_analysis: pcap_analysis.o
	g++ -o pcap_analysis pcap_analysis.o -lpcap

pcap_analysis.o: pcap.cpp link.h headers.h
	g++ -c -o pcap_analysis.o pcap.cpp -lpcap
