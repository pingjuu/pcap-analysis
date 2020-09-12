all: pcap_analysis

pcap_analysis: main.o
	g++ -o pcap_analysis main.o -lpcap

main.o: main.cpp flow.h headers.h
	g++ -c -o main.o main.cpp -lpcap

clean:
	rm -f pcap_analysis *.o