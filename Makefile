all: pcap_analysis

pcap_analysis: main.o printflow.o flow.o tcpsession.o
	g++ -o pcap_analysis main.o printflow.o tcpsession.o flow.o -lpcap

tcpsession.o: tcpsession.cpp tcpsession.h
	g++ -c -o tcpsession.o tcpsession.cpp -lpcap

main.o: main.cpp printflow.h
	g++ -c -o main.o main.cpp -lpcap

printflow.o: printflow.cpp printflow.h tcpsession.h
	g++ -c -o printflow.o printflow.cpp -lpcap

flow.o: flow.cpp flow.h tcpsession.h
	g++ -c -o flow.o flow.cpp -lpcap

clean:
	rm -f pcap_analysis *.o
