all: trace

trace: main.o ethernet.o arp.o ip.o
	g++ main.o ethernet.o arp.o ip.o -Wall -Werror -o trace -lpcap

main.o: main.cpp ethernet.h arp.h
	g++ -c main.cpp

ethernet.o: ethernet.cpp ethernet.h
	g++ -c ethernet.cpp

arp.o: arp.cpp arp.h
	g++ -c arp.cpp

ip.o: ip.cpp ip.h
	g++ -c ip.cpp

clean:
	rm -f *.o trace *~ #*
