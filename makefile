LDLIBS=-lpcap
LDLIBS+=-lpthread

all: arp-spoof

arp-spoof: main.o arphdr.o ethhdr.o iphdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
