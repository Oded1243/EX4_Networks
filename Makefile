all: ping traceroute port_scanning

#---Ping---

ping: ping.o
	gcc ping.o -o ping

ping.o: ping.c
	gcc -c ping.c

#---traceroute---

traceroute: traceroute.o
	gcc $^ -o traceroute

traceroute.o: traceroute.c
	gcc -c traceroute.c

#---port_scanning---

port_scanning: port_scanning.o
	gcc $^ -o port_scanning

port_scanning.o: port_scanning.c
	gcc -c port_scanning.c

clean:
	rm -f *.ping traceroute port_scanning