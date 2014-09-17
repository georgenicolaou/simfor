CFLAGS = -ggdb -Wall

all : SIMFor

remake: clean all

SIMFor : simfor.o serial_com.o sim_wrap.o node.o xml_generator.o
	gcc $(CFLAGS) -o SIMFor simfor.o serial_com.o sim_wrap.o node.o xml_generator.o

xml_generator.o : xml_generator.c
	gcc $(CFLAGS) -c xml_generator.c
	
node.o : node.c
	gcc $(CFLAGS) -c node.c
	
serial_com.o : serial_com.c
	gcc $(CFLAGS) -c serial_com.c

simfor.o : simfor.c
	gcc $(CFLAGS) -c simfor.c

sim_wrap.o : sim_wrap.c
	gcc $(CFLAGS) -c sim_wrap.c
	
clean :
	rm -rf SIMFor *.o *~
