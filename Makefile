# Compiler variables
CCFLAGS = -ansi -Wall -g -std=c++11

all: main

# Rule to link object code files to create executable file
main: main.o WireExtr.o 
	g++ $(CCFLAGS) -o main main.o WireExtr.o -lpcap

main.o:
	g++ $(CCFLAGS) -c main.cpp -lpcap

WireExtr.o: WireExtr.h
	g++ $(CCFLAGS) -c WireExtr.cpp -lpcap

# Pseudo-target to remove object code and executale files
clean:
	-rm *.o main