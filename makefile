# CC = g++
# CFLAGS=-g -Wall -Wextra -Werror -lcurl
# MODULES=main.o
# all: main

# main: $(MODULES) 
# 	$(CC) $(FLAGS) $@ $^

all: main

main: main.cpp
	g++ -g -Wall -o main main.cpp -lxml2 -lcrypto -lssl