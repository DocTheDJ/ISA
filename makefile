# CC = g++
# CFLAGS=-g -Wall -Wextra -Werror -lcurl
# MODULES=main.o
# all: main

# main: $(MODULES) 
# 	$(CC) $(FLAGS) $@ $^

all: main

main: main.cpp
	g++ -Wall -o main main.cpp -lcrypto -lssl #`xml2-config --cflags` -lxml2
