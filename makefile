CC = gcc
CFLAGS=-g -Wall -Wextra -Werror -lstdc++ -lssl -lcrypto
MODULES=main.o HTTPClient.o CurlHandle.o
all: main

main: $(MODULES)
	$(CC) $(FLAGS) -o $@ $^
