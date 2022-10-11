CC = g++
CFLAGS=-g -Wall -Wextra -Werror -lcurl
MODULES=main.o
all: main

main: $(MODULES)
	$(CC) $(FLAGS) -o $@ $^
