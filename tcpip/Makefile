CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude
SRC = src/network_sim.c src/ip.c src/tcp.c
OBJ = $(SRC:.c=.o)

all: test/client test/server

src/%.o: src/%.c include/%.h
	$(CC) $(CFLAGS) -c $< -o $@

test/client: test/client.c $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

test/server: test/server.c $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f src/*.o test/client test/server 