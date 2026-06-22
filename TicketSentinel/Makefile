CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iutil
LDFLAGS = -lcurl -lkrb5 -luuid -ldl
SRC = main.c util/commands.c util/http_transport.c util/tickets.c util/file_util.c util/watcher.c util/kerb.c
OBJ = $(SRC:.c=.o)

TicketSentinel: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJ) TicketSentinel
