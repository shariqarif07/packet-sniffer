CC=gcc
LIBS=-lpcap
SRC = sniffer.c
BIN = sniffer

# Normal build
CFLAGS=-Wall -O2 -pthread

# Debug / sanitizer common flags
#DBGFLAGS = -g -O0 -Wall -pthread -fno-omit-frame-pointer

# Optional Sanitizers options
#ASAN_FLAGS = -fsanitize=address
#LSAN_FLAGS = -fsanitize=leak
#UBSAN_FLAGS = -fsanitize=undefined

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LIBS)

#asan:
#	$(CC) $(DBGFLAGS) $(ASAN_FLAGS) $(SRC) -o $(BIN)_asan $(LIBS)

#lsan:
#	$(CC) $(DBGFLAGS) $(LSAN_FLAGS) $(SRC) -o $(BIN)_lsan $(LIBS)

#ubsan:
#	$(CC) $(DBGFLAGS) $(UBSAN_FLAGS) $(SRC) -o $(BIN)_ubsan $(LIBS)

#clean:
#	rm -f $(BIN) #$(BIN)_asan $(BIN)_lsan $(BIN)_ubsan

clean:
	rm -f $(BIN)


