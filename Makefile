CC=gcc
CFLAGS = -Wall -Wextra -pedantic -lpcap
CFLAGS_WERROR = -Wall -Wextra -Werror -pedantic -lpcap
CFLAGS_DEBUG = -DDEBUG -lpcap
CFLAGS_VERBOSE = -Wall -Wextra -pedantic -DVERBOSE -lpcap
CFLAGS_RAW = -lpcap

EXECUTABLE=./ipk-sniffer

default:
	$(CC) ./src/*.c -o $(EXECUTABLE) $(CFLAGS)

debug:
	$(CC) ./src/*.c -o $(EXECUTABLE) $(CFLAGS_DEBUG)

raw:
	$(CC) ./src/*.c -o $(EXECUTABLE) $(CFLAGS_RAW)

clean: