CC=gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic
CFLAGS_WERROR = -std=c99 -Wall -Wextra -Werror -pedantic
CFLAGS_DEBUG = -std=c99 -Wall -Wextra -pedantic -DDEBUG
CFLAGS_VERBOSE = -std=c99 -Wall -Wextra -pedantic -DVERBOSE
CFLAGS_RAW =

EXECUTABLE=./ipk-sniffer

default:
	$(CC) $(CFLAGS) -o $(EXECUTABLE) ./src/*.c

debug:
	$(CC) $(CFLAGS_DEBUG) -o $(EXECUTABLE) ./src/*.c

raw:
	$(CC) $(CFLAGS_RAW) -o $(EXECUTABLE) ./src/*.c

clean: