# GENERAL
SOURCE := $(wildcard ./src/*)
INCLUDE := ./include
BINARY := tc2_client
# POSIX
CC := gcc
POSIX_SOURCE := $(wildcard ./posix_src/*)
# WINDOWS
CC_WINDOWS := x86_64-w64-mingw32-gcc
LDFLAGS_WINDOWS := ws2_32
WINDOWS_SOURCE := $(POSIX_SOURCE)

all: win posix

debug: wind posixd

win:
	$(CC_WINDOWS) -s -Wall -I $(INCLUDE) -mwindows -DWIN_MAIN $(SOURCE) $(WINDOWS_SOURCE) -l$(LDFLAGS_WINDOWS) -o ./$(BINARY).exe

wind:
	$(CC_WINDOWS) -g -Wall -DDEBUG -I $(INCLUDE) $(SOURCE) $(WINDOWS_SOURCE) -l$(LDFLAGS_WINDOWS) -o ./$(BINARY).exe

posix:
	$(CC) -s -Wall -I $(INCLUDE) $(SOURCE) $(POSIX_SOURCE) -o ./$(BINARY).out

posixd:
	$(CC) -Wall -g -I $(INCLUDE) -DDEBUG $(SOURCE) $(POSIX_SOURCE) -o ./$(BINARY).out

scanbuild:
	$(CC) -I $(INCLUDE) $(SOURCE) $(POSIX_SOURCE) -o ./$(BINARY).out

clean:
	rm -f $(BINARY).*

.PHONY: all debug win wind posix posixd scanbuild clean
