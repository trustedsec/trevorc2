CC:=gcc

all: win posix

debug: wind posixd

win:
	x86_64-w64-mingw32-gcc -Wall -I ./include/ -mwindows -DWIN_MAIN src/main.c src/crypto.c src/aes.c src/encode.c src/decode.c src/sha256.c posix_src/http.c -lws2_32 -o ./tc2_agent.exe

wind:
	x86_64-w64-mingw32-gcc -Wall -DDEBUG -I ./include/ src/main.c src/crypto.c src/aes.c src/encode.c src/decode.c src/sha256.c posix_src/http.c -lws2_32 -o ./tc2_agent.exe

posix:
	gcc -Wall -I ./include/ src/main.c src/crypto.c src/aes.c src/encode.c src/decode.c src/sha256.c posix_src/http.c -o ./tc2_agent.out

posixd:
	gcc -Wall -I ./include/ -DDEBUG src/main.c src/crypto.c src/aes.c src/encode.c src/decode.c src/sha256.c posix_src/http.c -o ./tc2_agent.out

scanbuild:
	$(CC) -I ./include/ src/main.c src/crypto.c src/aes.c src/encode.c src/decode.c src/sha256.c posix_src/http.c -o ./tc2_agent.out

clean:
	rm -f tc2_agent.*
