#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif
#include <time.h>
#include <ctype.h>

#include "debug.h"

#define CHUNKSIZE 2048

int winsock_initialized = 0;

#if defined _WIN32 || defined WIN32
int init_winsock2(void)
{
    WORD ver;
    WSADATA wd;
    if (winsock_initialized == 1) {
        return 0;
    }
    ver = MAKEWORD(2, 2);
    winsock_initialized = 1;
    return WSAStartup(ver, &wd) == 0;
}
#endif

char* INITIAL_REQUEST_TEMPLATE
    = "%s %s HTTP/1.1\r\nConnection: Close\r\nUser-Agent: Mozilla/5.0 (Windows "
      "NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/79.0.3945.74 Safari/537.37 Edg/79.0.309.43\r\nPragma: "
      "no-cache\r\nHost: %s\r\nAccept: text/html\r\nAccept-Encoding: "
      "identity\r\n\r\n";

char* REQUEST_TEMPLATE
    = "%s %s HTTP/1.1\r\nConnection: Close\r\nUser-Agent: Mozilla/5.0 (Windows "
      "NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/79.0.3945.74 Safari/537.37 Edg/79.0.309.43\r\nCookie: "
      "sessionid=%s\r\nHost: %s\r\nAccept: text/html\r\nAccept-Encoding: "
      "identity\r\n\r\n";

unsigned char* http_request(int isinitial, char* method, char* hostname,
    uint16_t port, char* cookie, char* path, char* postData, size_t postDataLen)
{
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct sockaddr_in* ipv4 = NULL;
    struct sockaddr_in6* ipv6 = NULL;
    char* data = NULL;
    size_t dataLen = 0;
    char* tempdata = NULL;
    char* outdata = NULL;
#if defined(__linux__)
    struct timeval tv;
#endif

    int status = 0;
    int sock = 0;
    int failcount = 0;
    int err = 0;
    ssize_t read_write_size = 0;
    ssize_t total_read_write_size = 0;

#if defined(_WIN32) || defined(WIN32)
    if (winsock_initialized == 0) {
        (void)init_winsock2();
    }
#endif
    DEBUG_PRINT("Hostname: %s Port: %d Path: %s\n", hostname, port, path);
    memset((char*)&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // AF_UNSPEC to support ipv4 or ipv6
    hints.ai_socktype = SOCK_STREAM;

    status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status != 0) {
        DEBUG_PRINT("Error of some sort, return NULL\n");
        return NULL;
    }
    if (res->ai_family == AF_INET) {
        ipv4 = (struct sockaddr_in*)res->ai_addr;
    } else if (res->ai_family == AF_INET6) {
        ipv6 = (struct sockaddr_in6*)res->ai_addr;
    }
    DEBUG_PRINT("Before socket\n");
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (ipv4 != NULL) {
        ipv4->sin_port = htons(port);
    }
    if (ipv6 != NULL) {
        ipv6->sin6_port = htons(port);
    }
#if defined(__linux__)
    tv.tv_sec = 4;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
#endif

#if defined(_WIN32) || defined(WIN32)
    DWORD timeout = 4 * 1000;
    setsockopt(
        sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);
#endif

    err = connect(sock, res->ai_addr, res->ai_addrlen);
    if (err < 0) {
        goto error;
    }
    DEBUG_PRINT("After connect\n");
    /*Generate the http request*/
    if (isinitial == 1) {
        data = calloc(strlen(INITIAL_REQUEST_TEMPLATE) + strlen(hostname)
                + strlen(path) + 255 + postDataLen,
            1);
        sprintf(data, INITIAL_REQUEST_TEMPLATE, method, path, hostname);
    } else {
        data = calloc(strlen(REQUEST_TEMPLATE) + strlen(hostname) + strlen(path)
                + strlen(cookie) + 255 + postDataLen,
            1);
        sprintf(data, REQUEST_TEMPLATE, method, path, cookie, hostname);
    }
    dataLen = strlen(data);

    DEBUG_PRINT("After sprintf\n");
    DEBUG_PRINT("Request: %s\n", data);
    /*Send the http request*/
    total_read_write_size = 0;
    while (total_read_write_size < dataLen) {
        read_write_size = send(sock, data + total_read_write_size,
            dataLen - total_read_write_size, 0);
        total_read_write_size += read_write_size;
    }
    DEBUG_PRINT("Wrote all data\n");
    /* Read all data, pull down chunks until fail to read anymore,
     * and then return data*/
    total_read_write_size = 0;
    read_write_size = 1;
    outdata = calloc(CHUNKSIZE + 1, 1);
    DEBUG_PRINT("Reading data\n");
    while (read_write_size > 0 && failcount < 2) {
        read_write_size
            = recv(sock, outdata + total_read_write_size, CHUNKSIZE, 0);
        // DEBUG_PRINT("Readin: %d\n", read_write_size);
        if (read_write_size == -1) {
            DEBUG_PRINT("Breaking out because of error\n");
            break;
        }
        total_read_write_size += read_write_size;
        // DEBUG_PRINT("New readwrite size: %d\n", total_read_write_size);
        tempdata = realloc(outdata, total_read_write_size + CHUNKSIZE + 1);

        if (tempdata == NULL) {
            DEBUG_PRINT("Failed to realloc\n");
            free(outdata);
            outdata = NULL;
            goto error;
        }
        outdata = tempdata;
        memset(outdata + total_read_write_size, 0, CHUNKSIZE + 1);
        if (read_write_size == 0) {
            failcount++;
        } else if (read_write_size == -1) {
            failcount = 2;
        } else {
            failcount = 0;
        }
    }
    // printf("Results: %s\n", outdata);
    outdata[total_read_write_size + 1] = 0;
    // DEBUG_PRINT("%s\n", outdata);

cleanup:
    if (data) {
        free(data);
    }
    if (res) {
        freeaddrinfo(res);
    }
    if (sock > 0) {
#if defined(WIN32) || defined(_WIN32)
        closesocket(sock);
#else
        close(sock);
#endif
    }
    return (unsigned char*)outdata;

error:
    goto cleanup;
}

#ifdef HTTP_TESTING
int main(int argc, char* argv[])
{
    unsigned char* outdata = NULL;
    outdata = http_request(
        "GET", argv[1], (uint16_t)atoi(argv[2]), argv[3], NULL, 0);
    return 0;
}
#endif
