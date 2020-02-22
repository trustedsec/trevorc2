#ifndef HTTP_H_
#define HTTP_H_

unsigned char* http_request(int isinitial, char* method, char* hostname, uint16_t port, char* cookie, char* path, char* postData, size_t postDataLen);
#endif
