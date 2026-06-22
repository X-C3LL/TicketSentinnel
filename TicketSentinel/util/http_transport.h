#pragma once
typedef struct {
    unsigned char *data;
    size_t size;
} response_buffer_t;

void hex_dump(const unsigned char *data, size_t size);
int send_ticket(char *url, char *filename, char* buffer, size_t buffer_len, response_buffer_t *contents);
int upload_data_request(char *url, char* buffer, size_t buffer_len);
int ping(char *url, response_buffer_t *contents);
