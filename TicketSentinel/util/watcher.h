#define DOMAIN_UID_THRESHOLD 1000000000

int ccache_check_cache(const char *name);
void add_to_ccache(const char *name);
void *inotify_ccache(void *state);
void *inotify_keyring(void *state);
