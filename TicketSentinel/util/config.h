#include <sys/inotify.h>

// URL Endpoints

#define URL "http://10.2.99.32:5000"
#define REGISTER_URI "/register/"
#define INGEST_URI "/ingest/"
#define PING_URI "/ping/"
#define COMMAND_URI "/commands/output/"
#define WATCHER_URI "/commands/watcher/"

// Agent config

#define SLEEP_TIME 5

// Inotify config

#define MAX_EVENTS 1024 
#define LEN_NAME 1024 
#define EVENT_SIZE  ( sizeof (struct inotify_event)  ) 
#define BUF_LEN     ( MAX_EVENTS * ( EVENT_SIZE + LEN_NAME  ) ) 
#define MAX_FILENAME_CACHE 32



