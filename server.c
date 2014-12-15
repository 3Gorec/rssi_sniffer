
#include <stdlib.h>
#include "server.h"
#include "sys/types.h"
#include "sys/socket.h"
#include "pthread.h"
#include "debug.h"


void *server_thread(void *vptr_args){ 
    /*
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (socket < 0) {
            DEBUG_PRINT("socket() failed: %d\n", errno);
            return EXIT_FAILURE;
        }
    */
    
    pthread_exit(NULL);
}