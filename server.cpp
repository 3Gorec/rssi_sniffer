
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include "server.h"
#include "pthread.h"

#include "debug.h"


void *server_thread(void *vptr_args){ 
    int server_sock, client_sock;
    socklen_t clilen;
    char data=77;   
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr, cli_addr;    
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_addr.s_addr=INADDR_ANY;
    serv_addr.sin_port = htons(7987);    
    if (socket < 0) {
        DEBUG_PRINT("Socet creating failed: %d\n",errno);
        return 0;
    } 
    
    if(bind(server_sock,(struct sockaddr *)&serv_addr,sizeof(serv_addr))!=0){
        DEBUG_PRINT("Binding failed: %d\n",errno);
        return 0;
    }
    listen(server_sock,5);
    clilen = sizeof(cli_addr);
    client_sock = accept(server_sock, (struct sockaddr *) &cli_addr, &clilen);
    write(client_sock,&data,1);    
    pthread_exit(NULL);
}
