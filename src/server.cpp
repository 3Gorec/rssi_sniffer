
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <errno.h>
#include "server.h"
#include "pthread.h"
#include "sniffer.pb.h"
#include "debug.h"
//#include "byteorder.h"

#define BUF_SIZE    1024

//--------------PROTOTYPES----------

static void ProcessQuery(SnifferQuery *query, SnifferResponse *response);

static int ServerInit(ServerInfo *serv_info);

static void ServiceClient(int client_sock);

static void SendResponse(ResponseType type);

/*!return 0-success; -1-error*/
static int ReceiveData(int socket, void *buf,int len);

/*!Receive message from socket data len, then buffer.
 * return data_size, -1 - error*/
static int32_t ReceiveMsg(int socket, void *buffer, int buffer_size);

/*!return 0-success; -1-error*/
static int SendData(int socket, void *buf,int len);

static int SendMsg(int socket, void *buffer, int buffer_size);
//--------------CODE----------------

void *server_thread(void *vptr_args){         
    int server_sock,client_sock;
    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    
    ServerInfo serv_info=*(ServerInfo *)vptr_args;    
    server_sock=ServerInit(&serv_info);
    addr_size = sizeof their_addr;
    while(1){
        client_sock = accept(server_sock, (struct sockaddr *)&their_addr, &addr_size);
        if(client_sock==-1){
            DEBUG_PRINTERR("accept: %i\n",errno);
            continue;
        }
        ServiceClient(client_sock);
    }
        
    pthread_exit(NULL);
}

//---------------------

int ServerInit(ServerInfo *serv_info){
    int status;
    char host[NI_MAXHOST];  //host IP ascii string
    struct ifaddrs *ifaddr_list, *ifa;       //Address of interface struct
    struct sockaddr *ifa_addr=NULL;    
    struct addrinfo hints;
    struct addrinfo *server_addr=NULL, *server_addr_list, *p;   //Address to open connection struct
    int server_sock;
    
    /*This code support inly IPv4 addresses*/
    
    //get address of interface
    if (status=getifaddrs(&ifaddr_list)) {               
        DEBUG_PRINTERR("getifaddrs error: %i\n", errno);
        exit(EXIT_FAILURE);
    }
    
    //choose property address from list
    for (ifa = ifaddr_list; ifa != NULL; ifa = ifa->ifa_next){
        if(strcmp(ifa->ifa_name,serv_info->interface)==0 && ifa->ifa_addr->sa_family==AF_INET){               
            ifa_addr=ifa->ifa_addr;
            break;
        }
    }       
    
    //get address of interface in ascii and error handling
    if(ifa_addr!=NULL){     
        status=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);        
        if(status!=0){
            DEBUG_PRINTERR("getnameinfo: %s\n",gai_strerror(status));
        }        
    }
    else{
        DEBUG_PRINTERR("Getting ip address error\n");
        exit(EXIT_FAILURE);
    }
    freeifaddrs(ifaddr_list); //we have IP ascii string and need no more this list
    
    //Time to get address struct by host IP for open connection in future
    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_INET;     // only IPv4 
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    if ((status = getaddrinfo(host, serv_info->port, &hints, &server_addr_list)) != 0) {
        DEBUG_PRINTERR("getaddrinfo error: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }
    for(p=server_addr_list;p!=NULL;p=p->ai_next){
        //Create socket
        if ((server_sock = socket(p->ai_family, p->ai_socktype,p->ai_protocol))==-1){
            DEBUG_PRINTERR("Creating socket error\n");            
            continue;
        }
        
        //Bind socket
        int yes=1; 
        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &yes,sizeof(int))==-1){
            DEBUG_PRINTERR("setsockopt: %i\n",errno);
            exit(EXIT_FAILURE);
        }
        if (bind(server_sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(server_sock);
            DEBUG_PRINTERR("bind: %i\n",errno);
            exit(EXIT_FAILURE);
        }

        break;
    } 
    if(p == NULL)  {
        DEBUG_PRINTERR("Failed to bind\n");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(server_addr_list); // all done with this structure
            
    //Listen
    if (listen(server_sock, 5) == -1) {
        DEBUG_PRINTERR("listen: %i\n",errno);
        exit(EXIT_FAILURE);
    }
    DEBUG_PRINT("Listening interface: %s:%s\n",host,serv_info->port);
    return server_sock;
}

//---------------------

void ServiceClient(int client_sock){
    SnifferQuery query;    
    int32_t data_size=0;
    char buffer[BUF_SIZE];    
    SnifferResponse response;
    std::string input_msg_str;    
    input_msg_str.clear();
    
    data_size=ReceiveMsg(client_sock,(void *)buffer,BUF_SIZE);
    if(data_size==-1){    
        return;
    }
    
    input_msg_str.append(buffer, data_size);
    if(!query.ParseFromString(input_msg_str)){
        DEBUG_PRINTERR("Error parsing query\n");        
        return;
    }
    DEBUG_PRINT("Query:\n"
            "\tData size=: %d\n"
            "\tMessage: %s\n",data_size,query.DebugString().data());        
    
    
    
    ProcessQuery(&query,&response);
    data_size=response.ByteSize();
    response.SerializeToArray((void*)buffer,data_size);
    DEBUG_PRINT("response:\n"
            "\tData size=: %d\n"
            "\tMessage: %s\n",data_size,response.DebugString().data());        
    if(SendMsg(client_sock,buffer,data_size)==-1){
        return;
    }
}

//---------------------

void ProcessQuery(SnifferQuery *query, SnifferResponse *response){    
    switch(query->type()){
        case START_SNIFFING:
            response->set_type(QUERY_OK);
            break;
        case STOP_SNIFFING:
            response->set_type(QUERY_OK);
            break;
        case DATA_REQUEST:
            response->set_type(DATA_RESPONSE);
            break;
        default:
            response->set_type(QUERY_ERROR);
            break;
    }    
}

//---------------------

int ReceiveData(int socket, void *buf,int len){
    int recvd=0, total_recvd=0;
    while(total_recvd<len){
        recvd=recv(socket,(void *)((char *)buf+total_recvd),len-total_recvd,0);
        if(recvd==0){
            DEBUG_PRINTERR("Receiving error: connection closed\n");
            return -1;
        }
        if(recvd==-1){
            DEBUG_PRINTERR("Receiving error: %i\n",errno);
            return -1;
        }
        total_recvd+=recvd;
    }
    return 0;
}

//---------------------

int32_t ReceiveMsg(int socket, void *buffer, int buffer_size){
    int32_t data_size=0;
    //Read incoming data size
    if(ReceiveData(socket,(void *)&data_size,sizeof(data_size))==-1){
        close(socket);
        return -1;
    }    
    data_size=ntohl(data_size);
    if(data_size>BUF_SIZE){
        DEBUG_PRINTERR("Error: too big msg\n");        
        return -1;
    }
   
    if(ReceiveData(socket,(void *)buffer,data_size)==-1){
        close(socket);
        return -1;
    }
    
    return data_size;
}

//---------------------

int SendData(int socket, void *buf,int len){
    int sent=0, total_sent=0;
    while(total_sent<len){
        sent=send(socket,(void *)((char*)buf+total_sent),len-total_sent,0);
        if(sent==-1){
            DEBUG_PRINTERR("Sending error: %i\n",errno);
            return -1;
        }
        total_sent+=sent;
    }
}

//---------------------

int SendMsg(int socket, void *buffer, int buffer_size){
    uint32_t size_to_send=htonl((uint32_t)buffer_size);
    if(SendData(socket,(void*)&(size_to_send),sizeof(size_to_send))==-1){
        close(socket);
        return -1;
    }
    if(SendData(socket,buffer,buffer_size)==-1){
        close(socket);
        return -1;
    }
    return 0;
}

//---------------------