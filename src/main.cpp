/* 
 * File:   main.cpp
 * Author: gorec
 *
 * Created on 14 Октябрь 2014 г., 22:18
 */

#include <stdio.h>
#include <stdlib.h>
#include "pthread.h"
#include "sniffer.h"
#include "server.h"
#include "debug.h"

using namespace std;


static void CloseSniffer(void);

int handle=0;


int main(int argc, char** argv) {

	if(argc!=5){
        DEBUG_PRINTERR("Invalid arguments\n"
                "rssi_aggregator [interface to sniffing][accumulating period][interface to connect][port to connect]\n");
        exit(EXIT_FAILURE);
    }
           
    
    char *dev=argv[1];  /*default interface*/             
    int interval=atoi(argv[2]);
    ServerInfo serv_info={argv[3],argv[4]};
    pthread_t serv_handle;    
    char network_int;    

    
    if(pthread_create(&serv_handle,NULL,server_thread,(void *)&serv_info)){	//Create server thread
        DEBUG_PRINTERR("Error thread\n");
        exit(EXIT_FAILURE);
    }
        
    SnifferInit(interval,dev);

    if(conf.init_flag){
    	atexit(&CloseSniffer);
		SnifferLoop();
    }
    else{
    	DEBUG_PRINTERR("Error thread\n");
		exit(EXIT_FAILURE);
    }
    
    exit(0);
}

static void CloseSniffer(void){
	//todo корректно убить поток сервера и закрыть все сокеты
	SnifferClose();
}
