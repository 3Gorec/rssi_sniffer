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


static void CloseSniffer();

int main(int argc, char** argv) {    
    if(argc!=5){
        DEBUG_PRINTERR("Invalid arguments\n"
                "rssi_aggregator [interface to sniffing][accumulating period][interface to connect][port to connect]\n");
        exit(EXIT_FAILURE);
    }
            
    char *dev=argv[1];  /*default interface*/             
    int interval=atoi(argv[2]);
    ServerInfo serv_info={argv[3],argv[4]}; //todo считать из аргументов
    pthread_t serv_handle;    
    char network_int;    
    
    SetDevice(dev);
    
    if(pthread_create(&serv_handle,NULL,server_thread,(void *)&serv_info)){
        DEBUG_PRINTERR("Error thread\n");
        exit(EXIT_FAILURE);
    }
        
    if(SnifferStart(interval)!=0){
        exit(EXIT_FAILURE);
    }
    atexit(&CloseSniffer);
    SnifferLoop();    
    DEBUG_PRINTERR("Sniffer abort\n");
    
    exit(0);
}

static void CloseSniffer(){
    SnifferStop();
}