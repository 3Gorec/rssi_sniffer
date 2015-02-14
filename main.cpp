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
    int interval=2; //todo считать из аргументов
    char *dev;
    char *default_dev=(char *)"wlan0";  /*default interface*/             
    ServerInfo serv_info={(char *)"lo",(char *)"7987"}; //todo считать из аргументов
    pthread_t serv_handle;    
    char network_int;
    
    dev=default_dev;    //todo считать из аргументов    
    SetDevice(dev);
    
    if(pthread_create(&serv_handle,NULL,server_thread,(void *)&serv_info)){
        DEBUG_PRINTERR("Error thread");
        exit(EXIT_FAILURE);
    }
        
    if(SnifferStart(interval)!=0){
        exit(EXIT_FAILURE);
    }
    atexit(&CloseSniffer);
    SnifferLoop();    
    DEBUG_PRINTERR("Sniffer abort");
    
    exit(0);
}

static void CloseSniffer(){
    SnifferStop();
}