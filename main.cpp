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




int main(int argc, char** argv) {
    char *dev;
    char *default_dev=(char *)"wlan0";  /*default interface*/             
    ServerInfo serv_info={(char *)"lo",(char *)"7987"};
    pthread_t serv_handle;
    pcap_t *handle=0;
    char network_int;
    
    
    dev=default_dev;    //todo добавтить возожность кастомизации    
    
    /*handle=SnifferInit(dev);    
        if(handle==0){
            DEBUG_PRINT("Error, while opening device %s\n",dev);
            return 1;
        }
     */
    
    //SnifferStart(handle);       
      
    //SnifferClose(handle);    
    
    if(pthread_create(&serv_handle,NULL,server_thread,(void *)&serv_info)){
        DEBUG_PRINT("Error thread");
        exit(1);
    }
    
    
    while(1);
    exit(0);
    //return 0;     
}

