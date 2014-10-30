/* 
 * File:   main.cpp
 * Author: gorec
 *
 * Created on 14 Октябрь 2014 г., 22:18
 */

#include <stdio.h>
#include <stdlib.h>
#include "sniffer.h"
#include "debug.h"

using namespace std;


/*
 * 
 */
int main(int argc, char** argv) {
    char *dev;
    char *default_dev=(char *)"wlan0";  /*default interface*/   
    pcap_t *handle;
    
    dev=default_dev;    //todo добавтить возожность кастомизации
    
    handle=SnifferInit(dev);
    if(handle==0){
        DEBUG_PRINT("Error, while opening device %s\n",dev);
        return 1;
    }
    DEBUG_PRINT("TEST"); 
    SnifferStart(handle);       
        
    SnifferClose(handle);    
    
    return(0);
}



