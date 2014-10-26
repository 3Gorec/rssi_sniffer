/* 
 * File:   main.cpp
 * Author: gorec
 *
 * Created on 14 Октябрь 2014 г., 22:18
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>


using namespace std;

int capture_packet_counter=0;

void packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


/*
 * 
 */
int main(int argc, char** argv) {
    char *dev;
    char *default_dev="wlan0";  /*default interface*/   
    char errbuf[PCAP_ERRBUF_SIZE*10];    
    int header_type;    
    int status=0;
    pcap_t *handle=0;
        
    dev=default_dev;    //todo добавтить возожность кастомизации
    
    
    handle=pcap_create(dev,errbuf);
    if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(1);
    }
    else{
        printf("Opened device %s\n",dev);
    }
    
    if(pcap_can_set_rfmon(handle)){
        printf("Device %s can be opened in monitor mode\n",dev);
    }
    else{
        printf("Device %s can't be opened in monitor mode!!!\n",dev);
    }
    
    pcap_set_rfmon(handle,0);
    if(pcap_set_rfmon(handle,1)!=0){
        fprintf(stderr, "Device %s couldn't be opened in monitor mode\n", dev);
        return(2);
    }
    else{
        printf("Device %s has been opened in monitor mode\n", dev);
    }
    pcap_set_promisc(handle,0);
    pcap_set_snaplen(handle,BUFSIZ);
    
    status=pcap_activate(handle);               
    if(status==0){   

        header_type=pcap_datalink(handle);
        if(header_type!=DLT_IEEE802_11_RADIO){
            printf("Error: incorrect header type - %d",header_type);
            return(3);            
        }
        
        pcap_loop(handle,10,packet_process,NULL);
        
        
        /* Сlose the session */
        pcap_close(handle);
    }
    else{
        pcap_perror(handle,(char*)"pcap error: ");
    }
    pcap_set_rfmon(handle,0);
    return(0);
}

void packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    ++capture_packet_counter;
    printf("Packet %d:\n",capture_packet_counter);
    if(header!=0 && packet!=0){        
        printf("\t len=%d\n\tcaplen=%d\n",header->len,header->caplen);
    }
    else{
        if(!header){            
            printf("Error: no header\n");            
        }
        if(!packet){            
            printf("Error: no packet\n");            
        }
    }
}

