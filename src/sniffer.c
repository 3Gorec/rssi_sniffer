
#include <stdio.h>
#include <stdlib.h>
#include "sniffer.h"


static void packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

static int capture_packet_counter=0;

//----------------------------------

pcap_t * SnifferInit(char *dev){    
    char errbuf[PCAP_ERRBUF_SIZE*10];    
    int header_type;    
    int status=0;
    pcap_t *handle=0;
    
    handle=pcap_create(dev,errbuf); //Открываем устройство
    if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return 0;
    }
    else{
        printf("Opened device %s\n",dev);
    }
    
    if(pcap_can_set_rfmon(handle)){     //Проверка на возможность включени monitor мода
        printf("Device %s can be opened in monitor mode\n",dev);
    }
    else{
        printf("Device %s can't be opened in monitor mode!!!\n",dev);
    }
    
    pcap_set_rfmon(handle,0);   //Включение monitor mode
    if(pcap_set_rfmon(handle,1)!=0){
        fprintf(stderr, "Device %s couldn't be opened in monitor mode\n", dev);
        return 0;
    }
    else{
        printf("Device %s has been opened in monitor mode\n", dev);
    }
    pcap_set_promisc(handle,0);
    pcap_set_snaplen(handle,BUFSIZ);
    
    status=pcap_activate(handle);   //Активация и проверка статуса
    if(status!=0){
        pcap_perror(handle,(char*)"pcap error: ");
        return 0;
    }
    
    header_type=pcap_datalink(handle);  //Провекрка типа заголовков
    if(header_type!=DLT_IEEE802_11_RADIO){
        printf("Error: incorrect header type - %d",header_type);
        return 0;            
    }
    
    return handle;
}

//----------------------------------

int SnifferStart(pcap_t * handle){
    pcap_loop(handle,10,packet_process,NULL);
    return 0;
}

//----------------------------------

int SnifferStop(pcap_t * handle){
    return 0;
}

//----------------------------------

int SnifferClose(pcap_t * handle){
     /* Сlose the session */      
    pcap_close(handle);
    pcap_set_rfmon(handle,0);
    return 0;
}

//----------------------------------

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