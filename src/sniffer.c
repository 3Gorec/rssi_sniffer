
#include <stdio.h>
#include <stdlib.h>
#include "sniffer.h"
#include "radiotap-parser.h"


static void packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

static int get_rssi(const u_char *packet, int len, int8_t *rssi);

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
    pcap_loop(handle,20,packet_process,NULL);   
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
    int status=0;
    int8_t rssi=0;
    ++capture_packet_counter;
    printf("Packet %d:\n",capture_packet_counter);
    if(header!=0 && packet!=0){        
        status=get_rssi(packet,header->len,&rssi);
        if(status!=0){
            if(status==-1){
                printf("\tNo RSSI\n\n");   //Дропаем пакет, он нам не интересен.
                return;
            }
            else{
                printf("Error %d\n",status);
            }
        }
        printf("\tlen=%d \n\tcaplen=%d \n\tRSSI=%i\n",header->len,header->caplen,rssi,status);        
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

/*Возвращает 0 в случае успешного получения RSSI, иначе возвращает код ошибки.
 * -1 RSSI  не найден
 */
static int get_rssi(const u_char *packet, int len, int8_t*rssi){
    int status=0, next_arg_index=0;

    struct ieee80211_radiotap_header *header=(struct ieee80211_radiotap_header *)packet;

    struct ieee80211_radiotap_iterator iterator;
    
    if(ieee80211_radiotap_iterator_init(&iterator,header,len)){
        return status;
    }
    
    status=-1;
    do{
        next_arg_index=ieee80211_radiotap_iterator_next(&iterator);        
        if(iterator.this_arg_index==IEEE80211_RADIOTAP_DBM_ANTSIGNAL){
            *rssi=*iterator.this_arg;                        
            status=0;
            break;           
        }
    }while(next_arg_index>=0);
    
    
    return status;
}