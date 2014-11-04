
#include <stdio.h>
#include <stdlib.h>
#include "sniffer.h"
#include "radiotap-parser.h"
#include "debug.h"

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
            DEBUG_PRINT("Couldn't open device %s: %s\n",dev,errbuf);
            return 0;
    }
    else{
        DEBUG_PRINT("Opened device %s\n",dev);
    }
    
    if(pcap_can_set_rfmon(handle)){     //Проверка на возможность включени monitor мода
        DEBUG_PRINT("Device %s can be opened in monitor mode\n",dev);
    }
    else{
        DEBUG_PRINT("Device %s can't be opened in monitor mode!!!\n",dev);
    }
    
    pcap_set_rfmon(handle,0);   //Включение monitor mode
    if(pcap_set_rfmon(handle,1)!=0){
        DEBUG_PRINT("Device %s couldn't be opened in monitor mode\n", dev);
        return 0;
    }
    else{
        DEBUG_PRINT("Device %s has been opened in monitor mode\n", dev);
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
        DEBUG_PRINT("Error: incorrect header type - %d",header_type);
        return 0;            
    }
    
    return handle;
}

//----------------------------------

int SnifferStart(pcap_t * handle){
    pcap_loop(handle,10000,packet_process,NULL);   
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
    DEBUG_PRINT("Packet %d:\n",capture_packet_counter);
    if(header!=0 && packet!=0){        
        status=get_rssi(packet,header->len,&rssi);        
        switch(status){
            case 0:
                break;
            case -1:
                DEBUG_PRINT("\tNo RSSI\n\n");   //Дропаем пакет, в нем нет RSSI.
                return;
                break;
            case -2:
                DEBUG_PRINT("\tCRC Error\n\n");   //Дропаем пакет, в нем нет RSSI.
                return;
                break;
            default:
                DEBUG_PRINT("\tError %d\n",status);
                return;
                break;
                
        }        
        DEBUG_PRINT("\tlen=%d \n\tcaplen=%d \n\tRSSI=%i\n",header->len,header->caplen,rssi);        
    }
    else{
        if(!header){            
            DEBUG_PRINT("Error: no header\n");            
        }
        if(!packet){            
            DEBUG_PRINT("Error: no packet\n");            
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
    
    status=ieee80211_radiotap_iterator_init(&iterator,header,len);
    if(status){       
        return status;
    }
    
    
    do{
        next_arg_index=ieee80211_radiotap_iterator_next(&iterator);        
        switch(iterator.this_arg_index){        
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                *rssi=*iterator.this_arg;                                                    
                return 0;
                break;           
            case IEEE80211_RADIOTAP_RX_FLAGS:
                if((*iterator.this_arg)!=0){
                    return -2;
                }
                break;
            default:
                break;
        }
        
    }while(next_arg_index>=0);
    
    
    return -1;
}