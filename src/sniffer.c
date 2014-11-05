
#include <stdio.h>
#include <stdlib.h>
#include "sniffer.h"
#include "radiotap-parser.h"
#include "debug.h"


/*!Колбек для обработки пакектов, вытаскивает из них RSSI  и MAC если возможно*/
static void packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/*!Возвращает 0 в случае успешного получения RSSI, иначе возвращает код ошибки.
 * -1 RSSI  не найден
 * rt_header_len - указатель на переменную в которую ф-я вернет длину radiotap хидера
 */
static int get_rssi(const u_char *packet, int len, int8_t *rssi, uint16_t *rt_header_len);

/*!Вытаскивает из пакета mac источника, если возможно
 * packet - указатель на 802_11 frame (БЕЗ radiotap  хидера)
 * len - длина фрейма (БЕЗ учета radiotap хидера)
 * src_mac - указатель на массив, куда функция вернет mac отправителя
 */
static int get_mac(const u_char *packet, int len, uint8_t *src_mac);

static void copy_mac(const u_char *mac_addr, uint8_t *src_mac);

static int capture_packet_counter=0;    //Используется для отладочного вывода номер пакета

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
    pcap_loop(handle,1000,packet_process,NULL);   
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
    uint16_t rt_header_len;
    uint8_t src_mac[6];
    
    ++capture_packet_counter;
    DEBUG_PRINT("Packet %d:\n",capture_packet_counter);
    if(header!=0 && packet!=0){        
        status=get_rssi(packet,header->len,&rssi,&rt_header_len);       //Получение RSSI  
        switch(status){
            case 0:
                break;
            case -1:
                DEBUG_PRINT("\tExtract RSSI error: no RSSI\n\n");   //Дропаем пакет, в нем нет RSSI.
                return;
                break;
            case -2:
                DEBUG_PRINT("\tExtract RSSI error: CRC check failed\n\n");   //Дропаем пакет, в нем нет RSSI.
                return;
                break;
            default:
                DEBUG_PRINT("\tExtract RSSI error: code %d\n",status);
                return;
                break;
                
        }        
        DEBUG_PRINT("\tlen=%d \n\tcaplen=%d \n\tRSSI=%i\n",header->len,header->caplen,rssi);  
        
        status=get_mac(packet+rt_header_len, header->len-rt_header_len,src_mac);
        switch(status){
            case 0:
                break;
            case -2:
                DEBUG_PRINT("\tExtract MAC error: frame doesn't contain source MAC\n",status);
                return;
                break;
            default:
                DEBUG_PRINT("\tExtract MAC error: code %d\n",status);
                return;
                break;    
        }
        DEBUG_PRINT("\tSource MAC = %X:%X:%X:%X:%X:%X\n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
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

//----------------------------------

int get_rssi(const u_char *packet, int len, int8_t*rssi, uint16_t *rt_header_len){
    int status=0, next_arg_index=0;

    struct ieee80211_radiotap_header *header=(struct ieee80211_radiotap_header *)packet;

    struct ieee80211_radiotap_iterator iterator;
    
    status=ieee80211_radiotap_iterator_init(&iterator,header,len);
    if(status){       
        return status;
    }    
    
    *rt_header_len=header->it_len;
    
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

//----------------------------------

int get_mac(const u_char *packet, int len, uint8_t *src_mac){
    uint8_t type=0,subtype=0;    
    char from_ds_flag=0;
    type = ((*(uint16_t *)packet) >> 2) & (0x0003);
    subtype = ((*(uint16_t *)packet) >> 4) & (0x000f);
    from_ds_flag=((*(uint16_t *)packet) >> 6) & (0x0001);
    
    DEBUG_PRINT("\tType=%i\n",type);
    DEBUG_PRINT("\tSubtype=%i\n",subtype);
    
    switch(type){
        case 0x0:   //management frames
            copy_mac(packet+10,src_mac);  //TA MAC offset for management frames = 10
            break;
            
        case 0x1:
            switch(subtype){
                case 0x8:   //BlockAckRequest
                case 0x9:   //BlockAck                    
                case 0xA:   //PS-Poll                    
                case 0xB:   //RTS
                    copy_mac(packet+10,src_mac);  
                    break;
                case 0x7:   //wrapper
                case 0xC:   //CTS                
                case 0xD:   //ACK                    
                case 0xE:   //CF-End                    
                case 0xF:   //CF-End + CF-Ack                    
                default:
                    return -2;  //Не содержит MAC источника
                    break;
            }
            break;
            
        case 0x2:
            if(!from_ds_flag){
                copy_mac(packet+10,src_mac);  
            }
            else{
                return -2;   //Не содержит MAC источника
            }
            break;
        default:
            return -1;
            break;
    }
    
    return 0;
}

//----------------------------------

void copy_mac(const u_char *mac_addr, uint8_t *src_mac){
    int i=0;
    for(i=0;i<6;++i,++mac_addr){
        src_mac[i]=*((uint8_t *)mac_addr);
    }
}