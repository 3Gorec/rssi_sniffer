//----------------INCLUDES----------------------


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sniffer.h"
#include "radiotap-parser.h"
#include "debug.h"



//----------------DEFINES-----------------------

#define MAX_RSSI_RECORDS_PER_INTERVAL   1000   
#define MAX_CAPTURE_PERIOD              10
#define MIN_CAPTURE_PERIOD              1

//----------------TYPES-------------------------


typedef struct{    
    uint8_t mac[6];
    int8_t rssi;
}sCapturedRSSI;

/*!Структура предназначена для хранения данных собранных за интервал времени
 * с последующей передачей их по сети*/
typedef struct{
   char valid;  //флаг валидность 0 - невалидно !0 - валидно
   struct timeval ts;   //временная метка
   int records_count;     
   sCapturedRSSI rssi_data[MAX_RSSI_RECORDS_PER_INTERVAL];  
}sCapturedDataSet;  //todo возможно стоит добавить выравнивание


//----------------GLOBAL VARS-------------------

static int capture_inerval_s=1;

static int capture_packet_counter=0;    //Используется для отладочного вывода номер пакета

static struct timeval cur_ts={0,0};

static sCapturedDataSet data_set_0={.valid=0,.ts={0,0},.records_count=0};
static sCapturedDataSet data_set_1={.valid=0,.ts={0,0},.records_count=0};;
static sCapturedDataSet *ready_ds=0;
static sCapturedDataSet *process_ds=&data_set_0;

static pcap_t * handle=0;
char device[255]="";

//----------------PROTOTYPES--------------------

/*!Устанавливает период наакопления данных
 * capture_period - длина периода в секундах*/
static int SetPeriod(int capture_period);

/*!Открытие устройства, проверка возможности включения в monitor mode*/
static pcap_t* SnifferInit();

/*!Колбек для обработки пакектов, вытаскивает из них RSSI  и MAC если возможно*/
static void PacketProcess(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/*!Возвращает 0 в случае успешного получения RSSI, иначе возвращает код ошибки.
 * -1 RSSI  не найден
 * rt_header_len - указатель на переменную в которую ф-я вернет длину radiotap хидера
 */
static int GetRSSI(const u_char *packet, int len, int8_t *rssi, uint16_t *rt_header_len);

/*!Вытаскивает из пакета mac источника, если возможно
 * packet - указатель на 802_11 frame (БЕЗ radiotap  хидера)
 * len - длина фрейма (БЕЗ учета radiotap хидера)
 * src_mac - указатель на массив, куда функция вернет mac отправителя
 */
static int GetMAC(const u_char *packet, int len, uint8_t *src_mac);

/*!Копирует MAC адрес, из пакета в память*/
static void CopyMAC(const u_char *mac_addr_p, uint8_t *src_mac);

/*!Выводит RSSI и MAC в консоль*/
static void PrintCapturedData(sCapturedRSSI *rssi_data);

/*!Добавляет заснифаные данные к массиву сохраненных данных. Манипулирует массивами при необходимости*/
static void AddToDataSet(sCapturedRSSI *rssi_data, struct timeval ts);



//----------------CODE--------------------------

void SetDevice(char *dev){    
    strcpy(device,dev);
    DEBUG_PRINT("Device %s has been setted\n",device);
}

//----------------------------------

static int SetPeriod(int capture_period){
    if(capture_period<MIN_CAPTURE_PERIOD || capture_period>MAX_CAPTURE_PERIOD){
        return -1;
    }
    capture_inerval_s=capture_period;
    return 0;
}

//----------------------------------

static pcap_t* SnifferInit(){    
    char errbuf[PCAP_ERRBUF_SIZE*10];            
    handle=0;    
    if(device[0]==0){
        DEBUG_PRINTERR("Error: device didn't setted\n");
        return 0;
    }
    
    handle=pcap_create(device,errbuf); //Открываем устройство
    if (handle == NULL) {
        DEBUG_PRINTERR("Couldn't open device %s: %s\n",device,errbuf);
        return 0;
    }
    else{
        DEBUG_PRINT("Opened device %s\n",device);
    }
    
    if(pcap_can_set_rfmon(handle)){     //Проверка на возможность включени monitor мода
        DEBUG_PRINT("Device %s can be opened in monitor mode\n",device);
    }
    else{
        DEBUG_PRINTERR("Device %s can't be opened in monitor mode\n",device);
    }
    
    return handle;
}

//----------------------------------

int SnifferStart(int capture_period){
    int header_type;    
    int status=0;    
    
    if(SetPeriod(capture_period)!=0){
        DEBUG_PRINTERR("Error, wrong accumulation period\n");
        return -1;
    }
    
    handle=SnifferInit();    
    if(handle==0){
        DEBUG_PRINTERR("Error, while opening device %s\n",device);
        exit(EXIT_FAILURE);
    }
    
    pcap_set_rfmon(handle,0);   //Выключение monitor mode, если он был включен
    if(pcap_set_rfmon(handle,1)!=0){
        DEBUG_PRINTERR("Error opening in monitor mode\n");
        return -1;
    }
    else{
        DEBUG_PRINT("Device has been opened in monitor mode\n");
    }
    pcap_set_promisc(handle,0);
    pcap_set_snaplen(handle,BUFSIZ);
    
    status=pcap_activate(handle);   //Активация и проверка статуса
    if(status!=0){
        pcap_perror(handle,(char*)"pcap error: ");
        return -1;
    }
    
    header_type=pcap_datalink(handle);  //Провекрка типа заголовков
    if(header_type!=DLT_IEEE802_11_RADIO){
        DEBUG_PRINTERR("Error: incorrect header type - %d",header_type);
        return -1;       
    }
    
    pcap_loop(handle,10,PacketProcess,NULL);  //todo переделать  
    return 0;
}

//----------------------------------

int SnifferStop(){
    if(handle==0){
        DEBUG_PRINTERR("Error: device didn't opened");
        return -1;       
    }
    pcap_set_rfmon(handle,0);
    /* Сlose the session */      
    pcap_close(handle);
    capture_packet_counter=0;
    handle=0;
    return 0;
}

//----------------------------------

void PacketProcess(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    int status=0;    
    uint16_t rt_header_len;    
    sCapturedRSSI rssi_data;
    
    ++capture_packet_counter;
    DEBUG_PRINT("Packet %d:\n",capture_packet_counter);
    if(header!=0 && packet!=0){        
        status=GetRSSI(packet,header->len,&rssi_data.rssi,&rt_header_len);       //Получение RSSI  
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
        
        status=GetMAC(packet+rt_header_len, header->len-rt_header_len,rssi_data.mac);
        switch(status){
            case 0:
                break;
            case -2:
                DEBUG_PRINT("\tExtract MAC error: frame doesn't contain source MAC\n");
                return;
                break;
            default:
                DEBUG_PRINT("\tExtract MAC error: code %d\n",status);
                return;
                break;    
        }
        PrintCapturedData(&rssi_data);
        
        AddToDataSet(&rssi_data,header->ts);
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

int GetRSSI(const u_char *packet, int len, int8_t*rssi, uint16_t *rt_header_len){
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

int GetMAC(const u_char *packet, int len, uint8_t *src_mac){
    uint8_t type=0,subtype=0;    
    char from_ds_flag=0;
    type = ((*(uint16_t *)packet) >> 2) & (0x0003);
    subtype = ((*(uint16_t *)packet) >> 4) & (0x000f);
    from_ds_flag=((*(uint16_t *)packet) >> 6) & (0x0001);
    
    DEBUG_PRINT("\tType=0x%x\n",type);
    DEBUG_PRINT("\tSubtype=0x%x\n",subtype);
    
    switch(type){
        case 0x0:   //management frames
            CopyMAC(packet+10,src_mac);  //TA MAC offset for management frames = 10
            break;
            
        case 0x1:
            switch(subtype){
                case 0x8:   //BlockAckRequest
                case 0x9:   //BlockAck                    
                case 0xA:   //PS-Poll                    
                case 0xB:   //RTS
                    CopyMAC(packet+10,src_mac);  
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
                CopyMAC(packet+10,src_mac);  
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

void CopyMAC(const u_char *mac_addr_p, uint8_t *src_mac){
    int i=0;
    for(i=0;i<6;++i,++mac_addr_p){
        src_mac[i]=*((uint8_t *)mac_addr_p);
    }
}

//----------------------------------

void PrintCapturedData(sCapturedRSSI *rssi_data){
    uint8_t *mac=rssi_data->mac;
    DEBUG_PRINT("\tRSSI = %i\n",rssi_data->rssi);
    DEBUG_PRINT("\tSource MAC = %X:%X:%X:%X:%X:%X\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

//----------------------------------

void AddToDataSet(sCapturedRSSI *rssi_data, struct timeval ts){
    if(cur_ts.tv_sec==0){   //В случае если данная запись - первая с запуска программы
        cur_ts=ts;
        process_ds->ts=ts;
    }
        
    if(ts.tv_sec-cur_ts.tv_sec>=capture_inerval_s){   //Начало нового секундного интервала
        cur_ts=ts;
        process_ds->valid=1;
        ready_ds=process_ds;
        if(process_ds==&data_set_0){   
            process_ds=&data_set_1;
        }
        else{
            process_ds=&data_set_0;
        }
        process_ds->valid=0;
        process_ds->ts=ts;
        process_ds->records_count=0;
    }
    if(process_ds->records_count<MAX_RSSI_RECORDS_PER_INTERVAL){    //сохранение данных за текущий интервал
        process_ds->rssi_data[process_ds->records_count]=*rssi_data;
        ++process_ds->records_count;
    }
}

//----------------------------------