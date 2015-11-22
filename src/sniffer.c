//----------------INCLUDES----------------------


#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <semaphore.h>
#include <errno.h>
#include <err.h>
#include <pthread.h>
#include <sys/socket.h>

#include "sniffer.h"

#include "../inc/capture.h"
#include "debug.h"
#include "radiotap.h"



//----------------DEFINES-----------------------

#define MAX_CAPTURE_PERIOD              10
#define MIN_CAPTURE_PERIOD              1

//----------------TYPES-------------------------

/*!Структура содержит кольцевой буффер и предназначена для хранения данных
 * с последующей передачей их по сети*/
typedef struct{
   int cur_index;
   int records_count;
   sCapturedRSSI rssi_data[RSSI_BUFFER_SIZE];
   uint16_t id_array[RSSI_BUFFER_SIZE];
}sCapturedDataCircular;

//----------------GLOBAL VARS-------------------

/*
 * size: max 80211 frame (2312) + space for prism2(not supported by my sniffer) header (144)
 * or radiotap header (usually only 26) + some extra */
static unsigned char buffer[2312 + 200];

static unsigned int capture_packet_counter=0;    //Используется для отладочного вывода номер пакета

static sCapturedDataCircular captured_data={.cur_index=0, .records_count=0};


static pthread_mutex_t data_mutex;
static char mutex_init=0;

/* for select */
static fd_set read_fds;
static struct timeval tv;	//todo убрать?

#define ID_LIMIT 65000
static uint16_t global_id=1;	//zero - reserved id to indicate first request in series

tSnifferConfig conf;


//----------------PROTOTYPES--------------------

/*!Установка интерфейса для сниффинга dev - имя интерфейса*/
static void SetDevice(char *dev);

/*!Колбек для обработки пакектов, вытаскивает из них RSSI  и MAC если возможно*/
static void PacketProcess(struct packet_info *p);

/*!Копирует MAC адрес, из пакета в память*/
static void CopyMAC(unsigned char *mac_addr_p, unsigned char *target_mac);

/*!Выводит RSSI и MAC в консоль*/
static void PrintCapturedData(sCapturedRSSI *rssi_data);

/*!Добавляет заснифаные данные к массиву сохраненных данных. Манипулирует массивами при необходимости*/
static void AddToDataSet(sCapturedRSSI *rssi_data);

/*!Захватывает мьютекс доступа к данным*/
void CapturedData_Lock();

/*!Освобождает мьютекс доступа к данным*/
void CapturedData_Unlock();

static uint16_t GetId(void);

static void local_receive_packet(int fd, unsigned char* buffer, size_t bufsize);

//----------------CODE--------------------------

static void SetDevice(char *dev){
    strcpy(conf.ifname,dev);
    DEBUG_PRINT("Device %s has been setted\n",conf.ifname);
}

//----------------------------------

void SnifferInit(char *dev){
    int handle=0;
    conf.handle=0;
    conf.init_flag=0;
    
    if(dev[0]==0){
	   DEBUG_PRINTERR("Error: device didn't setted\n");
	   return;
	}
    SetDevice(dev);
    
    conf.sniffer_status=sns_stoped;

    if(!mutex_init){
        pthread_mutex_init(&data_mutex,NULL);
        mutex_init=1;
    }

    /*horst code part*/
    handle = open_packet_socket(conf.ifname, 0);
   	if (handle <= 0){
   		err(1, "Couldn't open packet socket");
   	}

   	conf.arphrd = device_get_hwinfo(handle, conf.ifname, conf.my_mac_addr);
   	if (conf.arphrd != ARPHRD_IEEE80211_RADIOTAP) {	//support only RADIOTAP headers
   		DEBUG_PRINTERR("You need to put your interface into monitor mode!\n");
   		DEBUG_PRINTERR("(e.g. 'iw %s interface add mon0 type monitor')\n", conf.ifname);
   		return ;
   	}
   /*-----------------------------------------*/
   	conf.handle=handle;
   	conf.init_flag=1;
}

//----------------------------------

int SnifferLoop(){
	DEBUG_PRINT("Sniffer loop started\n");
    conf.sniffer_status=sns_run;
    for ( /* ever */ ;;)
	{
    	int ret;

		FD_ZERO(&read_fds);
		FD_SET(conf.handle, &read_fds);

		tv.tv_sec = 0;
		tv.tv_usec = 1000000;

		ret = select(conf.handle+1, &read_fds, 0, 0, &tv);
		if (ret == -1 && errno == EINTR) /* interrupted */
			return 0;

		if (ret < 0) /* error */{
			err(1, "select()");
		}

		/*local packet*/
		if (FD_ISSET(conf.handle, &read_fds)) {
				local_receive_packet(conf.handle, buffer, sizeof(buffer));
		}
	}
    return 0;
}

//----------------------------------

void SnifferClose(){
	close_packet_socket(conf.handle, conf.ifname);
}

//----------------------------------

static void local_receive_packet(int fd, unsigned char* buffer, size_t bufsize)
{
	int len;
	struct packet_info p;

	DEBUG_PRINT("\n===============================================================================\n");

	len = recv_packet(fd, buffer, bufsize);

#if DO_DEBUG
	if (conf.debug) {
		dump_packet(buffer, len);
		DEBUG("\n");
	}
#endif
	memset(&p, 0, sizeof(p));

	if (!parse_packet(buffer, len, &p)) {
		DEBUG_PRINT("parsing failed\n");
		return;
	}

	PacketProcess(&p);
}

//----------------------------------

void PacketProcess(struct packet_info *p){
	int status=0;
    sCapturedRSSI rssi_data;    
    ++capture_packet_counter;

	if(p->phy_signal!=0){
		rssi_data.rssi=(int8_t)p->phy_signal;
	}
	else{
		DEBUG_PRINT("\tExtract RSSI error: no RSSI\n\n");   //Дропаем пакет, в нем нет RSSI.
		return;
	}

	if(p->wlan_src[0]!=0){
		CopyMAC(p->wlan_src,rssi_data.mac);
	}
	else{
		DEBUG_PRINT("\tExtract MAC error: frame doesn't contain source MAC\n");
		return;
	}

	//DEBUG_PRINT("Packet %d:\n",capture_packet_counter);
	//PrintCapturedData(&rssi_data); obsoleted debug output
	AddToDataSet(&rssi_data);
}

//----------------------------------

void CopyMAC(unsigned char *mac_addr_p, unsigned char *target_mac){
    int i=0;
    for(i=0;i<6;++i,++mac_addr_p){
    	target_mac[i]=*((uint8_t *)mac_addr_p);
    }
}

//----------------------------------

void PrintCapturedData(sCapturedRSSI *rssi_data){
    uint8_t *mac=rssi_data->mac;
    DEBUG_PRINT("\tRSSI = %i\n",rssi_data->rssi);
    DEBUG_PRINT("\tSource MAC = %X:%X:%X:%X:%X:%X\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

//----------------------------------
void AddToDataSet(sCapturedRSSI *rssi_data){
	int i,j;
	CapturedData_Lock();
	int index=captured_data.cur_index;
	captured_data.id_array[index]=GetId();
	captured_data.rssi_data[index].rssi=rssi_data->rssi;
	for(i=0;j<MAC_LEN;++i){
		captured_data.rssi_data[index].mac[i]=rssi_data->mac[i];
	}

	if(index<RSSI_BUFFER_SIZE-1){
		++(captured_data.cur_index);
	}
	else{
		captured_data.cur_index=0;
	}

	if(captured_data.records_count<RSSI_BUFFER_SIZE){
		++(captured_data.records_count);
	}
	CapturedData_Unlock();
}

//----------------------------------

void CapturedData_Lock(){
    while(!mutex_init);
        pthread_mutex_lock(&data_mutex);
}

//----------------------------------

void CapturedData_Unlock(){
	while(!mutex_init);
        pthread_mutex_unlock(&data_mutex);
}

//----------------------------------

static uint16_t GetId(void){
	uint16_t result=global_id;
	if(global_id<ID_LIMIT){
		++global_id;
	}
	else{
		global_id=1;
	}
	return result;
}

//----------------------------------

int GetRecords(uint16_t start_id, sCapturedRSSI *buffer){
	int i;
	int index;
	int total_count=0;
	CapturedData_Lock();
	if(start_id==0){
		index=captured_data.cur_index;
	}
	else{
		for(i=0;i<RSSI_BUFFER_SIZE;++i){
			if(captured_data.id_array[i]==start_id){
				index=i;
				break;
			}
		}
	}

	//todo реализовать уже сильно спать охота

	CapturedData_Unlock();
	return total_count;
}

//----------------------------------






