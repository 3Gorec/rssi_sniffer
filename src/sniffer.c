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


//----------------GLOBAL VARS-------------------

/*
 * size: max 80211 frame (2312) + space for prism2(not supported by my sniffer) header (144)
 * or radiotap header (usually only 26) + some extra */
static unsigned char buffer[2312 + 200];

static unsigned int capture_packet_counter=0;    //Используется для отладочного вывода номер пакета

static sCapturedDataSet data_set_0={.valid=0,.ts={0,0},.records_count=0};
static sCapturedDataSet data_set_1={.valid=0,.ts={0,0},.records_count=0};;
sCapturedDataSet *ready_ds=0;
static sCapturedDataSet *process_ds=&data_set_0;


static pthread_mutex_t data_mutex;
static char mutex_init=0;

/* for select */
static fd_set read_fds;
static struct timeval tv;	//todo убрать?

tSnifferConfig conf;

//----------------PROTOTYPES--------------------

/*!Устанавливает период наакопления данных
 * capture_period - длина периода в секундах*/
static int SetPeriod(int capture_period);

/*!Подготавлевает структуры дла накопления данных*/
static void PrepareStructures();

/*!Настраивает переключение структур по таймеру*/
static int InitTimer(int interval);

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

/*!Колбек вызываемый по таймеру*/
static void SniffingInervalTick(union sigval sv);

/*!Переключает буферы по истечению интервала*/
static void SwitchDataStructs();

static void local_receive_packet(int fd, unsigned char* buffer, size_t bufsize);

//----------------CODE--------------------------

static void SetDevice(char *dev){
    strcpy(conf.ifname,dev);
    DEBUG_PRINT("Device %s has been setted\n",conf.ifname);
}

//----------------------------------

static void PrepareStructures(){
    struct timeval ts;
    gettimeofday(&ts,NULL);
    process_ds=&data_set_0;
    ready_ds=0;
    data_set_0.records_count=0;
    data_set_0.valid=0;
    data_set_0.ts.tv_sec=0;
    data_set_0.ts.tv_usec=0;
    data_set_1.records_count=0;
    data_set_1.valid=0;
    data_set_1.ts.tv_sec=0;
    data_set_1.ts.tv_usec=0;
    process_ds->ts=ts;
}

//----------------------------------

static int InitTimer(int interval){
    timer_t timerid;   
    struct sigevent sev;
    struct itimerspec its;
    
    sev.sigev_notify=SIGEV_THREAD;
    sev.sigev_notify_function =SniffingInervalTick;
    sev.sigev_notify_attributes = NULL;
    sev.sigev_value.sival_ptr = &timerid;
    
    its.it_interval.tv_sec=interval;
    its.it_interval.tv_nsec=0;
    its.it_value.tv_sec=interval;
    its.it_value.tv_nsec=0;
    if(timer_create(CLOCK_REALTIME,&sev,&timerid)==-1){
        DEBUG_PRINTERR("Error timer\n");
        exit(EXIT_FAILURE);
    }
    timer_settime(&timerid,0,&its,NULL);   
}

//----------------------------------

void SnifferInit(int capture_period, char *dev){
    int handle=0;
    conf.handle=0;
    conf.init_flag=0;

    
    if(SetPeriod(capture_period)!=0){
         DEBUG_PRINTERR("Error, wrong accumulation period\n");
         return;
    }
    
    if(dev[0]==0){
	   DEBUG_PRINTERR("Error: device didn't setted\n");
	   return;
	}
    SetDevice(dev);
    
    PrepareStructures();
    InitTimer(conf.capture_inerval_s);
    
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

	DEBUG_PRINT("Packet %d:\n",capture_packet_counter);
	PrintCapturedData(&rssi_data);	
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
    
    if(process_ds->records_count<MAX_RSSI_RECORDS_PER_INTERVAL){    //сохранение данных за текущий интервал
        i=process_ds->records_count;
        process_ds->rssi_data[i].rssi=rssi_data->rssi;
        for(j=0;j<MAC_LEN;++j){
            process_ds->rssi_data[i].mac[j]=rssi_data->mac[j];
        }
        ++process_ds->records_count;
        if(process_ds==&data_set_0){   
            DEBUG_PRINT("\tHeader added to bank 0\n");
        }
        else{
            DEBUG_PRINT("\tHeader added to bank 1\n");
        }
    }
}
//----------------------------------

void SwitchDataStructs(){
    struct timeval ts;
    gettimeofday(&ts,NULL);
    CapturedData_Lock();        
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
    CapturedData_Unlock();
}

//----------------------------------

static void SniffingInervalTick(union sigval sv){
    SwitchDataStructs();
}

//----------------------------------

static int SetPeriod(int capture_period){
    if(capture_period<MIN_CAPTURE_PERIOD || capture_period>MAX_CAPTURE_PERIOD){
        return -1;
    }
    conf.capture_inerval_s=capture_period;
    return 0;
}

//----------------------------------

int GetPeriod(){
    return conf.capture_inerval_s;
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
