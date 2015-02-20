/* 
 * File:   sniffer.h
 * Author: root
 *
 * Created on 26 Октябрь 2014 г., 23:13
 */

#ifndef SNIFFER_H
#define	SNIFFER_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <pcap/pcap.h>

#define MAX_RSSI_RECORDS_PER_INTERVAL   1000       
#define MAC_LEN                         6
    
typedef enum{sns_run,sns_stoped}tSnifferStatus;

typedef struct{    
    uint8_t mac[MAC_LEN];
    int8_t rssi;
}sCapturedRSSI;

/*!Структура предназначена для хранения данных собранных за интервал времени
 * с последующей передачей их по сети*/
typedef struct{
   char valid;  //флаг валидность 0 - невалидно !0 - валидно
   struct timeval ts;   //временная метка
   int records_count;     
   sCapturedRSSI rssi_data[MAX_RSSI_RECORDS_PER_INTERVAL];  
}sCapturedDataSet; 

/*!Установка интерфейса для сниффинга dev - имя интерфейса*/    
void SetDevice(char *dev);

/*!Открытие устройства запуск снифинга*/
int SnifferStart(int capture_period);

/*!Закрытие устройства остановка снифинга*/
int SnifferStop();

/*!Главный цикл*/
int SnifferLoop();

/*!Возвращает период накопления данных снифером*/
int GetPeriod();

void CapturedData_Lock();

void CapturedData_Unlock();


extern sCapturedDataSet *ready_ds;
extern tSnifferStatus sniffer_status;

#ifdef	__cplusplus
}
#endif

#endif	/* SNIFFER_H */

