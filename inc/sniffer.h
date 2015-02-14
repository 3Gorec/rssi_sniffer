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

#include <pcap/pcap.h>

typedef enum{sns_run,sns_stoped}tSnifferStatus;
    
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

extern tSnifferStatus sniffer_status;

#ifdef	__cplusplus
}
#endif

#endif	/* SNIFFER_H */

