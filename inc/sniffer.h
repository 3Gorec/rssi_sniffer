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

#define MAX_RSSI_RECORDS_PER_INTERVAL   300       
#define MAC_LEN                         6
#define WLAN_MAX_SSID_LEN	34

#define MAX_HISTORY		255
#define MAX_RATES		44	/* 12 legacy rates and 32 MCS */
#define MAX_FSTYPE		0xff
#define MAX_FILTERMAC		9

/* packet types we actually care about, e.g filter */
#define PKT_TYPE_CTRL		0x000001
#define PKT_TYPE_MGMT		0x000002
#define PKT_TYPE_DATA		0x000004

#define PKT_TYPE_BADFCS		0x000008

#define PKT_TYPE_BEACON		0x000010
#define PKT_TYPE_PROBE		0x000020
#define PKT_TYPE_ASSOC		0x000040
#define PKT_TYPE_AUTH		0x000080
#define PKT_TYPE_RTSCTS		0x000100
#define PKT_TYPE_ACK		0x000200
#define PKT_TYPE_NULL		0x000400
#define PKT_TYPE_QDATA		0x000800

#define PKT_TYPE_ARP		0x001000
#define PKT_TYPE_IP		0x002000
#define PKT_TYPE_ICMP		0x004000
#define PKT_TYPE_UDP		0x008000
#define PKT_TYPE_TCP		0x010000
#define PKT_TYPE_OLSR		0x020000
#define PKT_TYPE_BATMAN		0x040000
#define PKT_TYPE_MESHZ		0x080000

#define PKT_TYPE_ALL_MGMT	(PKT_TYPE_BEACON | PKT_TYPE_PROBE | PKT_TYPE_ASSOC | PKT_TYPE_AUTH)
#define PKT_TYPE_ALL_CTRL	(PKT_TYPE_RTSCTS | PKT_TYPE_ACK)
#define PKT_TYPE_ALL_DATA	(PKT_TYPE_NULL | PKT_TYPE_QDATA | PKT_TYPE_ARP | PKT_TYPE_ICMP | PKT_TYPE_IP | \
				 PKT_TYPE_UDP | PKT_TYPE_TCP | PKT_TYPE_OLSR | PKT_TYPE_BATMAN | PKT_TYPE_MESHZ)
#define PKT_TYPE_ALL		(PKT_TYPE_CTRL | PKT_TYPE_MGMT | PKT_TYPE_DATA | PKT_TYPE_ALL_MGMT | PKT_TYPE_ALL_CTRL | PKT_TYPE_ALL_DATA | PKT_TYPE_BADFCS)

#define WLAN_MODE_AP		0x01
#define WLAN_MODE_IBSS		0x02
#define WLAN_MODE_STA		0x04
#define WLAN_MODE_PROBE		0x08
#define WLAN_MODE_4ADDR		0x10
#define WLAN_MODE_UNKNOWN	0x20

#define WLAN_MODE_ALL		(WLAN_MODE_AP | WLAN_MODE_IBSS | WLAN_MODE_STA | WLAN_MODE_PROBE | WLAN_MODE_4ADDR | WLAN_MODE_UNKNOWN)

#define PHY_FLAG_SHORTPRE	0x0001
#define PHY_FLAG_BADFCS		0x0002
#define PHY_FLAG_A		0x0010
#define PHY_FLAG_B		0x0020
#define PHY_FLAG_G		0x0040
#define PHY_FLAG_MODE_MASK	0x00f0

/* default config values */
#define INTERFACE_NAME		"wlan0"
#define NODE_TIMEOUT		60	/* seconds */
#define CHANNEL_TIME		250000	/* 250 msec */
/* update display every 100ms - "10 frames per sec should be enough for everyone" ;) */
#define DISPLAY_UPDATE_INTERVAL 100000	/* usec */
#define RECV_BUFFER_SIZE	0	/* not used by default */
#define DEFAULT_PORT		"4444"	/* string because of getaddrinfo() */
#define DEFAULT_CONTROL_PIPE	"/tmp/horst"

#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP 803    /* IEEE 802.11 + radiotap header */
#endif

#ifndef ARPHRD_IEEE80211_PRISM
#define ARPHRD_IEEE80211_PRISM 802      /* IEEE 802.11 + Prism2 header  */
#endif


typedef enum{sns_run,sns_stoped}tSnifferStatus;

typedef struct  {
	int handle;
	char init_flag;
	char		ifname[255];
	int capture_inerval_s;
	int			arphrd; // the device ARP type
	unsigned char		my_mac_addr[MAC_LEN];
	tSnifferStatus sniffer_status;
}tSnifferConfig;

extern tSnifferConfig conf;

typedef struct{    
    uint8_t mac[MAC_LEN];
    int8_t rssi;
}sCapturedRSSI;

struct packet_info {
	/* general */
	unsigned int		pkt_types;	/* bitmask of packet types */

	/* wlan phy (from radiotap) */
	int			phy_signal;	/* signal strength (usually dBm) */
	unsigned int		phy_rate;	/* physical rate * 10 (=in 100kbps) */
	unsigned char		phy_rate_idx;	/* MCS index */
	unsigned char		phy_rate_flags;	/* MCS flags */
	unsigned int		phy_freq;	/* frequency from driver */
	unsigned int		phy_flags;	/* A, B, G, shortpre */

	/* wlan mac */
	unsigned int		wlan_len;	/* packet length */
	u_int16_t		wlan_type;	/* frame control field */
	unsigned char		wlan_src[MAC_LEN]; /* transmitter (TA) */
	unsigned char		wlan_dst[MAC_LEN]; /* receiver (RA) */
	unsigned char		wlan_bssid[MAC_LEN];
	char			wlan_essid[WLAN_MAX_SSID_LEN];
	u_int64_t		wlan_tsf;	/* timestamp from beacon */
	unsigned int		wlan_bintval;	/* beacon interval */
	unsigned int		wlan_mode;	/* AP, STA or IBSS */
	unsigned char		wlan_channel;	/* channel from beacon, probe */
	unsigned char		wlan_qos_class;	/* for QDATA frames */
	unsigned int		wlan_nav;	/* frame NAV duration */
	unsigned int		wlan_seqno;	/* sequence number */

	/* flags */
	unsigned int		wlan_wep:1,	/* WEP on/off */
				wlan_retry:1,
				wlan_wpa:1,
				wlan_rsn:1;

	/* batman-adv */
	unsigned char		bat_version;
	unsigned char		bat_packet_type;
	unsigned char		bat_gw:1;

	/* IP */
	unsigned int		ip_src;
	unsigned int		ip_dst;
	unsigned int		tcpudp_port;
	unsigned int		olsr_type;
	unsigned int		olsr_neigh;
	unsigned int		olsr_tc;

	/* calculated from other values */
	unsigned int		pkt_duration;	/* packet "airtime" */
	int			pkt_chan_idx;	/* received while on channel */
	int			wlan_retries;	/* retry count for this frame */
};



/*!Структура предназначена для хранения данных собранных за интервал времени
 * с последующей передачей их по сети*/
typedef struct{
   char valid;  //флаг валидность 0 - невалидно !0 - валидно
   struct timeval ts;   //временная метка
   int records_count;     
   sCapturedRSSI rssi_data[MAX_RSSI_RECORDS_PER_INTERVAL];  
}sCapturedDataSet; 

/*!Инициализаци сниффера*/
void SnifferInit(int capture_period, char *dev);

/*!Главный цикл*/
int SnifferLoop();

void SnifferClose();

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

