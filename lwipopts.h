#ifndef _LWIPOPTS_H
#define _LWIPOPTS_H

// Common settings for Pico W / Pico 2 W bare-metal (No RTOS)
#define NO_SYS                      1
#define LWIP_SOCKET                 0
#define LWIP_COMPAT_SOCKETS         0
#define LWIP_CORE_LOCKING           0
#define LWIP_NETCONN                0

// Enable specific protocols
#define LWIP_IPV4                   1
#define LWIP_TCP                    1
#define LWIP_UDP                    1
#define LWIP_DHCP                   1
#define LWIP_ARP                    1
#define LWIP_ETHERNET               1
#define LWIP_ICMP                   1
#define LWIP_RAW                    1

// Memory and Buffer configurations (Sized for Pico's RAM)
#define MEM_ALIGNMENT               4
#define MEM_SIZE                    32768
#define MEMP_NUM_TCP_SEG            32
#define MEMP_NUM_ARP_QUEUE          10
#define PBUF_POOL_SIZE              24

// TCP Window and Queue sizes
#define TCP_WND                     (8 * TCP_MSS)
#define TCP_MSS                     1460
#define TCP_SND_BUF                 (8 * TCP_MSS)
#define TCP_SND_QUEUELEN            ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS))
#define TCP_LISTEN_BACKLOG          1

#define LWIP_NETIF_TX_SINGLE_PBUF   1

#endif /* _LWIPOPTS_H */