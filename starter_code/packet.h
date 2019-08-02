//
// Created by ssjjcao on 2018/11/28.
//

#ifndef CN_BITTORRENT_PACKET_H
#define CN_BITTORRENT_PACKET_H

#define HEADERLEN          16
#define PACKETLEN          1500
#define DATALEN            (PACKETLEN - HEADERLEN)
#define MAGIC_NUM          15441
#define MAX_CHUNK_NUM      74
#define WHOHAS             0
#define IHAVE              1
#define GET                2
#define DATA               3
#define ACK                4
#define DENIED             5

typedef struct header_s {
    unsigned short magic;
    unsigned char version;
    unsigned char type;
    unsigned short header_len;
    unsigned short packet_len;
    unsigned int seq_num;
    unsigned int ack_num;
} header_t;

typedef struct packet_s {
    header_t header;
    char data[DATALEN];
} packet_t;

#endif //CN_BITTORRENT_PACKET_H
