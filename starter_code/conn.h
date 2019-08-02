//
// Created by ssjjcao on 2018/11/25.
//

#ifndef CN_BITTORRENT_CONN_H
#define CN_BITTORRENT_CONN_H

#include "bt_parse.h"
#include "sha.h"
#include "packet.h"

//#define WINDOW_SIZE  8  //fixed window size
#define CHUNK_SIZE     512

typedef struct chunk_buffer_s {
    char chunk_hash[SHA1_HASH_SIZE];
    char *data_buf;
} chunk_buffer_t;

typedef struct down_conn_s {
    int from_here; //used when caching data into chunk_buf->data_buf
    int next_ack; //next ack expected, range form 1 to 512
    bt_peer_t *sender;
    chunk_buffer_t *chunk_buf; //used to cache data
} down_conn_t;

typedef struct up_conn_s {
    int last_ack;
    int to_send; //the num to send, range from 0 to (512 - 1)
    int available; //index(of last available packet in the sender window) + 1
    int dup_times; //duplicate times of last_ack
    int cwnd; //congestion window size(dynamic size)
    int ssthresh; //thresh of 'slow start' stage
    int rtt_flag; //represent the end of a rtt
    long begin_time;
    packet_t **pkts; //cache all packets to send
    bt_peer_t *receiver;
} up_conn_t;

typedef struct down_pool_s {
    down_conn_t **conns;
    int conn_num;
    int max_conn;
} down_pool_t;

typedef struct up_pool_s {
    up_conn_t **conns;
    int conn_num;
    int max_conn;
} up_pool_t;

chunk_buffer_t *init_chunk_buffer(char *hash);

void free_chunk_buffer(chunk_buffer_t *chunk_buf);

down_conn_t *init_down_conn(bt_peer_t *peer, chunk_buffer_t *chunk_buf);

down_conn_t *add_to_down_pool(down_pool_t *pool, bt_peer_t *peer, chunk_buffer_t *chunk_buf);

void remove_from_down_pool(down_pool_t *pool, bt_peer_t *peer);

void init_down_pool(down_pool_t *pool, int max_conn);

down_conn_t *get_down_conn(down_pool_t *pool, bt_peer_t *peer);

up_conn_t *init_up_conn(bt_peer_t *peer, packet_t **pkts);

up_conn_t *add_to_up_pool(up_pool_t *pool, bt_peer_t *peer, packet_t **pkts);

void remove_from_up_pool(up_pool_t *pool, bt_peer_t *peer);

void init_up_pool(up_pool_t *pool, int max_conn);

up_conn_t *get_up_conn(up_pool_t *pool, bt_peer_t *peer);


#endif //CN_BITTORRENT_CONN_H
