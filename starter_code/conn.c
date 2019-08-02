//
// Created by ssjjcao on 2018/11/25.
// used to construct a reliable transmission connection
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "conn.h"
#include "chunk.h"

chunk_buffer_t *init_chunk_buffer(char *hash) {
    chunk_buffer_t *chunk_buf = malloc(sizeof(chunk_buffer_t));
    memcpy(chunk_buf->chunk_hash, hash, SHA1_HASH_SIZE);
    chunk_buf->data_buf = malloc(BT_CHUNK_SIZE);
    return chunk_buf;
}

void free_chunk_buffer(chunk_buffer_t *chunk_buf) {
    free(chunk_buf->data_buf);
    free(chunk_buf);
}

down_conn_t *init_down_conn(bt_peer_t *peer, chunk_buffer_t *chunk_buf) {
    down_conn_t *conn = malloc(sizeof(down_conn_t));
    conn->from_here = 0;
    conn->next_ack = 1;
    conn->chunk_buf = chunk_buf;
    conn->sender = peer;
    return conn;
}

down_conn_t *add_to_down_pool(down_pool_t *pool, bt_peer_t *peer, chunk_buffer_t *chunk_buf) {
    down_conn_t *conn = init_down_conn(peer, chunk_buf);
    for (int i = 0; i < pool->max_conn; i++) {
        if (pool->conns[i] == NULL) {
            pool->conns[i] = conn;
            break;
        }
    }
    pool->conn_num++;
    return conn;
}

void remove_from_down_pool(down_pool_t *pool, bt_peer_t *peer) {
    down_conn_t **conns = pool->conns;
    for (int i = 0; i < pool->max_conn; i++) {
        if (conns[i] != NULL && conns[i]->sender->id == peer->id) {
            free_chunk_buffer(conns[i]->chunk_buf);
            free(conns[i]);
            conns[i] = NULL;
            pool->conn_num--;
            break;
        }
    }
}

void init_down_pool(down_pool_t *pool, int max_conn) {
    pool->conn_num = 0;
    pool->max_conn = max_conn;
    pool->conns = malloc(max_conn * sizeof(down_conn_t *));
    for (int i = 0; i < max_conn; i++) {
        pool->conns[i] = NULL;
    }
}

down_conn_t *get_down_conn(down_pool_t *pool, bt_peer_t *peer) {
    down_conn_t **conns = pool->conns;
    for (int i = 0; i < pool->max_conn; i++) {
        down_conn_t *down_conn = conns[i];
        if (down_conn != NULL && down_conn->sender->id == peer->id) {
            return down_conn;
        }
    }
    return NULL;
}

up_conn_t *init_up_conn(bt_peer_t *peer, packet_t **pkts) {
    up_conn_t *conn = malloc(sizeof(up_conn_t));
    conn->last_ack = 0;
    conn->to_send = 0;
    conn->available = 1;
    conn->dup_times = 0;
    conn->cwnd = 1; //initial congestion control window size
    conn->ssthresh = 64; //initial slow start threshold
    conn->rtt_flag = 1;
    conn->begin_time = clock();
    conn->receiver = peer;
    conn->pkts = pkts;
    return conn;
}

up_conn_t *add_to_up_pool(up_pool_t *pool, bt_peer_t *peer, packet_t **pkts) {
    up_conn_t *conn = init_up_conn(peer, pkts);
    for (int i = 0; i < pool->max_conn; i++) {
        if (pool->conns[i] == NULL) {
            pool->conns[i] = conn;
            break;
        }
    }
    pool->conn_num++;
    return conn;
}

void remove_from_up_pool(up_pool_t *pool, bt_peer_t *peer) {
    up_conn_t **conns = pool->conns;
    for (int i = 0; i < pool->max_conn; i++) {
        if (conns[i] != NULL && conns[i]->receiver->id == peer->id) {
            for (int j = 0; j < CHUNK_SIZE; j++) {
                free(conns[i]->pkts[j]);
            }
            free(conns[i]->pkts);
            free(conns[i]);
            conns[i] = NULL;
            pool->conn_num--;
            break;
        }
    }
}

void init_up_pool(up_pool_t *pool, int max_conn) {
    pool->conn_num = 0;
    pool->max_conn = max_conn;
    pool->conns = malloc(max_conn * sizeof(up_conn_t *));
    for (int i = 0; i < max_conn; i++) {
        pool->conns[i] = NULL;
    }
}

up_conn_t *get_up_conn(up_pool_t *pool, bt_peer_t *peer) {
    up_conn_t **conns = pool->conns;
    for (int i = 0; i < pool->max_conn; i++) {
        up_conn_t *up_conn = conns[i];
        if (up_conn != NULL && up_conn->receiver->id == peer->id) {
            return up_conn;
        }
    }
    return NULL;
}

