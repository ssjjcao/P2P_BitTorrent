//
// Created by ssjjcao on 2018/11/19.
//

#ifndef CN_BITTORRENT_HANDLER_H
#define CN_BITTORRENT_HANDLER_H

#include "sha.h"
#include "list.h"
#include "store.h"
#include "bt_parse.h"
#include "packet.h"
#include "conn.h"

void pkt_ntoh(packet_t *packet);

//return corresponding packet type if packet is valid, -1 otherwise
int parse_type(packet_t *packet);

//return a corresponding Ihave packet if the peer has the chunk, NULL otherwise
packet_t *handle_whohas(packet_t *pkt_whohas);

//whether i have this chunk or not, has -> return 1, otherwise return 0.
int has_chunk(char *chunk_hash);

packet_t *new_pkt(unsigned char type, unsigned short packet_len,
                  unsigned int seq_num, unsigned int ack_num, char *payload);

//create WHOHAS packet(s) according to the task of GET
list_t *new_whohas_pkt();

void assemble_chunk_hash(char *payload, int chunk_num, chunk_t *chunks);

list_t *split_into_chunks(void *payload);

packet_t *handle_ihave(packet_t *pkt, bt_peer_t *peer);

void handle_get(int sock, packet_t *pkt, bt_peer_t *peer);

void send_data_pkts(up_conn_t *conn, int sock, struct sockaddr *to);

packet_t **get_data_pkts(char *chunk_hash);

void handle_data(int sock, packet_t *pkt, bt_peer_t *peer);

void handle_ack(int sock, packet_t *pkt, bt_peer_t *peer);

void handle_timeout();

#endif //CN_BITTORRENT_HANDLER_H
