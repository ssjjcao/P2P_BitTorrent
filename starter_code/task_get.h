//
// Created by ssjjcao on 2018/11/20.
//

#ifndef CN_BITTORRENT_TASK_GET_H
#define CN_BITTORRENT_TASK_GET_H

#include "list.h"
#include "bt_parse.h"
#include "store.h"

typedef struct task_get_s {
    int get_num;
    int *status; //0: not start; 1: done; 2: processing.
    bt_peer_t **providers;
    chunk_t *get_chunks;
    char **chunk_data;
    char output[BT_FILENAME_LEN];
} task_get_t;

void init_task(char *chunk_file, char *out_file);

char *update_provider(list_t *chunk_hash_list, bt_peer_t *peer);

//check the chunk data of chunk hash and update status if valid
void add_and_check_data(char *hash, char *data);

int is_task_finish();

void write_data();

#endif //CN_BITTORRENT_TASK_GET_H
