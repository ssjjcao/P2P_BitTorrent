//
// Created by ssjjcao on 2018/11/20.
// used to init and manager GET task
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "task_get.h"
#include "sha.h"
#include "chunk.h"

extern task_get_t task_get;

void init_task(char *chunk_file, char *out_file) {
    FILE *fd = fopen(chunk_file, "r");

    int line_num = 0;
    char read_buf[256];
    int id_buf;
    char hash_buf[2 * SHA1_HASH_SIZE];
    while (fgets(read_buf, 256, fd)) {
        line_num++;
    }
    task_get.get_num = line_num;
    task_get.get_chunks = malloc(line_num * sizeof(chunk_t));
    task_get.chunk_data = malloc(line_num * sizeof(char *));
    strcpy(task_get.output, out_file);
    task_get.status = malloc(line_num * sizeof(int));
    task_get.providers = malloc(line_num * sizeof(bt_peer_t *));
    for (int i = 0; i < line_num; i++) {
        task_get.status[i] = 0;
        task_get.providers[i] = NULL;
    }

    fseek(fd, 0, SEEK_SET);
    int index = 0;
    while (fgets(read_buf, 256, fd)) {
        if (sscanf(read_buf, "%d %s", &id_buf, hash_buf) != 2) {
            continue;
        }
        task_get.get_chunks[index].id = id_buf;
        hex2binary(hash_buf, 2 * SHA1_HASH_SIZE, task_get.get_chunks[index].chunk_hash);
        index++;
    }
}

char *update_provider(list_t *chunk_hash_list, bt_peer_t *peer) {
    int num = task_get.get_num;
    char *to_download = NULL;
    int is_first = 1;
    for (node_t *node = chunk_hash_list->head; node != NULL; node = node->next) {
        char *chunk_hash = (char *) (node->data);
        for (int i = 0; i < num; i++) {
            char *this_chunk_hash = task_get.get_chunks[i].chunk_hash;
            if (memcmp(this_chunk_hash, chunk_hash, SHA1_HASH_SIZE) == 0) {
                if (task_get.status[i] == 0) {
                    task_get.providers[i] = peer;

                    //in consideration of simultaneous transmission
                    if (is_first == 1) {
                        task_get.status[i] = 2;
                        to_download = task_get.get_chunks[i].chunk_hash;
                        is_first++;
                    }
                }
                break;
            }
        }
    }
    return to_download;
}

void add_and_check_data(char *hash, char *data) {
    int i;
    for (i = 0; i < task_get.get_num; i++) {
        char *this_hash = task_get.get_chunks[i].chunk_hash;
        if (memcmp(this_hash, hash, SHA1_HASH_SIZE) == 0) {
            task_get.chunk_data[i] = malloc(BT_CHUNK_SIZE);
            memcpy(task_get.chunk_data[i], data, BT_CHUNK_SIZE);
            break;
        }
    }

    uint8_t hash_my_data[SHA1_HASH_SIZE];
    char *my_data = task_get.chunk_data[i];
    shahash((uint8_t *) my_data, BT_CHUNK_SIZE, hash_my_data);
    task_get.status[i] = memcmp(hash_my_data, hash, SHA1_HASH_SIZE) == 0 ? 1 : 0;
}

int is_task_finish() {
    for (int i = 0; i < task_get.get_num; i++) {
        if (task_get.status[i] != 1) {
            return 0;
        }
    }
    return 1;
}


void write_data() {
    FILE *fd = fopen(task_get.output, "wb+");
    for (int i = 0; i < task_get.get_num; i++) {
        fwrite(task_get.chunk_data[i], 1024, 512, fd);
    }
    fclose(fd);
    for (int i = 0; i < task_get.get_num; i++) {
        free(task_get.chunk_data[i]);
    }
    free(task_get.chunk_data);
    free(task_get.status);
    free(task_get.providers);
    free(task_get.get_chunks);
}