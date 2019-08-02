//
// Created by ssjjcao on 2018/11/20.
//

#ifndef CN_BITTORRENT_STORE_H
#define CN_BITTORRENT_STORE_H

#include "sha.h"

typedef struct chunk_s {
    int id;
    char chunk_hash[SHA1_HASH_SIZE];
} chunk_t;

//read master-chunk-file, and store all chunks' information
void init_tracker();

//read has-chunk-file and store
void init_chunks_ihave();

#endif //CN_BITTORRENT_STORE_H
