//
// Created by ssjjcao on 2018/11/20.
//

#ifndef CN_BITTORRENT_LIST_H
#define CN_BITTORRENT_LIST_H

typedef struct node_s {
    void *data;
    struct node_s *next;
} node_t;

typedef struct list_s {
    int node_num;
    node_t *head;
    node_t *tail;
} list_t;

list_t *init_list();

void add_node(list_t *list, void *data);

void *pop_node(list_t *list);

#endif //CN_BITTORRENT_LIST_H
