# P2P-BitTorrent

> Note:  
> This document is written to describe my code design and implementation in general.  
> For more specific details, please look over the document "Design.pdf".  
> by *ssjjcao* <16302010015@fudan.edu.cn>

## 1. additional files written for the project
  |file|description|
  |:-:|:-|
  |packet.h|define the structure of a packet and its header|
  |list.[h&#124;c]|implement data structure of `single linked list`|
  |store.[h&#124;c]|store information of the chunk(s) this peer has;<br>simulate tracker, manage information of all peers' chunks.|
  |handler.[h&#124;c]|handle packets received;<br>send and receive chunk data reliably;<br>implement congestion control.|
  |task_get.[h&#124;c]|initialize and manage GET task from user's cmd|
  |conn.[h&#124;c]|simulate connection of TCP;<br>define structure(pool) to manage simultaneous downloads.|

## 2. some structures
  (1) GET task  
```
    typedef struct task_get_s {  
      int get_num; //chunks number of this GET task
      int *status; //0: not start; 1: done; 2: processing.
      bt_peer_t **providers; //senders for each chunk
      chunk_t *get_chunks; //chunks to get
      char **chunk_data; //chunk data for each chunk
      char output[BT_FILENAME_LEN]; //output file
    } task_get_t;
```
  
  (2) chunk and chunk buffer
```
    typedef struct chunk_s {
      int id;
      char chunk_hash[SHA1_HASH_SIZE]; //chunk hash(20 bytes) after shahash
    } chunk_t;
```
``` 
    typedef struct chunk_buffer_s {
      char chunk_hash[SHA1_HASH_SIZE];
      char *data_buf; //chunk data of chunk_hash
    } chunk_buffer_t;
```

  (3) download and upload connection
```
    typedef struct down_conn_s {
      int from_here; //used when caching data into chunk_buf->data_buf
      int next_ack; //next ack expected, range form 1 to 512
      bt_peer_t *sender;
      chunk_buffer_t *chunk_buf; //used to cache data
    } down_conn_t;
```
```  
    typedef struct up_conn_s {
      int last_ack;
      int to_send; //index of packet to send, range from 0 to (512 - 1)
      int available; //index(of last available packet in sender's window) + 1
      int dup_times; //duplicate times of last_ack
      int cwnd; //(dynamic)congestion window size
      int ssthresh; //slow start threshold
      int rtt_flag; //represent the end of a rtt
      long begin_time;
      packet_t **pkts; //cache all packets to send
      bt_peer_t *receiver;
    } up_conn_t;
```

  (4) download and upload pool
```
    typedef struct down_pool_s {
      down_conn_t **conns;
      int conn_num; //current download connection number of peer
      int max_conn; //maxmium download connection number of peer
    } down_pool_t;
```
```
    typedef struct up_pool_s {
      up_conn_t **conns;
      int conn_num;
      int max_conn;
    } up_pool_t;
```

> In fact, I only implement simultaneous download from other peers.   
> up_pool_t is useless to some extent, just in consistence with down_pool_t.

## 3. methods used to implement reliable transmission and congestion control
  |function|method|
  |:-:|:-:|
  |reliable transmission|GBN| 
  |simultaneous transmission|connection pool(a structure)|
  |timer|signal: SIGALRM| 
  |congestion control|TCP Tahoe|  

  *Specific implementation of reliable transmission and congestion control: please look over [Design](https://github.com/ssjjcao/CN_BitTorrent/blob/master/Design.pdf)*








