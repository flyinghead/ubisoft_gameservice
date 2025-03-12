/*

  Game Service Server functions header for Dreamcast
  Author Shuouma

*/
#include <sqlite3.h>
#include <pthread.h>
#include "../gs_common/gs_common.h"

/* MSG ID */
#define EVENT_REGISTER 0xFA
#define EVENT_OWNID 0xF9
#define EVENT_NEWPLAYER 0xF3
#define EVENT_PLAYERLEFT 0xF2
#define EVENT_NEWMASTER 0xF1
#define EVENT_SERVERTIME 0xF0
#define EVENT_PLAYERINFOS 0xEF
#define EVENT_ACK 0xEA
#define EVENT_CHOKE 0xEB
#define EVENT_RATE 0xEC
#define EVENT_UDPCONNECT 0xED

/* STAT ID */
#define EVENT_TOPSCORES     0xC9
#define EVENT_UPDATESCORES  0xCB
#define EVENT_TRACKSRECORDS    0xCC
#define EVENT_UPDATETRACKSPEED 0xCD
#define EVENT_UPDATELAPSPEED   0xCE
#define EVENT_SETTRACKSPEED    0xCF
#define EVENT_SETLAPSPEED      0xD0
#define EVENT_FIVESCORESBEFORE 0xD1
#define EVENT_FIVESCORESAFTER  0xD2
#define EVENT_DELETETRACKSRECORDS 0xD3
#define EVENT_MONACO_FIVESCORESBEFORE 0xD9
#define EVENT_MONACO_FIVESCORESAFTER  0xDA

/*MSG FLAG*/
#define SENDTOOTHERPLAYERS 0x01
#define SENDTOPLAYERGROUP 0x02
#define SENDTOPLAYER 0x03
#define SENDTOSERVER 0x04
#define SENDTOALLPLAYERS 0x05

typedef struct server_data server_data_t;

#define SEQ_TAB_LEN 150

typedef struct {
  int sock;
  int is_master;
  struct {
    int ready;
    uint32_t client_seq;
    uint32_t rel_client_seq;
    uint32_t last_ack_seq;
    uint32_t last_rel_ack_seq;
    uint16_t last_time;
    uint16_t clock_diff;
    time_t last_update;
    struct sockaddr_in addr;
    struct {
      uint32_t cseq;
      uint32_t sseq;
    } seq_table[SEQ_TAB_LEN];
    int seq_head;
    int seq_tail;
  } udp;
  uint32_t trophies;
  uint32_t points;
  struct sockaddr_in addr;
  char username[MAX_UNAME_LEN];
  uint16_t player_id;
  server_data_t *server;
} player_t;

struct server_data {
  int udp_sock;
  uint8_t server_type;
  uint8_t max_players;
  uint8_t current_nr_of_players;
  uint16_t game_tcp_port;
  uint16_t game_udp_port;
  struct timespec start_time;
  char master[MAX_UNAME_LEN];
  char server_db_path[MAX_UNAME_LEN];
  char pidfile[32];
  uint16_t master_id;
  player_t **p_l;
  sqlite3 *db;
  int lobby_pipe;
  pthread_mutex_t mutex;
  char session_info[32];
};

void *gs_gameserver_handler(void* data);
