/*

  Game Service Server functions header for Dreamcast
  Author Shuouma

*/
#include <time.h>
#include <sqlite3.h>
#include <pthread.h>
#include <netinet/in.h>
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

/* SDO */
#define SDO_DUMMY 0x01
#define SDO_COMPETITOR_SETTINGS 0x02
#define SDO_START_SYNCHRO 0x03
#define SDO_START_TIME 0x04
#define SDO_PLAYER_READY_REQ 0x05
#define SDO_PLAYER_READY_UPDATE 0x06
#define SDO_START_RACE 0x07
#define SDO_START_RACE_ACK 0x08
#define SDO_GAME_SETTINGS 0x0A
#define SDO_GAME_SETTINGS_ACK 0x0B
#define SDO_PLAYER_STAT 0x0C
#define SDO_GAME_SETTINGS_MENUS 0x0D
#define SDO_IN_WAITROOM 0x0E
#define SDO_NEWMASTER_RESYNC 0x0F
#define SDO_FAMOUSLASTWORD 0x10
#define SDO_PLAYER_STATE 0x32
#define SDO_RESTART_RACE 0x33
#define SDO_GAME_EVENT 0x3C
#define SDO_PRICES_LIST 0x65
#define SDO_DBINFO_PLAYERSTAT 0x66
#define SDO_DBINFO_PLAYERCAR 0x67
#define SDO_DBUPDATE_PLAYERSTAT 0x68
#define SDO_DBUPDATE_PLAYERCAR 0x69
#define SDO_DBINFO_PLAYERALLCARS 0x6A
#define SDO_DBINFO_PLAYERDATA 0x6B
#define SDO_DATABASE_STATUS 0x6C
#define SDO_PLAYER_QUIT_RACE 0x6D
#define SDO_LOCAL_END_OF_RACE 0x6E
#define SDO_GAME_DEFINES 0x6F
#define SDO_LOCK_ROOM 0x70
#define SDO_UNLOCK_ROOM 0x71
#define SDO_DBUPDATE_PLAYERQUEST 0x72
#define SDO_DBINFO_PLAYERQUEST 0x73
#define SDO_PLAYER_KICK 0x74
#define SDO_DBINFO_FULLSTATS 0x75
#define SDO_DBUPDATE_FULLSTATS 0x76
#define SDO_STATS_POINT 0x78
#define SDO_STATS_CASH 0x79
#define SDO_STATS_STANDARDAVG 0x7A
#define SDO_STATS_STANDARDWIN 0x7B
#define SDO_STATS_TRIALAVG 0x7C
#define SDO_STATS_TRIALWIN 0x7D
#define SDO_STATS_VENDETTAAVG 0x7E
#define SDO_STATS_VENDETTAWIN 0x7F
#define SDO_STATS_PLAYERPOINTS 0x80
#define SDO_STATS_PLAYERCASH 0x81
#define SDO_STATS_PLAYERSTANDARDAVG 0x82
#define SDO_STATS_PLAYERSTANDARDWIN 0x83
#define SDO_STATS_PLAYERTRIALAVG 0x84
#define SDO_STATS_PLAYERTRIALWIN 0x85
#define SDO_STATS_PLAYERVENDETTAAVG 0x86
#define SDO_STATS_PLAYERVENDETTAWIN 0x87
#define SDO_DBUPDATE_DESC 0x88
#define SDO_DBUPDATE_STANDARD 0x89
#define SDO_DBUPDATE_TRIAL 0x8A
#define SDO_DBUPDATE_VENDETTA 0x8B
#define SDO_REQUEST_MOTD 0x8C
#define SDO_UPDATE_SESSION_INFO 0x8D
#define SDO_VERSION_CHECK 0x8E
#define SDO_DBERROR 0x8F
#define SDO_GMGENERROR 0x90
#define SDO_GETBESTLAP 0x91
#define SDO_COMMIT 0x92
#define SDO_TRACKRECORDS_UPDATE  0xC7
#define SDO_TRACKRECORDS  0xC8

/*MSG FLAG*/
#define SENDTOOTHERPLAYERS 0x01
#define SENDTOPLAYERGROUP 0x02
#define SENDTOPLAYER 0x03
#define SENDTOSERVER 0x04
#define SENDTOALLPLAYERS 0x05

typedef struct server_data server_data_t;
typedef struct player_data player_t;
typedef void (*send_udp_player_t)(player_t *player, char *msg, size_t size);
typedef int (*udp_msg_handler_t)(char *buf, size_t size, server_data_t *server, struct sockaddr_in *client);

#define SEQ_TAB_LEN 150

struct player_data {
  int sock;
  int is_master;
  struct {
    int ready;
    uint32_t client_seq;
    uint32_t rel_client_seq;
    uint32_t last_ack_seq;
    uint32_t last_rel_ack_seq;
    uint16_t last_time;
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
};

struct server_data {
  int udp_sock;
  uint8_t server_type;
  uint8_t max_players;
  uint8_t current_nr_of_players;
  uint16_t game_tcp_port;
  uint16_t game_udp_port;
  time_t start_time;
  char master[MAX_UNAME_LEN];
  char server_db_path[MAX_UNAME_LEN];
  char pidfile[32];
  uint16_t master_id;
  player_t *players[MAX_PLAYERS];
  sqlite3 *db;
  int lobby_pipe;
  pthread_mutex_t mutex;
  char session_info[32];
  int locked;
  send_udp_player_t send_udp_player;
  udp_msg_handler_t udp_msg_handler;
};

void *gs_gameserver_handler(void* data);
player_t *get_user_from_addr(server_data_t *s, struct sockaddr_in *addr);
uint16_t create_gameserver_hdr(char* msg, uint8_t msg_id, uint8_t msg_flag, uint16_t msg_size);
uint16_t create_event_newplayer(char* msg, uint16_t playerid, char* username);
uint16_t create_event_newmaster(char* msg, uint16_t playerid);
uint16_t create_event_playerinfos(char* msg, uint16_t playerid, uint32_t points, uint32_t trophies);
void send_udp_functions(int send_flag, char* msg, uint16_t pkt_size, server_data_t *s, uint16_t player_id);
void lobby_kick_player(server_data_t *server, uint16_t player_id);

int pod_udp_msg_handler(char *buf, size_t size, server_data_t *server, struct sockaddr_in *client);
void pod_send_udp_player(player_t *player, char *msg, size_t size);
int sdo_udp_msg_handler(char *buf, size_t size, server_data_t *server, struct sockaddr_in *client);
void sdo_send_udp_player(player_t *player, char *msg, size_t size);
