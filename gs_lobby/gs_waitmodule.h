/*

  Game Service Server functions header for Dreamcast
  Author Shuouma

*/
#include <sqlite3.h>
#include "../gs_common/gs_common.h"

typedef struct server_data server_data_t;

typedef struct {
  int sock;
  int in_game;
  struct sockaddr_in addr;
  char username[MAX_UNAME_LEN];
  uint32_t player_id;
  uint32_t in_session_id;
  uint32_t keepalive;
  uint32_t trophies;
  uint32_t points;
  server_data_t *server;
} player_t;

typedef struct {
  char session_name[MAX_UNAME_LEN];
  char session_game[MAX_UNAME_LEN];
  char session_gameversion[MAX_UNAME_LEN];
  char session_gameinfo[32];
  char session_password[MAX_UNAME_LEN];
  char session_master[MAX_UNAME_LEN];
  uint32_t session_master_player_id;
  uint32_t session_gs_version;
  uint32_t session_max_players;
  uint32_t session_nb_players;
  uint32_t session_max_observers;
  uint32_t session_nb_observers;
  uint32_t session_groupid;
  uint32_t session_pgroupid;
  uint32_t session_id;
  uint32_t session_unknown_1;
  uint32_t session_unknown_2;
  uint32_t session_config;
  uint16_t session_gameport;
  uint32_t session_duration;
  player_t **p_l;
  server_data_t *server;
  int gameserver_pipe;
} session_t;

struct server_data {
  char server_ip[INET_ADDRSTRLEN];
  char server_db_path[256];

  char name[MAX_UNAME_LEN];
  char game[MAX_UNAME_LEN];
  char allowedbranch[256];
  
  uint16_t waitmodule_port;
  uint16_t server_port;
  
  uint8_t server_type;
  uint32_t arena_id;
  uint32_t basicgroup_id;
  uint32_t chatgroup_id;
  uint32_t start_session_id;
  uint16_t max_sessions;
  uint16_t max_players;

  uint32_t group_size;
  
  //Data
  session_t **s_l;
  player_t **waitmodule_p_l;
  player_t **server_p_l;
    
  sqlite3 *db;
};



