/*

  Game Service MSG functions header for Dreamcast
  Author Shuouma

*/

uint16_t create_gs_hdr(char* msg, uint8_t msg_id, uint8_t msg_flag, uint16_t msg_size);
uint16_t create_joinwaitmodule(char* msg, char* ip, uint16_t port);
uint16_t create_playerinfo(char* msg, char* username, char* ip);
uint16_t create_updategroupsize(char* msg, uint32_t groupid, uint32_t nr_players);
uint16_t create_loginarena(char* msg, uint32_t arena_id);
uint16_t create_joinarena(char* msg, uint32_t arena_id, uint16_t port);
uint16_t create_joinsession(char* msg, uint32_t groupid);
uint16_t create_createsession(char* msg, char* session_name, uint32_t session_id);
uint16_t create_playerpoints(char* msg, char* username, uint32_t points, uint32_t trophies, char* game);
uint16_t create_gssuccessful(char* msg, uint8_t msg_code);
uint16_t create_gsfail(char* msg, uint8_t msg_code, uint32_t error_code);
uint16_t create_new_basic_group(char* msg, uint32_t arena_id, uint32_t basicgroup_id, char* game, char* allowedbranch);
uint16_t create_new_arena(char* msg, uint32_t arena_id, uint32_t basicgroup_id, char* ip);
uint16_t create_getsession(char* msg, char* username, char* name, char* game,char* gameinfo, char* master, uint32_t session_id, uint32_t group_id, uint32_t max_players, uint32_t max_observers, uint32_t conf);
uint16_t create_sessionnew(char* msg, char* name, char* game, char* allowedbranch, char* gameinfo, char* master, uint32_t session_id, uint32_t group_id, uint32_t nb_of_players, uint32_t max_players, uint32_t max_observers, uint32_t config);
uint16_t create_joinnew(char* msg, char* username, uint32_t groupid);
uint16_t create_joinleave(char* msg, char* username, uint32_t groupid);
uint16_t create_begingame(char* msg, uint32_t groupid);
uint16_t create_updatesessions(char* msg, uint32_t groupid, uint32_t session_config);
uint16_t create_sessionremove(char* msg, uint32_t groupid);
uint16_t create_startgame(char* msg, uint32_t group_id, char* ip, uint32_t port);
uint16_t create_master_changed(char* msg, uint32_t session_id, char* username);
uint16_t create_ping(char* msg);
uint16_t create_updateplayerping(char* msg, char* username, uint32_t groupid, uint8_t ping);
