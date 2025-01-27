#include <sqlite3.h>

sqlite3* open_gs_db(const char* db_path);
int create_player_record(sqlite3* db, const char* username);
int create_lap_record(sqlite3* db, const char* username, const char* trackname, uint32_t laptime, int mode);
int create_track_record(sqlite3* db, const char* username, const char* trackname, uint32_t tracktime);
int update_player_point(sqlite3* db, const char* username, uint32_t points, uint32_t trophies);
int load_player_record(sqlite3 *db, const char* username, uint32_t *points, uint32_t *trophies);
int load_topscores_record(sqlite3 *db, char* msg, uint16_t max_pkt_size);
int load_fivescoreafter_record(sqlite3 *db, const char* username, char* msg, uint16_t max_pkt_size);
int load_fivescorebefore_record(sqlite3 *db, const char* username, char* msg, uint16_t max_pkt_size);
int load_track_record(sqlite3 *db, char* msg, uint16_t max_pkt_size);
