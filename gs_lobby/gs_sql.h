#include <sqlite3.h>

sqlite3* open_gs_db(const char* db_path);
int create_player_record(sqlite3* db, const char* username, int sdo);
int create_lap_record(sqlite3* db, const char* username, const char* trackname, uint32_t laptime, int mode);
int create_track_record(sqlite3* db, const char* username, const char* trackname, uint32_t tracktime);
int update_player_point(sqlite3* db, const char* username, uint32_t points, uint32_t trophies);
int load_player_record(sqlite3 *db, const char* username, uint32_t *points, uint32_t *trophies);
int load_topscores_record(sqlite3 *db, char* msg, uint16_t max_pkt_size);
int load_fivescoreafter_record(sqlite3 *db, const char* username, char* msg, uint16_t max_pkt_size);
int load_fivescorebefore_record(sqlite3 *db, const char* username, char* msg, uint16_t max_pkt_size);
int load_track_record(sqlite3 *db, char* msg, uint16_t max_pkt_size);
/* SDO */
int load_player_data(sqlite3 *db, const char* username, uint8_t *data, int *size);
int update_player_data(sqlite3 *db, const char* username, const uint8_t *data, int size);
int load_player_car(sqlite3 *db, const char* username, int carnum, uint8_t *data, int *size);
int update_player_car(sqlite3 *db, const char* username, int carnum, const uint8_t *data, int size);
int load_player_fullstats(sqlite3 *db, const char* username, uint8_t *data, int *size);
int update_player_fullstats(sqlite3 *db, const char* username, const uint8_t *data, int size);
int load_price_list(sqlite3 *db, int type, uint32_t *prices, int size);
int load_game_defines(sqlite3 *db, int *values, int size);
int load_initial_cash(sqlite3 *db);
int load_motd(sqlite3 *db, char *text, int size);
int update_std_race(sqlite3 *db, char *username, int races, int wins);
int update_trial_race(sqlite3 *db, char *username, int races, int trials, int wins, int cash_won);
int update_vendetta_race(sqlite3 *db, char *username, int races, int wins);
int update_track_record(sqlite3 *db, char *username, int track, int mode, int lap_time, int race_time, int max_speed);
int load_best_lap(sqlite3 *db, int track, int mode);
int load_sdo_track_record(sqlite3 *db, char *username, int track, int mode, int class, char *buf);
int load_hall_of_fame(sqlite3 *db, char *username, int type, int class, char *buf);
int load_player_scorecard(sqlite3 *db, const char* username, uint32_t *class, uint32_t *points, uint32_t *cash);
