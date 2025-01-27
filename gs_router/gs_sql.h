#include <sqlite3.h>

sqlite3* open_gs_db(const char* db_path);
int is_player_in_gs_db(sqlite3 *db, const char* username);
int validate_player_login(sqlite3* db, const char* u_name, const char* passwd);
int write_player_to_gs_db(sqlite3* db, const char* username, const char* passwd, const char* firstname, const char* lastname, const char* email, const char* country);
int update_player_lastlogin (sqlite3* db, const char* username);
