/*
 *
 * Copyright 2017 Shuouma <dreamcast-talk.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * Game Service SQL functions for Dreamcast
 */

#include <stdlib.h>
#include <sqlite3.h>
#include <assert.h>
#include "../gs_common/gs_common.h"
#include "gs_sql.h"

typedef struct {
  uint32_t trophies;
  uint32_t points;
  uint32_t rank;
  char username[MAX_UNAME_LEN];
} player_t;

static int load_world_record(sqlite3 *db, int track, int mode, const char *column, const char *minmax);

static void sql_error(sqlite3 *db, const char *what)
{
  const char *errmsg = sqlite3_errmsg(db);
  if (errmsg == NULL)
    gs_error("%s: sqlite3 error %d", what, sqlite3_extended_errcode(db));
  else
    gs_error("%s: %s", what, errmsg);
}

sqlite3* open_gs_db(const char* db_path) {
   sqlite3 *db = NULL;
   int rc = 0;
   rc = sqlite3_open_v2(db_path, &db,
		   SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, NULL);
   if(rc) {
     sql_error(db, "Can't open database");
     return NULL;
   }

   sqlite3_busy_timeout(db, 1000);
   
   return db;
}

static void create_player_cars(sqlite3* db, int playerId)
{
  const char* zSql = "INSERT INTO PLAYER_CAR (PLAYER_ID, CAR_NUM) VALUES (?, ?)";

  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK) {
      sql_error(db, "Prepare SQL error");
      sqlite3_finalize(pStmt);
      return;
  }
  rc = sqlite3_bind_int(pStmt, 1, playerId);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int failed");
      sqlite3_finalize(pStmt);
      return;
  }
  for (int carnum = 0; carnum < 10; carnum++)
  {
    rc = sqlite3_bind_int(pStmt, 2, carnum);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int failed");
	break;
    }
    rc = sqlite3_step(pStmt);
    if (rc != SQLITE_DONE) {
	sql_error(db, "Insert failed");
	break;
    }
    if (sqlite3_reset(pStmt) != SQLITE_OK) {
	sql_error(db, "Can't reset the statement");
	break;
    }
  }
  sqlite3_finalize(pStmt);
}

int create_player_record(sqlite3* db, const char* username, int sdo) {
  int rc = 0;
  sqlite3_stmt *pStmt;

  const char* zSql = "INSERT INTO PLAYER_DATA(ID,USERNAME,TOTALPOINTS,TOTALTROPHIES) VALUES (NULL, trim(?), 0, 0);";
  
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sql_error(db, "Prepare SQL error");
    sqlite3_finalize(pStmt);
    return 0;
  }
  
  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    sql_error(db, "Insert failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  
  sqlite3_finalize(pStmt);
  gs_info("Records created successfully for %s", username);
  
  if (sdo)
    create_player_cars(db, (int)sqlite3_last_insert_rowid(db));
  
  return 1;
}

int create_lap_record(sqlite3* db, const char* username, const char* trackname, uint32_t laptime, int mode) {
  int rc = 0;
  sqlite3_stmt *pStmt;
  const char* zSql;
  
  if (mode == SIM_LAP_MODE)
    zSql = "INSERT INTO SIM_LAP_DATA (ID,TRACKNAME,USERNAME,LAPTIME) VALUES (NULL, trim(?), trim(?), ?);";
  else
    zSql = "INSERT INTO LAP_DATA (ID,TRACKNAME,USERNAME,LAPTIME) VALUES (NULL, trim(?), trim(?), ?);";

  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sql_error(db, "Prepare SQL error");
    sqlite3_finalize(pStmt);
    return 0;
  }

   rc = sqlite3_bind_text(pStmt, 1, trackname, (int)strlen(trackname), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  
  rc = sqlite3_bind_text(pStmt, 2, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 3, (int)laptime);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind int failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    sql_error(db, "Insert failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  
  sqlite3_finalize(pStmt);
  gs_info("Laptime record created successfully for %s", username);
  
  return 1;
}

int create_track_record(sqlite3* db, const char* username, const char* trackname, uint32_t tracktime) {
  int rc = 0;
  sqlite3_stmt *pStmt;

  const char* zSql = "INSERT INTO TRACK_DATA (ID,TRACKNAME,USERNAME,TRACKTIME) VALUES (NULL, trim(?), trim(?), ?);";

  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sql_error(db, "Prepare SQL error");
    sqlite3_finalize(pStmt);
    return 0;
  }

   rc = sqlite3_bind_text(pStmt, 1, trackname, (int)strlen(trackname), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  
  rc = sqlite3_bind_text(pStmt, 2, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 3, (int)tracktime);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind int failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    sql_error(db, "Insert failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  
  sqlite3_finalize(pStmt);
  gs_info("Tracktime record created successfully for %s", username);
  
  return 1;
}

int update_player_point(sqlite3* db, const char* username, uint32_t points, uint32_t trophies) {
  int rc = 0;
  sqlite3_stmt *pStmt;

  const char* zSql = "UPDATE PLAYER_DATA SET TOTALPOINTS = ?, TOTALTROPHIES = ?  where USERNAME = trim(?);";

  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sql_error(db, "Prepare SQL error");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 1, (int)points);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind int failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 2, (int)trophies);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind int failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  
  rc = sqlite3_bind_text(pStmt, 3, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    sql_error(db, "Insert failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  
  sqlite3_finalize(pStmt);
  gs_info("Updated [%d:%d] for %s", points, trophies, username);

  return 1;
}


int load_player_record(sqlite3 *db, const char* username, uint32_t *points, uint32_t *trophies) {
  int rc, count = 0;
  sqlite3_stmt *pStmt;
  uint32_t points_tmp = 0, trophies_tmp = 0;

  const char *zSql = "SELECT TOTALPOINTS,TOTALTROPHIES from PLAYER_DATA WHERE USERNAME = trim(?);";
  
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sql_error(db, "Prepare SQL error");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  
  rc = sqlite3_step(pStmt);
  //Getting no lines
  if (rc == SQLITE_DONE) {
    gs_info("Username: %s is missing player record in DB", username);
    count = 2;
  } else if (rc == SQLITE_ROW) {
    points_tmp = (uint32_t)sqlite3_column_int(pStmt, 0);
    trophies_tmp = (uint32_t)sqlite3_column_int(pStmt, 1);
    gs_info("Loaded (%d:%d) for user %s", points_tmp, trophies_tmp, username);
    *points = points_tmp;
    *trophies = trophies_tmp;
    count = 1;
  } else {
    gs_info("Got SQL return %d from sqlite3_step..skip storing", rc);
    count = 0;
  }
  
  sqlite3_finalize(pStmt);
  return count;
}

int load_track_record(sqlite3 *db, char* msg, uint16_t max_pkt_size) {
  int rc, index = 4, nr = 0;
  uint32_t rank = 1;
  uint32_t time = 0;
  sqlite3_stmt *pStmt;

  const char *zSql = "select T1.TRACKNAME, T1.USERNAME, MIN(T1.LAPTIME), T2.USERNAME, T2.TT from lap_data T1 join (select TRACKNAME,USERNAME,MIN(TRACKTIME) as TT from track_data group by TRACKNAME) T2 on T1.TRACKNAME = T2.TRACKNAME group by T2.TRACKNAME;"; 
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sql_error(db, "Prepare SQL error");
    sqlite3_finalize(pStmt);
    return 0;
  }

  while (sqlite3_step(pStmt) == SQLITE_ROW) {
    if ((index + 56) >= max_pkt_size) {
      gs_info("Can't add more to msg");
      sqlite3_finalize(pStmt);
      return 0;
    }
    strncpy(&msg[index], (char*)sqlite3_column_text(pStmt,0), 16);
    strncpy(&msg[index + 16], (char*)sqlite3_column_text(pStmt,1), 16);
    time = (uint32_t)sqlite3_column_int(pStmt,2);
    memcpy(&msg[index + 32], &time, sizeof(uint32_t));

    strncpy(&msg[index + 36], (char*)sqlite3_column_text(pStmt,3), 16);
    time = (uint32_t)sqlite3_column_int(pStmt,4);
    memcpy(&msg[index + 52], &time, sizeof(uint32_t));
    
    index += 56;
    nr++;
    rank = (uint32_t)(rank + 1);
  }
  
  memcpy(&msg[0], &nr, sizeof(uint32_t));
  
  sqlite3_finalize(pStmt);
  
  return (index);
}

int load_topscores_record(sqlite3 *db, char* msg, uint16_t max_pkt_size) {
  int rc, index = 4, nr = 0;
  uint32_t rank = 1;
  uint32_t tot_p = 0, tot_t = 0;
  sqlite3_stmt *pStmt;

  const char *zSql = "SELECT USERNAME,TOTALPOINTS,TOTALTROPHIES from PLAYER_DATA ORDER BY TOTALPOINTS DESC LIMIT 10;"; 
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sql_error(db, "Prepare SQL error");
    sqlite3_finalize(pStmt);
    return 0;
  }

  while (sqlite3_step(pStmt) == SQLITE_ROW) {
    if ((index + 28) >= max_pkt_size) {
      gs_info("Can't add more to msg");
      sqlite3_finalize(pStmt);
      return 0;
    }
    strncpy(&msg[index], (char*)sqlite3_column_text(pStmt,0), 16);
    memcpy(&msg[index + 16], &rank, sizeof(uint32_t));
    tot_p = (uint32_t)sqlite3_column_int(pStmt,1);
    tot_t = (uint32_t)sqlite3_column_int(pStmt,2);
    memcpy(&msg[index + 20], &tot_p, sizeof(uint32_t));
    memcpy(&msg[index + 24], &tot_t, sizeof(uint32_t));
    index += 28;
    nr++;
    rank = (uint32_t)(rank + 1);
  }
  
  memcpy(&msg[0], &nr, sizeof(uint32_t));
  
  sqlite3_finalize(pStmt);
  return (index);
}

int load_fivescoreafter_record(sqlite3 *db, const char* username, char* msg, uint16_t max_pkt_size) {
  int rc, index = 4, nr = 0, hit = 0;
  uint32_t rank = 1;
  uint32_t points = 0, trophies = 0;
  sqlite3_stmt *pStmt;

  const char *zSql = "SELECT USERNAME,TOTALPOINTS,TOTALTROPHIES from PLAYER_DATA ORDER BY TOTALPOINTS DESC;"; 
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sql_error(db, "Prepare SQL error");
    sqlite3_finalize(pStmt);
    return 0;
  }

  while (sqlite3_step(pStmt) == SQLITE_ROW) {

    if(strcmp(username, (char*)sqlite3_column_text(pStmt,0)) == 0) {
      gs_info("Found player %s on line %d", username, rank);
      hit = 1;      
    }
    
    if (hit == 1) {
      if ((index + 28) >= max_pkt_size) {
	gs_info("Can't add more to msg");
	sqlite3_finalize(pStmt);
	return 0;
      }     
      strncpy(&msg[index], (char*)sqlite3_column_text(pStmt,0), 16);
      memcpy(&msg[index + 16], &rank, sizeof(uint32_t));
      points = (uint32_t)sqlite3_column_int(pStmt,1);
      trophies = (uint32_t)sqlite3_column_int(pStmt,2);
      memcpy(&msg[index + 20], &points, sizeof(uint32_t));
      memcpy(&msg[index + 24], &trophies, sizeof(uint32_t));
      index += 28;
      nr++;
      rank = (uint32_t)(rank + 1);
    } else {
      rank = (uint32_t)(rank + 1);
    }
    if (nr >= 5) {
      break;
    }
    
  }
  memcpy(&msg[0], &nr, sizeof(uint32_t));
  
  gs_info("Found %d players after %s", nr, username);
  sqlite3_finalize(pStmt);
  return (index);
}

int load_fivescorebefore_record(sqlite3 *db, const char* username, char* msg, uint16_t max_pkt_size) {
  int rc, index = 4, nr = 0, hit = 0, i = 0;
  uint32_t rank = 1;
  sqlite3_stmt *pStmt;
  uint16_t max_players = 0;

  const char *preSql = "SELECT COUNT(*) from PLAYER_DATA;";
  rc = sqlite3_prepare_v2(db, preSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sql_error(db, "Prepare SQL error");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc == SQLITE_ROW ) {
    max_players = (uint16_t)sqlite3_column_int(pStmt, 0);
  }
  sqlite3_finalize(pStmt);

  if(max_players <= 0) {
    gs_error("Could not get max players");
    return 0;
  }
  
  player_t tmp_pl[max_players];
  
  const char *zSql = "SELECT USERNAME,TOTALPOINTS,TOTALTROPHIES from PLAYER_DATA ORDER BY TOTALPOINTS DESC;"; 
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sql_error(db, "Prepare SQL error");
    sqlite3_finalize(pStmt);
    return 0;
  }

  while (sqlite3_step(pStmt) == SQLITE_ROW) {
    if(strcmp(username, (char*)sqlite3_column_text(pStmt,0)) == 0) {
      gs_info("Found player %s on line %d", username, rank);
      hit = 1;
      break;
    } else {
      strncpy(tmp_pl[nr].username, (char*)sqlite3_column_text(pStmt,0), 16);
      tmp_pl[nr].points = (uint32_t)sqlite3_column_int(pStmt,1);
      tmp_pl[nr].trophies = (uint32_t)sqlite3_column_int(pStmt,2);
      tmp_pl[nr].rank = rank;
    }
    nr++;
    rank = (uint32_t)(rank + 1);
  }

  if (hit == 0) {
    gs_info("Could not find player %s", username);
    sqlite3_finalize(pStmt);
    return 0;
  }

  if (nr < 5) {
    for (i = 0; i < nr; i++) {
      if ((index + 28) >= max_pkt_size) {
	gs_info("Can't add more to msg");
	sqlite3_finalize(pStmt);
	return 0;
      }     
      strncpy(&msg[index], tmp_pl[i].username, 16);
      memcpy(&msg[index + 16], &tmp_pl[i].rank, sizeof(uint32_t));
      memcpy(&msg[index + 20], &tmp_pl[i].points, sizeof(uint32_t));
      memcpy(&msg[index + 24], &tmp_pl[i].trophies, sizeof(uint32_t));
      index += 28;
    }
    memcpy(&msg[0], &nr, sizeof(uint32_t));
  } else {
    for (i = (nr-5); i < nr; i++) {
      if ((index + 28) >= max_pkt_size) {
	gs_info("Can't add more to msg");
	sqlite3_finalize(pStmt);
	return 0;
      }     
      strncpy(&msg[index], tmp_pl[i].username, 16);
      memcpy(&msg[index + 16], &tmp_pl[i].rank, sizeof(uint32_t));
      memcpy(&msg[index + 20], &tmp_pl[i].points, sizeof(uint32_t));
      memcpy(&msg[index + 24], &tmp_pl[i].trophies, sizeof(uint32_t));
      index += 28;
    }
    nr = 5;
    memcpy(&msg[0], &nr, sizeof(uint32_t));
  }  
  gs_info("Found %d players before %s", nr, username);
  sqlite3_finalize(pStmt);
  return (index);
}

int load_player_blob(sqlite3 *db, const char* username, const char *blobname, uint8_t *data, unsigned *size)
{
  char zSql[128];
  sprintf(zSql, "SELECT %s from PLAYER_DATA WHERE USERNAME = trim(?)", blobname);

  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sql_error(db, "Prepare SQL error");
    *size = 0;
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    sqlite3_finalize(pStmt);
    *size = 0;
    return 0;
  }

  int count;
  rc = sqlite3_step(pStmt);
  //Getting no lines
  if (rc == SQLITE_DONE) {
    gs_info("Username: %s is missing player record in DB", username);
    *size = 0;
    count = 2;
  } else if (rc == SQLITE_ROW) {
    int len = sqlite3_column_bytes(pStmt, 0);
    if (len > *size)
      len = (int)*size;
    else
      *size = (unsigned)len;
    memcpy(data, sqlite3_column_blob(pStmt, 0), (size_t)len);
    count = 1;
  } else {
    gs_info("Got SQL return %d from sqlite3_step..skip storing", rc);
    *size = 0;
    count = 0;
  }

  sqlite3_finalize(pStmt);
  return count;
}

int load_player_data(sqlite3 *db, const char* username, uint8_t *data, unsigned *size) {
  return load_player_blob(db, username, "PLAYERDATA", data, size);
}

int load_player_fullstats(sqlite3 *db, const char* username, uint8_t *data, int *size)
{
  const char *zSql = "SELECT FULLSTATS, STD_RACES, STD_WINS, TRIAL_RACES, TRIAL_COUNT, TRIAL_WINS, TRIAL_CASH, VENDETTA_WINS, VENDETTA_COUNT "
      "from PLAYER_DATA WHERE USERNAME = trim(?)";

  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sql_error(db, "Prepare SQL error");
    *size = 0;
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    sqlite3_finalize(pStmt);
    *size = 0;
    return 0;
  }

  int count;
  rc = sqlite3_step(pStmt);
  //Getting no lines
  if (rc == SQLITE_DONE) {
    gs_info("Username: %s is missing player record in DB", username);
    *size = 0;
    count = 2;
  } else if (rc == SQLITE_ROW) {
    int len = sqlite3_column_bytes(pStmt, 0);
    if (len > *size)
      len = *size;
    else
      *size = len;
    memcpy(data, sqlite3_column_blob(pStmt, 0), (size_t)len);
    *(int *)&data[408] = sqlite3_column_int(pStmt, 1);	// std races
    *(int *)&data[412] = sqlite3_column_int(pStmt, 2);	// 1st place wins
    *(int *)&data[416] = sqlite3_column_int(pStmt, 3);	// trial races
    *(int *)&data[420] = sqlite3_column_int(pStmt, 4);	// trial bets
    *(int *)&data[424] = sqlite3_column_int(pStmt, 5);	// trials won
    *(int *)&data[428] = sqlite3_column_int(pStmt, 6);	// trial cash won
    *(int *)&data[432] = sqlite3_column_int(pStmt, 7);	// vendetta races
    *(int *)&data[436] = sqlite3_column_int(pStmt, 8);	// vendetta wins
    *(int *)&data[456] = *(int *)&data[408] * 5;	// mystery std avg multiplier (divided by std_races * 5 by the game)
    rc = -1;
    memcpy(&data[460], &rc, sizeof(int));	// favorite track mode
    memcpy(&data[464], &rc, sizeof(int));	// favorite track
    sqlite3_finalize(pStmt);
    // Favorite track mode
    rc = sqlite3_prepare_v2(db, "SELECT RACE_MODE, SUM(RACE_COUNT) AS total_count "
	"FROM TRACK_RECORD "
	"WHERE USERNAME = trim(?) "
	"GROUP BY RACE_MODE "
	"ORDER BY total_count DESC "
	"LIMIT 1", -1, &pStmt, 0);
    if (rc != SQLITE_OK ) {
      sql_error(db, "Favorite track mode prepare SQL error");
    }
    else {
      rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
      if (rc != SQLITE_OK)
	sql_error(db, "Bind username failed");
      rc = sqlite3_step(pStmt);
      if (rc == SQLITE_ROW) {
	int track = sqlite3_column_int(pStmt, 0);
	memcpy(&data[460], &track, sizeof(int));	// favorite track mode
      }
    }
    sqlite3_finalize(pStmt);
    // Favorite track
    rc = sqlite3_prepare_v2(db, "SELECT TRACK, SUM(RACE_COUNT) AS total_count "
	"FROM TRACK_RECORD "
	"WHERE USERNAME = trim(?) "
	"GROUP BY TRACK "
	"ORDER BY total_count DESC "
	"LIMIT 1", -1, &pStmt, 0);
    if (rc != SQLITE_OK ) {
      sql_error(db, "Favorite track prepare SQL error");
    }
    else {
      rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
      if (rc != SQLITE_OK)
	sql_error(db, "Bind username failed");
      rc = sqlite3_step(pStmt);
      if (rc == SQLITE_ROW) {
	int track = sqlite3_column_int(pStmt, 0);
	memcpy(&data[464], &track, sizeof(int));	// favorite track
      }
    }
    count = 1;
  } else {
    gs_info("Got SQL return %d from sqlite3_step..skip storing", rc);
    *size = 0;
    count = 0;
  }

  sqlite3_finalize(pStmt);
  return count;
}

int update_player_blob(sqlite3 *db, const char* username, const char *blobname, const uint8_t *data, int size)
{
  char zSql[128];
  sprintf(zSql, "UPDATE PLAYER_DATA SET %s = ? WHERE USERNAME = trim(?)", blobname);

  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sql_error(db, "Prepare SQL error");
    return 0;
  }

  rc = sqlite3_bind_blob(pStmt, 1, data, size, SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind blob failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 2, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    sql_error(db, "Update failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  sqlite3_finalize(pStmt);

  return 1;
}

int update_player_data(sqlite3 *db, const char* username, const uint8_t *data, int size)
{
  int driving_points = *(int *)&data[0];
  int cash = *(int *)&data[4];
  int class = *(int *)&data[12];
  if (driving_points == 99999999 ||  cash == 99999999) {
    gs_error("*** Cheating *** User %s: %d points, cash $%d", username, driving_points, cash);
    return -1;
  }

  char *zSql = "UPDATE PLAYER_DATA SET PLAYERDATA = ?, CLASS = ?, DRIVING_POINTS = ?, CASH = ? WHERE USERNAME = trim(?)";

  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sql_error(db, "Prepare SQL error");
    return 0;
  }

  rc = sqlite3_bind_blob(pStmt, 1, data, size, SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind PLAYERDATA failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 2, class);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind CLASS failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  rc = sqlite3_bind_int(pStmt, 3, driving_points);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind DRIVING_POINTS failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  rc = sqlite3_bind_int(pStmt, 4, cash);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind CASH failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 5, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind USERNAME failed");
    sqlite3_finalize(pStmt);
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    sql_error(db, "Update PLAYER_DATA failed");
    sqlite3_finalize(pStmt);
    return 0;
  }
  sqlite3_finalize(pStmt);
  gs_info("Player data updated for %s: %d pts class %c cash $%d", username, driving_points, 'D' - class, cash);

  return 1;
}

int update_player_fullstats(sqlite3 *db, const char* username, const uint8_t *data, int size) {
  return update_player_blob(db, username, "FULLSTATS", data, size);
}

int load_player_car(sqlite3 *db, const char* username, int carnum, uint8_t *data, unsigned *size)
{
  const char *zSql = "SELECT CARDATA from PLAYER_CAR "
      "INNER JOIN PLAYER_DATA ON PLAYER_DATA.ID = PLAYER_CAR.PLAYER_ID "
      "WHERE PLAYER_DATA.USERNAME = trim(?) AND PLAYER_CAR.CAR_NUM = ?";

  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sql_error(db, "Prepare SQL error");
    *size = 0;
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    sqlite3_finalize(pStmt);
    *size = 0;
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 2, carnum);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind int failed");
    sqlite3_finalize(pStmt);
    *size = 0;
    return 0;
  }

  int count;
  rc = sqlite3_step(pStmt);
  //Getting no lines
  if (rc == SQLITE_DONE) {
    //gs_info("Username: %s is missing car in DB", username);
    *size = 0;
    count = 2;
  } else if (rc == SQLITE_ROW) {
    int len = sqlite3_column_bytes(pStmt, 0);
    if (len > *size)
      len = (int)*size;
    else
      *size = (unsigned)len;
    memcpy(data, sqlite3_column_blob(pStmt, 0), (size_t)len);
    count = 1;
  } else {
    gs_info("Got SQL return %d from sqlite3_step..skip storing", rc);
    *size = 0;
    count = 0;
  }

  sqlite3_finalize(pStmt);
  return count;
}

int update_player_car(sqlite3 *db, const char* username, int carnum, const uint8_t *data, int size)
{
  const char *zSql = "SELECT ID FROM PLAYER_DATA WHERE USERNAME = trim(?)";
  int ret = 0;
  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sql_error(db, "Prepare SQL error");
    return ret;
  }
  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind int failed");
    goto exit;
  }
  rc = sqlite3_step(pStmt);
  int playerId = 0;
  if (rc == SQLITE_ROW) {
    playerId = sqlite3_column_int(pStmt, 0);
  }
  else {
    gs_info("Username: %s is missing in update player_car", username);
    goto exit;
  }
  sqlite3_finalize(pStmt);

  zSql = "UPDATE PLAYER_CAR SET CARDATA = ? WHERE PLAYER_ID = ? AND CAR_NUM = ?";
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sql_error(db, "Prepare SQL error");
    return ret;
  }

  rc = sqlite3_bind_blob(pStmt, 1, data, size, SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind blob failed");
    goto exit;
  }

  rc = sqlite3_bind_int(pStmt, 2, playerId);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind text failed");
    goto exit;
  }

  rc = sqlite3_bind_int(pStmt, 3, carnum);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind int failed");
    goto exit;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    sql_error(db, "Update failed");
    goto exit;
  }
  ret = 1;

exit:
  sqlite3_finalize(pStmt);
  return ret;
}

int load_price_list(sqlite3 *db, int type, uint32_t *prices, int size)
{
  const char *zSql = "SELECT ITEM_ID, PRICE FROM PRICE_LIST WHERE ITEM_TYPE = ?";
  int ret = 0;
  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sql_error(db, "Prepare SQL error");
    return ret;
  }
  rc = sqlite3_bind_int(pStmt, 1, type);
  if (rc != SQLITE_OK) {
    sql_error(db, "Bind int failed");
    goto exit;
  }
  while ((rc = sqlite3_step(pStmt)) == SQLITE_ROW) {
    int id = sqlite3_column_int(pStmt, 0);
    if (id >= size) {
      gs_error("load_price_list: list too small");
      goto exit;
    }
    prices[id] = (uint32_t)sqlite3_column_int(pStmt, 1);
  }
  if (rc != SQLITE_DONE) {
    sql_error(db, "SELECT failed");
    goto exit;
  }
  ret = 1;

exit:
  sqlite3_finalize(pStmt);
  return ret;
}

int load_game_defines(sqlite3 *db, int *values, int size)
{
  const char *zSql = "SELECT DEFNUM, DEFVALUE FROM GAME_DEFINES WHERE DEFNUM >= 0";
  int ret = 0;
  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
      sql_error(db, "Prepare SQL error");
      return ret;
  }
  while ((rc = sqlite3_step(pStmt)) == SQLITE_ROW) {
      int id = sqlite3_column_int(pStmt, 0);
      if (id >= size) {
	  gs_error("load_game_defines: list too small");
	  goto exit;
      }
      values[id] = sqlite3_column_int(pStmt, 1);
  }
  if (rc != SQLITE_DONE) {
      sql_error(db, "SELECT failed");
      goto exit;
  }
  ret = 1;

exit:
  sqlite3_finalize(pStmt);
  return ret;
}

int load_initial_cash(sqlite3 *db)
{
  const char *zSql = "SELECT DEFVALUE FROM GAME_DEFINES WHERE DEFNUM = -1";
  int ret = 10000;
  sqlite3_stmt *pStmt;
  if (sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0) != SQLITE_OK) {
      sql_error(db, "Prepare SQL error");
      return ret;
  }
  if (sqlite3_step(pStmt) == SQLITE_ROW)
    ret = sqlite3_column_int(pStmt, 0);

  sqlite3_finalize(pStmt);
  return ret;
}

int load_motd(sqlite3 *db, char *text, int size)
{
  const char *zSql = "SELECT MOTD FROM MOTD";
  memset(text, 0, (size_t)size);
  sqlite3_stmt *pStmt;
  if (sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0) != SQLITE_OK) {
      sql_error(db, "Prepare SQL error");
      return 0;
  }
  int ret = 0;
  if (sqlite3_step(pStmt) == SQLITE_ROW) {
      ret = 1;
      strncpy(text, (char *)sqlite3_column_text(pStmt, 0), (size_t)(size - 1));
  }
  sqlite3_finalize(pStmt);
  return ret;
}

int update_std_race(sqlite3 *db, char *username, int races, int wins)
{
  const char *zSql = "UPDATE PLAYER_DATA SET STD_RACES = ?, STD_WINS = ? WHERE USERNAME = trim(?)";
  sqlite3_stmt *pStmt;
  if (sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0) != SQLITE_OK) {
      sql_error(db, "Prepare SQL error");
      return 0;
  }
  int ret = 0;
  int rc = sqlite3_bind_int(pStmt, 1, races);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int1 failed");
      goto exit;
  }
  rc = sqlite3_bind_int(pStmt, 2, wins);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int2 failed");
      goto exit;
  }
  rc = sqlite3_bind_text(pStmt, 3, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind text failed");
      goto exit;
  }
  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
      sql_error(db, "Update failed");
      goto exit;
  }
  ret = 1;
  gs_info("Player %s: %d standard races, %d victories", username, races, wins);

exit:
  sqlite3_finalize(pStmt);
  return ret;
}

int update_trial_race(sqlite3 *db, char *username, int races, int trials, int wins, int cash_won)
{
  const char *zSql = "UPDATE PLAYER_DATA SET "
      "TRIAL_RACES = ?, "
      "TRIAL_WINS = ?, "
      "TRIAL_COUNT = ?, "
      "TRIAL_CASH = ? "
      "WHERE USERNAME = trim(?)";
  sqlite3_stmt *pStmt;
  if (sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0) != SQLITE_OK) {
      gs_error("Prepare SQL error");
      return 0;
  }
  int ret = 0;
  int rc = sqlite3_bind_int(pStmt, 1, races);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int1 failed");
      goto exit;
  }
  rc = sqlite3_bind_int(pStmt, 2, wins);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int2 failed");
      goto exit;
  }
  rc = sqlite3_bind_int(pStmt, 3, trials);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int3 failed");
      goto exit;
  }
  rc = sqlite3_bind_int(pStmt, 4, cash_won);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int4 failed");
      goto exit;
  }
  rc = sqlite3_bind_text(pStmt, 5, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind text failed");
      goto exit;
  }
  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
      sql_error(db, "Update failed");
      goto exit;
  }
  ret = 1;
  gs_info("Player %s: %d trial races, %d/%d wins, $%d cash", username, races, wins, trials, cash_won);

exit:
  sqlite3_finalize(pStmt);
  return ret;
}

int update_vendetta_race(sqlite3 *db, char *username, int races, int wins)
{
  const char *zSql = "UPDATE PLAYER_DATA SET VENDETTA_COUNT = ?, VENDETTA_WINS = ? WHERE USERNAME = trim(?)";
  sqlite3_stmt *pStmt;
  if (sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0) != SQLITE_OK) {
      sql_error(db, "Prepare SQL error");
      return 0;
  }
  int ret = 0;
  int rc = sqlite3_bind_int(pStmt, 1, races);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int1 failed");
      goto exit;
  }
  rc = sqlite3_bind_int(pStmt, 2, wins);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int2 failed");
      goto exit;
  }
  rc = sqlite3_bind_text(pStmt, 3, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind text failed");
      goto exit;
  }
  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
      sql_error(db, "Update failed");
      goto exit;
  }
  ret = 1;
  gs_info("Player %s: %d vendetta races, %d wins", username, races, wins);

exit:
  sqlite3_finalize(pStmt);
  return ret;
}

int update_track_record(sqlite3 *db, char *username, int track, int mode, int lap_time, int race_time, int max_speed)
{
  if (lap_time == 0)
    lap_time = -1;
  if (race_time == 0)
    race_time = -1;
  if (max_speed == 0)
    max_speed = -1;
  if (lap_time == -1 && race_time == -1 && max_speed == -1)
    return 0;
  int ret = -1;
  sqlite3_stmt *pStmt;
  if (sqlite3_prepare_v2(db,
      "SELECT LAP_TIME, RACE_TIME, MAX_SPEED, RACE_COUNT FROM TRACK_RECORD "
      "WHERE USERNAME = trim(?) AND TRACK = ? AND RACE_MODE = ?", -1, &pStmt, 0) != SQLITE_OK) {
      sql_error(db, "Prepare SQL error");
      return -1;
  }
  int rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind text failed");
      goto exit;
  }
  rc = sqlite3_bind_int(pStmt, 2, track);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int1 failed");
      goto exit;
  }
  rc = sqlite3_bind_int(pStmt, 3, mode);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int2 failed");
      goto exit;
  }
  rc = sqlite3_step(pStmt);
  if (rc == SQLITE_DONE)
  {
    // No track record for this user
    sqlite3_finalize(pStmt);
    if (sqlite3_prepare_v2(db, "INSERT INTO TRACK_RECORD "
	"(USERNAME, TRACK, RACE_MODE, LAP_TIME, RACE_TIME, MAX_SPEED, RACE_COUNT) VALUES (?, ?, ?, ?, ?, ?, 1)", -1, &pStmt, 0) != SQLITE_OK) {
      gs_error("Prepare SQL INSERT error");
    }
    rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind text failed");
	goto exit;
    }
    rc = sqlite3_bind_int(pStmt, 2, track);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int1 failed");
	goto exit;
    }
    rc = sqlite3_bind_int(pStmt, 3, mode);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int2 failed");
	goto exit;
    }
    rc = sqlite3_bind_int(pStmt, 4, lap_time);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int3 failed");
	goto exit;
    }
    rc = sqlite3_bind_int(pStmt, 5, race_time);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int4 failed");
	goto exit;
    }
    rc = sqlite3_bind_int(pStmt, 6, max_speed);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int5 failed");
	goto exit;
    }
    rc = sqlite3_step(pStmt);
    if (rc != SQLITE_DONE) {
	sql_error(db, "INSERT failed");
	goto exit;
    }
    ret = 0;
  }
  else if (rc == SQLITE_ROW)
  {
    int best_laptime = sqlite3_column_int(pStmt, 0);
    int best_racetime = sqlite3_column_int(pStmt, 1);
    int best_speed = sqlite3_column_int(pStmt, 2);
    int count = sqlite3_column_int(pStmt, 3);
    int records = 0;
    if (lap_time != -1 && (best_laptime == -1 || lap_time < best_laptime))
      records |= 1;
    if (race_time != -1 && (best_racetime == -1 || race_time < best_racetime))
      records |= 2;
    if (max_speed > best_speed)
      records |= 4;

    sqlite3_finalize(pStmt);
    if (sqlite3_prepare_v2(db,
	"UPDATE TRACK_RECORD SET LAP_TIME = ?, RACE_TIME = ?, MAX_SPEED = ?, RACE_COUNT = ? "
	"WHERE USERNAME = trim(?) AND TRACK = ? AND RACE_MODE = ?", -1, &pStmt, 0) != SQLITE_OK) {
      gs_error("Prepare SQL UPDATE error");
    }
    rc = sqlite3_bind_int(pStmt, 1, (records & 1) ? lap_time : best_laptime);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int1 failed");
	goto exit;
    }
    rc = sqlite3_bind_int(pStmt, 2, (records & 2) ? race_time : best_racetime);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int2 failed");
	goto exit;
    }
    rc = sqlite3_bind_int(pStmt, 3, (records & 4) ? max_speed : best_speed);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int3 failed");
	goto exit;
    }
    rc = sqlite3_bind_int(pStmt, 4, count + 1);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int4 failed");
	goto exit;
    }
    rc = sqlite3_bind_text(pStmt, 5, username, (int)strlen(username), SQLITE_STATIC);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind text failed");
	goto exit;
    }
    rc = sqlite3_bind_int(pStmt, 6, track);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int5 failed");
	goto exit;
    }
    rc = sqlite3_bind_int(pStmt, 7, mode);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind int6 failed");
	goto exit;
    }
    rc = sqlite3_step(pStmt);
    if (rc != SQLITE_DONE) {
	sql_error(db, "UPDATE failed");
	goto exit;
    }
    if (best_laptime == -1)
      records &= ~1;
    if (best_racetime == -1)
      records &= ~2;
    if (best_speed == -1)
      records &= ~4;
    ret = records;
  }
  int wr_laptime = load_best_lap(db, track, mode);
  if (wr_laptime != -1 && wr_laptime == lap_time)
    ret |= 0x10;
  int wr_racetime = load_world_record(db, track, mode, "RACE_TIME", "MIN");
  if (wr_racetime != -1 && wr_racetime == race_time)
    ret |= 0x20;
  int wr_maxspeed = load_world_record(db, track, mode, "MAX_SPEED", "MAX");
  if (wr_maxspeed != -1 && wr_maxspeed == max_speed)
    ret |= 0x40;
  gs_info("Player %s: track %d mode %d record: laptime %x racetime %x maxspeed %x record_flags %x",
	  username, track, mode, lap_time, race_time, max_speed, ret);

exit:
  sqlite3_finalize(pStmt);

  return ret;
}

static int load_world_record(sqlite3 *db, int track, int mode, const char *column, const char *minmax)
{
  char sql[256];
  sprintf(sql, "SELECT %s(%s) FROM TRACK_RECORD "
      "WHERE TRACK = ? AND RACE_MODE = ? AND %s != -1", minmax, column, column);
  sqlite3_stmt *pStmt;
  if (sqlite3_prepare_v2(db, sql, -1, &pStmt, 0) != SQLITE_OK) {
      sql_error(db, "Prepare SQL error");
      return -1;
  }
  int ret = -1;
  int rc = sqlite3_bind_int(pStmt, 1, track);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int1 failed");
      goto exit;
  }
  rc = sqlite3_bind_int(pStmt, 2, mode);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int2 failed");
      goto exit;
  }
  rc = sqlite3_step(pStmt);
  if (rc == SQLITE_ROW && sqlite3_column_type(pStmt, 0) == SQLITE_INTEGER)
    ret = sqlite3_column_int(pStmt, 0);

exit:
  sqlite3_finalize(pStmt);
  return ret;
}

int load_best_lap(sqlite3 *db, int track, int mode) {
  return load_world_record(db, track, mode, "LAP_TIME", "MIN");
}

int load_top3_record(sqlite3 *db, int track, int mode, int class, char *buf, const char *column, const char *order)
{
  buf[0] = (char)0;
  char sql[512];
  if (class == 4)
    sprintf(sql, "SELECT USERNAME, %s "
	"FROM TRACK_RECORD "
	"WHERE TRACK = :track AND RACE_MODE = :mode AND %s != -1 "
	"ORDER BY %s %s LIMIT 3",
	column, column, column, order);
  else
    sprintf(sql, "SELECT TRACK_RECORD.USERNAME, %s "
	"FROM TRACK_RECORD INNER JOIN PLAYER_DATA ON PLAYER_DATA.USERNAME = TRACK_RECORD.USERNAME "
	"WHERE TRACK = :track AND RACE_MODE = :mode AND %s != -1 AND PLAYER_DATA.CLASS = :class "
	"ORDER BY %s %s LIMIT 3",
	column, column, column, order);
  sqlite3_stmt *pStmt;
  if (sqlite3_prepare_v2(db, sql, -1, &pStmt, 0) != SQLITE_OK) {
      sql_error(db, "Prepare SQL error");
      return 0;
  }
  int ret = 0;
  int rc = sqlite3_bind_int(pStmt, sqlite3_bind_parameter_index(pStmt, ":track"), track);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind track failed");
      goto exit;
  }
  rc = sqlite3_bind_int(pStmt, sqlite3_bind_parameter_index(pStmt, ":mode"), mode);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind mode failed");
      goto exit;
  }
  if (class != 4) {
    int rc = sqlite3_bind_int(pStmt, sqlite3_bind_parameter_index(pStmt, ":class"), class);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind class failed");
	goto exit;
    }
  }
  char *p = buf + 1;
  while (sqlite3_step(pStmt) == SQLITE_ROW)
  {
    strcpy(p, (const char *)sqlite3_column_text(pStmt, 0));
    p += 16;
    int best = sqlite3_column_int(pStmt, 1);
    memcpy(p, &best, 4);
    p += 4;
    buf[0] = (char)(buf[0] + 1);
  }
  ret = buf[0];

exit:
  sqlite3_finalize(pStmt);
  return ret;
}

int load_sdo_track_record(sqlite3 *db, char *username, int track, int mode, int class, char *buf)
{
  memset(buf, 0, 6);
  sqlite3_stmt *pStmt;
  if (sqlite3_prepare_v2(db, "SELECT LAP_TIME, RACE_TIME, MAX_SPEED "
      "FROM TRACK_RECORD "
      "WHERE USERNAME = trim(?) AND TRACK = ? AND RACE_MODE = ?", -1, &pStmt, 0) != SQLITE_OK) {
    gs_error("Prepare SQL error");
    return 6;
  }
  int rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind text failed");
      goto exit;
  }
  rc = sqlite3_bind_int(pStmt, 2, track);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int1 failed");
      goto exit;
  }
  rc = sqlite3_bind_int(pStmt, 3, mode);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind int2 failed");
      goto exit;
  }
  int best_lap = -1;
  int best_race = -1;
  int max_speed = -1;
  if (sqlite3_step(pStmt) == SQLITE_ROW) {
    best_lap = sqlite3_column_int(pStmt, 0);
    best_race = sqlite3_column_int(pStmt, 1);
    max_speed = sqlite3_column_int(pStmt, 2);
  }
  sqlite3_finalize(pStmt);

  char *p = buf;
  int ret = load_top3_record(db, track, mode, class, p, "RACE_TIME", "ASC");
  p += ret * 20 + 1;
  if (best_race != -1) {
    *p++ = 1;
    strcpy(p, username);
    p += 16;
    memcpy(p, &best_race, 4);
    p += 4;
  }
  else {
    *p++ = 0;
  }
  ret = load_top3_record(db, track, mode, class, p, "MAX_SPEED", "DESC");
  p += ret * 20 + 1;
  if (max_speed != -1) {
    *p++ = 1;
    strcpy(p, username);
    p += 16;
    memcpy(p, &max_speed, 4);
    p += 4;
  }
  else {
    *p++ = 0;
  }
  ret = load_top3_record(db, track, mode, class, p, "LAP_TIME", "ASC");
  p += ret * 20 + 1;
  if (best_lap != -1) {
    *p++ = 1;
    strcpy(p, username);
    p += 16;
    memcpy(p, &best_lap, 4);
    p += 4;
  }
  else {
    *p++ = 0;
  }
  return (int)(p - buf);

exit:
  sqlite3_finalize(pStmt);
  return 6;
}

int load_hall_of_fame(sqlite3 *db, char *username, int type, int class, char *buf)
{
  const char *qcol;
  switch (type)
  {
    case 0: qcol = "driving_points"; break;
    case 1: qcol = "cash"; break;
    case 2: qcol = "driving_points / std_races"; break;
    case 3: qcol = "std_wins"; break;
    case 4: qcol = "trial_wins / trial_count * 1000000"; break;
    case 5: qcol = "trial_cash"; break;
    case 6: qcol = "vendetta_wins / vendetta_count * 1000000"; break;
    case 7: qcol = "vendetta_wins"; break;
    default: qcol = "null"; break;
  }
  // Zone 0: top 10
  char sql[512];
  sprintf(sql, "SELECT username, %s v, RANK() OVER (ORDER BY %s DESC) rnk FROM player_data WHERE v != 0 %s ORDER BY rnk LIMIT 10", qcol, qcol,
	  class == 4 ? "" : "AND class = :class");
  sqlite3_stmt *pStmt;
  if (sqlite3_prepare_v2(db, sql, -1, &pStmt, 0) != SQLITE_OK) {
      sql_error(db, "Prepare SQL error");
      goto exit;
  }
  if (class != 4) {
    int rc = sqlite3_bind_int(pStmt, sqlite3_bind_parameter_index(pStmt, ":class"), class);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind class failed");
	goto exit;
    }
  }
  int ranks[31];
  unsigned nranks = 0;
  char *p = buf;
  char *zone_count = p;
  *zone_count = 0;
  p += 1;
  int current_user_seen = 0;
  while (sqlite3_step(pStmt) == SQLITE_ROW && *zone_count < 10) {
    strcpy(p, (const char *)sqlite3_column_text(pStmt, 0));
    if (!strcmp(p, username))
      current_user_seen = 1;
    p += 16;
    int score = sqlite3_column_int(pStmt, 1);
    memcpy(p, &score, 4);
    p += 4;
    *zone_count = (char)(*zone_count + 1);
    ranks[nranks++] = sqlite3_column_int(pStmt, 2);
  }
  sqlite3_finalize(pStmt);
  if (current_user_seen == 1)
  {
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
  }
  else
  {
    // Zone 2: current user
    sprintf(sql, "SELECT * FROM (SELECT username, %s v, RANK() OVER (ORDER BY %s DESC) rnk FROM player_data WHERE v != 0 %s) WHERE username = trim(:username)", qcol, qcol,
	    class == 4 ? "" : "AND class = :class");
    if (sqlite3_prepare_v2(db, sql, -1, &pStmt, 0) != SQLITE_OK) {
	sql_error(db, "Prepare SQL error");
	goto exit;
    }
    if (class != 4) {
      int rc = sqlite3_bind_int(pStmt, sqlite3_bind_parameter_index(pStmt, ":class"), class);
      if (rc != SQLITE_OK) {
	  sql_error(db, "Bind class failed");
	  goto exit;
      }
    }
    int rc = sqlite3_bind_text(pStmt, sqlite3_bind_parameter_index(pStmt, ":username"), username, (int)strlen(username), SQLITE_STATIC);
    if (rc != SQLITE_OK) {
	sql_error(db, "Bind username failed");
	goto exit;
    }
    if (sqlite3_step(pStmt) != SQLITE_ROW) {
      sqlite3_finalize(pStmt);
      *p++ = 0;
      *p++ = 0;
      *p++ = 0;
    }
    else {
      int user_score = sqlite3_column_int(pStmt, 1);
      int user_rank = sqlite3_column_int(pStmt, 2);
      sqlite3_finalize(pStmt);
      // Zone 1: 5 ranks before user
      sprintf(sql, "SELECT * FROM (SELECT username, %s v, RANK() OVER (ORDER BY %s DESC) rnk FROM player_data WHERE v != 0 %s) WHERE rnk < :rank ORDER BY rnk DESC LIMIT 5", qcol, qcol,
	      class == 4 ? "" : "AND class = :class");
      if (sqlite3_prepare_v2(db, sql, -1, &pStmt, 0) != SQLITE_OK) {
	  sql_error(db, "Prepare SQL error");
	  goto exit;
      }
      if (class != 4) {
        rc = sqlite3_bind_int(pStmt, sqlite3_bind_parameter_index(pStmt, ":class"), class);
        if (rc != SQLITE_OK) {
            sql_error(db, "Bind class failed");
            goto exit;
        }
      }
      rc = sqlite3_bind_int(pStmt, sqlite3_bind_parameter_index(pStmt, ":rank"), user_rank);
      if (rc != SQLITE_OK) {
	  sql_error(db, "Bind user_rank failed");
	  goto exit;
      }
      zone_count = p;
      *zone_count = 0;
      p += 1;
      while (sqlite3_step(pStmt) == SQLITE_ROW && *zone_count < 5) {
	strcpy(p, (const char *)sqlite3_column_text(pStmt, 0));
	p += 16;
	int score = sqlite3_column_int(pStmt, 1);
	memcpy(p, &score, 4);
	p += 4;
	*zone_count = (char)(*zone_count + 1);
	ranks[nranks++] = sqlite3_column_int(pStmt, 2);
      }
      sqlite3_finalize(pStmt);
      // Update zone 2
      zone_count = p;
      *zone_count = 1;
      p += 1;
      strcpy(p, username);
      p += 16;
      memcpy(p, &user_score, 4);
      p += 4;
      ranks[nranks++] = user_rank;
      // Zone 3: 5 ranks after current user
      sprintf(sql, "SELECT * FROM (SELECT username, %s v, RANK() OVER (ORDER BY %s DESC) rnk FROM player_data WHERE v != 0 %s) "
	  "WHERE rnk >= :rank and username != trim(:username) ORDER BY rnk LIMIT 5", qcol, qcol,
	  class == 4 ? "" : "AND class = :class");
      if (sqlite3_prepare_v2(db, sql, -1, &pStmt, 0) != SQLITE_OK) {
	  sql_error(db, "Prepare SQL error");
	  goto exit;
      }
      if (class != 4) {
        rc = sqlite3_bind_int(pStmt, sqlite3_bind_parameter_index(pStmt, ":class"), class);
        if (rc != SQLITE_OK) {
            sql_error(db, "Bind class failed");
            goto exit;
        }
      }
      rc = sqlite3_bind_int(pStmt, sqlite3_bind_parameter_index(pStmt, ":rank"), user_rank);
      if (rc != SQLITE_OK) {
	  sql_error(db, "Bind user_rank failed");
	  goto exit;
      }
      rc = sqlite3_bind_text(pStmt, sqlite3_bind_parameter_index(pStmt, ":username"), username, (int)strlen(username), SQLITE_STATIC);
      if (rc != SQLITE_OK) {
	  sql_error(db, "Bind username failed");
	  goto exit;
      }
      zone_count = p;
      *zone_count = 0;
      p += 1;
      while (sqlite3_step(pStmt) == SQLITE_ROW && *zone_count < 5) {
	strcpy(p, (const char *)sqlite3_column_text(pStmt, 0));
	p += 16;
	int score = sqlite3_column_int(pStmt, 1);
	memcpy(p, &score, 4);
	p += 4;
	*zone_count = (char)(*zone_count + 1);
	ranks[nranks++] = sqlite3_column_int(pStmt, 2);
      }
      sqlite3_finalize(pStmt);
    }
  }
  memcpy(p, ranks, nranks * sizeof(int));
  p += nranks * sizeof(int);
  return (int)(p - buf);

exit:
  sqlite3_finalize(pStmt);
  memset(buf, 0, 4);
  return 4;
}

int load_player_scorecard(sqlite3 *db, const char* username, uint32_t *class, uint32_t *points, uint32_t *cash)
{
  *class = *points = *cash = 0;
  sqlite3_stmt *pStmt;
  if (sqlite3_prepare_v2(db, "SELECT CLASS, DRIVING_POINTS, CASH "
      "FROM PLAYER_DATA WHERE USERNAME = trim(?)", -1, &pStmt, 0) != SQLITE_OK) {
      sql_error(db, "Prepare SQL error");
      return -1;
  }
  int ret = -1;
  int rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
      sql_error(db, "Bind username failed");
      goto exit;
  }
  rc = sqlite3_step(pStmt);
  if (rc == SQLITE_ROW) {
    *class = (uint32_t)sqlite3_column_int(pStmt, 0);
    *points = (uint32_t)sqlite3_column_int(pStmt, 1);
    *cash = (uint32_t)sqlite3_column_int(pStmt, 2);
  }
  ret = 0;

exit:
  sqlite3_finalize(pStmt);
  return ret;
}
