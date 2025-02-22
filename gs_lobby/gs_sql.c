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

typedef struct {
  uint32_t trophies;
  uint32_t points;
  uint32_t rank;
  char username[MAX_UNAME_LEN];
} player_t;


sqlite3* open_gs_db(const char* db_path) {
   sqlite3 *db = NULL;
   int rc = 0;
   rc = sqlite3_open(db_path, &db);
   if(rc) {
     gs_error("Can't open database: %s", sqlite3_errmsg(db));
     return NULL;
   }

   sqlite3_busy_timeout(db, 1000);
   
   return db;
}

void create_player_cars(sqlite3* db, int playerId)
{
  const char* zSql = "INSERT INTO PLAYER_CAR (PLAYER_ID, CAR_NUM) VALUES (?, ?)";

  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Prepare SQL error: %d", rc);
    return;
  }
  rc = sqlite3_bind_int(pStmt, 1, playerId);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind int failed error: %d", rc);
    return;
  }
  for (int carnum = 0; carnum < 10; carnum++)
  {
    rc = sqlite3_bind_int(pStmt, 2, carnum);
    if (rc != SQLITE_OK) {
      gs_error("Bind int failed error: %d", rc);
      break;
    }
    rc = sqlite3_step(pStmt);
    if (rc != SQLITE_DONE) {
      gs_error("Insert failed error: %d", rc);
      break;
    }
    if (sqlite3_reset(pStmt) != SQLITE_OK) {
      gs_error("Can't reset the statement: %d", rc);
      break;
    }
  }
  sqlite3_finalize(pStmt);
}

int create_player_record(sqlite3* db, const char* username, int sdo) {
  int rc = 0;
  sqlite3_stmt *pStmt;

  sqlite3_mutex_enter(sqlite3_db_mutex(db));
  
  const char* zSql = "INSERT INTO PLAYER_DATA(ID,USERNAME,TOTALPOINTS,TOTALTROPHIES) VALUES (NULL, trim(?), 0, 0);";
  
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error( "Prepare SQL error: %d", rc);
    return 0;
  }
  
  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Bind text failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    gs_error("Insert failed error: %d", rc);
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }
  
  sqlite3_finalize(pStmt);
  gs_info("Records created successfully for %s", username);
  
  if (sdo)
    create_player_cars(db, (int)sqlite3_last_insert_rowid(db));
  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  
  return 1;
}

int create_lap_record(sqlite3* db, const char* username, const char* trackname, uint32_t laptime, int mode) {
  int rc = 0;
  sqlite3_stmt *pStmt;
  const char* zSql;
  
  sqlite3_mutex_enter(sqlite3_db_mutex(db));

  if (mode == SIM_LAP_MODE)
    zSql = "INSERT INTO SIM_LAP_DATA (ID,TRACKNAME,USERNAME,LAPTIME) VALUES (NULL, trim(?), trim(?), ?);";
  else
    zSql = "INSERT INTO LAP_DATA (ID,TRACKNAME,USERNAME,LAPTIME) VALUES (NULL, trim(?), trim(?), ?);";

  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error( "Prepare SQL error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }

   rc = sqlite3_bind_text(pStmt, 1, trackname, (int)strlen(trackname), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }
  
  rc = sqlite3_bind_text(pStmt, 2, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 3, (int)laptime);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind int failed error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    gs_error("Insert failed error: %d", rc);
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }
  
  sqlite3_finalize(pStmt);
  gs_info("Laptime record created successfully for %s", username);

  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  
  return 1;
}

int create_track_record(sqlite3* db, const char* username, const char* trackname, uint32_t tracktime) {
  int rc = 0;
  sqlite3_stmt *pStmt;

  sqlite3_mutex_enter(sqlite3_db_mutex(db));
  
  const char* zSql = "INSERT INTO TRACK_DATA (ID,TRACKNAME,USERNAME,TRACKTIME) VALUES (NULL, trim(?), trim(?), ?);";

  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error( "Prepare SQL error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }

   rc = sqlite3_bind_text(pStmt, 1, trackname, (int)strlen(trackname), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }
  
  rc = sqlite3_bind_text(pStmt, 2, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 3, (int)tracktime);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind int failed error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    gs_error("Insert failed error: %d", rc);
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }
  
  sqlite3_finalize(pStmt);
  gs_info("Tracktime record created successfully for %s", username);

  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  
  return 1;
}

int update_player_point(sqlite3* db, const char* username, uint32_t points, uint32_t trophies) {
  int rc = 0;
  sqlite3_stmt *pStmt;

  sqlite3_mutex_enter(sqlite3_db_mutex(db));
  
  const char* zSql = "UPDATE PLAYER_DATA SET TOTALPOINTS = ?, TOTALTROPHIES = ?  where USERNAME = trim(?);";

  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error( "Prepare SQL error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 1, (int)points);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind int failed error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 2, (int)trophies);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind int failed error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }
  
  rc = sqlite3_bind_text(pStmt, 3, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    gs_error("Insert failed error: %d", rc);
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }
  
  sqlite3_finalize(pStmt);
  gs_info("Updated [%d:%d] for %s", points, trophies, username);

  sqlite3_mutex_leave(sqlite3_db_mutex(db));

  return 1;
}


int load_player_record(sqlite3 *db, const char* username, uint32_t *points, uint32_t *trophies) {
  int rc, count = 0;
  sqlite3_stmt *pStmt;
  uint32_t points_tmp = 0, trophies_tmp = 0;

  sqlite3_mutex_enter(sqlite3_db_mutex(db));
  
  const char *zSql = "SELECT TOTALPOINTS,TOTALTROPHIES from PLAYER_DATA WHERE USERNAME = trim(?);";
  
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Prepare SQL error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Bind text failed error: %d", rc);
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
  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  return count;
}

int load_track_record(sqlite3 *db, char* msg, uint16_t max_pkt_size) {
  int rc, index = 4, nr = 0;
  uint32_t rank = 1;
  uint32_t time = 0;
  sqlite3_stmt *pStmt;

  sqlite3_mutex_enter(sqlite3_db_mutex(db));

  
  const char *zSql = "select T1.TRACKNAME, T1.USERNAME, MIN(T1.LAPTIME), T2.USERNAME, T2.TT from lap_data T1 join (select TRACKNAME,USERNAME,MIN(TRACKTIME) as TT from track_data group by TRACKNAME) T2 on T1.TRACKNAME = T2.TRACKNAME group by T2.TRACKNAME;"; 
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error("Prepare SQL error: %d", rc);
    return 0;
  }

  while (sqlite3_step(pStmt) == SQLITE_ROW) {
    if ((index + 56) >= max_pkt_size) {
      gs_info("Can't add more to msg");
      sqlite3_finalize(pStmt);
      sqlite3_mutex_leave(sqlite3_db_mutex(db));
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

  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  
  return (index);
}

int load_topscores_record(sqlite3 *db, char* msg, uint16_t max_pkt_size) {
  int rc, index = 4, nr = 0;
  uint32_t rank = 1;
  uint32_t tot_p = 0, tot_t = 0;
  sqlite3_stmt *pStmt;

  sqlite3_mutex_enter(sqlite3_db_mutex(db));
 
  const char *zSql = "SELECT USERNAME,TOTALPOINTS,TOTALTROPHIES from PLAYER_DATA ORDER BY TOTALPOINTS DESC LIMIT 10;"; 
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error("Prepare SQL error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
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
  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  return (index);
}

int load_fivescoreafter_record(sqlite3 *db, const char* username, char* msg, uint16_t max_pkt_size) {
  int rc, index = 4, nr = 0, hit = 0;
  uint32_t rank = 1;
  uint32_t points = 0, trophies = 0;
  sqlite3_stmt *pStmt;

  sqlite3_mutex_enter(sqlite3_db_mutex(db));
  
  const char *zSql = "SELECT USERNAME,TOTALPOINTS,TOTALTROPHIES from PLAYER_DATA ORDER BY TOTALPOINTS DESC;"; 
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error("Prepare SQL error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
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
  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  return (index);
}

int load_fivescorebefore_record(sqlite3 *db, const char* username, char* msg, uint16_t max_pkt_size) {
  int rc, index = 4, nr = 0, hit = 0, i = 0;
  uint32_t rank = 1;
  sqlite3_stmt *pStmt;
  uint16_t max_players = 0;

  sqlite3_mutex_enter(sqlite3_db_mutex(db));

  const char *preSql = "SELECT COUNT(*) from PLAYER_DATA;";
  rc = sqlite3_prepare_v2(db, preSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error("Prepare SQL error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc == SQLITE_ROW ) {
    max_players = (uint16_t)sqlite3_column_int(pStmt, 0);
  }
  sqlite3_finalize(pStmt);

  if(max_players <= 0) {
    gs_error("Could not get max players");
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }
  
  player_t tmp_pl[max_players];
  
  const char *zSql = "SELECT USERNAME,TOTALPOINTS,TOTALTROPHIES from PLAYER_DATA ORDER BY TOTALPOINTS DESC;"; 
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error("Prepare SQL error: %d", rc);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
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
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }

  if (nr < 5) {
    for (i = 0; i < nr; i++) {
      if ((index + 28) >= max_pkt_size) {
	gs_info("Can't add more to msg");
	sqlite3_finalize(pStmt);
	sqlite3_mutex_leave(sqlite3_db_mutex(db));
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
	sqlite3_mutex_leave(sqlite3_db_mutex(db));
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
  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  return (index);
}

int load_player_blob(sqlite3 *db, const char* username, const char *blobname, uint8_t *data, int *size)
{
  sqlite3_mutex_enter(sqlite3_db_mutex(db));

  char zSql[128];
  sprintf(zSql, "SELECT %s from PLAYER_DATA WHERE USERNAME = trim(?)", blobname);

  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Prepare SQL error: %d", rc);
    *size = 0;
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Bind text failed error: %d", rc);
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
    memcpy(data, sqlite3_column_blob(pStmt, 0), len);
    count = 1;
  } else {
    gs_info("Got SQL return %d from sqlite3_step..skip storing", rc);
    *size = 0;
    count = 0;
  }

  sqlite3_finalize(pStmt);
  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  return count;
}

int load_player_data(sqlite3 *db, const char* username, uint8_t *data, int *size) {
  return load_player_blob(db, username, "PLAYERDATA", data, size);
}

int load_player_fullstats(sqlite3 *db, const char* username, uint8_t *data, int *size) {
  return load_player_blob(db, username, "FULLSTATS", data, size);
}

int update_player_blob(sqlite3 *db, const char* username, const char *blobname, const uint8_t *data, int size)
{
  sqlite3_mutex_enter(sqlite3_db_mutex(db));

  char zSql[128];
  sprintf(zSql, "UPDATE PLAYER_DATA SET %s = ? WHERE USERNAME = trim(?)", blobname);

  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Prepare SQL error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_blob(pStmt, 1, data, size, SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Bind blob failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 2, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Bind text failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    gs_error("Update failed error: %d", rc);
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }
  sqlite3_finalize(pStmt);
  sqlite3_mutex_leave(sqlite3_db_mutex(db));

  return 1;
}

int update_player_data(sqlite3 *db, const char* username, const uint8_t *data, int size) {
  return update_player_blob(db, username, "PLAYERDATA", data, size);
}

int update_player_fullstats(sqlite3 *db, const char* username, const uint8_t *data, int size) {
  return update_player_blob(db, username, "FULLSTATS", data, size);
}

int load_player_car(sqlite3 *db, const char* username, int carnum, uint8_t *data, int *size)
{
  sqlite3_mutex_enter(sqlite3_db_mutex(db));

  const char *zSql = "SELECT CARDATA from PLAYER_CAR "
      "INNER JOIN PLAYER_DATA ON PLAYER_DATA.ID = PLAYER_CAR.PLAYER_ID "
      "WHERE PLAYER_DATA.USERNAME = trim(?) AND PLAYER_CAR.CAR_NUM = ?";

  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Prepare SQL error: %d", rc);
    *size = 0;
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Bind text failed error: %d", rc);
    *size = 0;
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 2, carnum);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Bind int failed error: %d", rc);
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
      len = *size;
    else
      *size = len;
    memcpy(data, sqlite3_column_blob(pStmt, 0), len);
    count = 1;
  } else {
    gs_info("Got SQL return %d from sqlite3_step..skip storing", rc);
    *size = 0;
    count = 0;
  }

  sqlite3_finalize(pStmt);
  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  return count;
}

int update_player_car(sqlite3 *db, const char* username, int carnum, uint8_t *data, int size)
{
  sqlite3_mutex_enter(sqlite3_db_mutex(db));

  const char *zSql = "SELECT ID FROM PLAYER_DATA WHERE USERNAME = trim(?)";
  sqlite3_stmt *pStmt;
  int rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Prepare SQL error: %d", rc);
    return 0;
  }
  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Bind int failed error: %d", rc);
    return 0;
  }
  rc = sqlite3_step(pStmt);
  int playerId = 0;
  if (rc == SQLITE_ROW) {
    playerId = sqlite3_column_int(pStmt, 0);
  }
  else {
    gs_info("Username: %s is missing in update player_car", username);
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }
  sqlite3_finalize(pStmt);

  zSql = "UPDATE PLAYER_CAR SET CARDATA = ? WHERE PLAYER_ID = ? AND CAR_NUM = ?";
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc != SQLITE_OK ) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Prepare SQL error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_blob(pStmt, 1, data, size, SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Bind blob failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 2, playerId);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Bind text failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_int(pStmt, 3, carnum);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    gs_error("Bind int failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    gs_error("Update failed error: %d", rc);
    sqlite3_finalize(pStmt);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return 0;
  }
  sqlite3_finalize(pStmt);
  sqlite3_mutex_leave(sqlite3_db_mutex(db));

  return 1;
}

