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

int is_player_in_gs_db(sqlite3 *db, const char* username) {
  int rc, count = 0;
  sqlite3_stmt *pStmt;
  
  const char *zSql = "SELECT COUNT(*) from PLAYER_DATA WHERE USERNAME = trim(?);"; 
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error("Prepare SQL error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    return 0;
  }
  
  rc = sqlite3_step(pStmt);
  if (rc == SQLITE_ROW )
    count = sqlite3_column_int(pStmt, 0);
  
  if (count == 1)
    gs_info("Username: %s is registered in the DB", username);
  else {
    gs_info("Username: %s is not in the DB", username);
    count = 2;
  }

  sqlite3_finalize(pStmt);
  return count;
}

int validate_player_login(sqlite3* db, const char* u_name, const char* passwd) {
  int rc, count = 0;
  sqlite3_stmt *pStmt;
  
  const char *zSql = "SELECT COUNT(*) from PLAYER_DATA WHERE USERNAME = trim(?) AND PASSWORD = trim(?);"; 
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error( "Prepare SQL error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 1, u_name, (int)strlen(u_name), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error( "Bind text failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 2, passwd, (int)strlen(passwd), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error( "Bind text failed error: %d", rc);
    return 0;
  } 
  
  rc = sqlite3_step(pStmt);
  if (rc == SQLITE_ROW )
    count = sqlite3_column_int(pStmt, 0);
  
  if (count == 1)
    gs_info("Login granted for %s", u_name);
  else
    gs_info("Login failed for %s", u_name);

  sqlite3_finalize(pStmt);
  return count;
}

int write_player_to_gs_db(sqlite3* db, const char* username, const char* passwd, const char* firstname, const char* lastname, const char* email, const char* country) {
  int rc = 0;
  sqlite3_stmt *pStmt;
  
  const char* zSql = "INSERT INTO PLAYER_DATA (ID,USERNAME,PASSWORD,FIRSTNAME,LASTNAME,EMAIL,COUNTRY,LASTLOGIN) VALUES (NULL, trim(?), trim(?), trim(?), trim(?), trim(?), trim(?), date('now'));";

  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error( "Prepare SQL error: %d", rc);
    return 0;
  }
  
  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 2, passwd, (int)strlen(passwd), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 3, firstname, (int)strlen(firstname), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 4, lastname, (int)strlen(lastname), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 5, email, (int)strlen(email), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_bind_text(pStmt, 6, country, (int)strlen(country), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    return 0;
  }
  
  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    gs_error("Insert failed error: %d", rc);
    sqlite3_finalize(pStmt);
    return 0;
  }
  
  sqlite3_finalize(pStmt);
  gs_info("Records created successfully for %s", username);

  return 1;
}

int update_player_lastlogin (sqlite3* db, const char* username) {
  int rc = 0;
  sqlite3_stmt *pStmt;
  
  const char* zSql = "UPDATE PLAYER_DATA SET LASTLOGIN = date('now') where USERNAME = ?;";

  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc != SQLITE_OK ){
    sqlite3_finalize(pStmt);
    gs_error( "Prepare SQL error: %d", rc);
    return 0;
  }
  
  rc = sqlite3_bind_text(pStmt, 1, username, (int)strlen(username), SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    gs_error("Bind text failed error: %d", rc);
    return 0;
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    gs_error("Insert failed error: %d", rc);
    sqlite3_finalize(pStmt);
    return 0;
  }
  
  sqlite3_finalize(pStmt);
  gs_info("Updated lastlogin for for %s", username);

  return 1;
}
