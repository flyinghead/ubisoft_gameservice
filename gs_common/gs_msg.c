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
 * Game Service MSG functions for Dreamcast
 */

#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include "gs_common.h"

uint16_t create_startgame(char* msg, uint32_t group_id, char* ip, uint16_t port) {
  int pkt_size = 0;
  
  pkt_size += bin32_to_msg(group_id, &msg[pkt_size]);
  pkt_size += sprintf(&msg[pkt_size], "s%s", ip);
  pkt_size++;
  pkt_size += bin32_to_msg(port, &msg[pkt_size]);    

  return (uint16_t)pkt_size;  
}

uint16_t create_sessionremove(char* msg, uint32_t group_id) {
  int pkt_size = 0;
  pkt_size += bin32_to_msg(group_id, &msg[pkt_size]);
  return (uint16_t)pkt_size;
}

uint16_t create_updateplayerping(char* msg, char* username, uint32_t group, uint8_t ping) {
  int pkt_size = 0;

  pkt_size += sprintf(&msg[pkt_size], "s%s", username);
  pkt_size++;
  pkt_size += bin8_to_msg(ping, &msg[pkt_size]);
  pkt_size++;
  pkt_size += bin32_to_msg(group, &msg[pkt_size]);
  
  return (uint16_t)pkt_size;
}

uint16_t create_ping(char* msg) {
  int pkt_size = 0;
  
  pkt_size += bin32_to_msg((uint32_t)rand(), &msg[pkt_size]); 

  return (uint16_t)pkt_size;
}

uint16_t create_updatesessions(char* msg, uint32_t groupid, uint32_t session_config) {
  int pkt_size = 0;
  pkt_size += bin32_to_msg(groupid, &msg[pkt_size]);
  pkt_size += bin32_to_msg(session_config, &msg[pkt_size]);
  return (uint16_t)pkt_size;
}

//Group_id
uint16_t create_begingame(char* msg, uint32_t groupid) {
  int pkt_size = 0;
  pkt_size += bin8_to_msg(BEGINGAME, &msg[pkt_size]);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "%s", "[");
  pkt_size += bin32_to_msg(groupid, &msg[pkt_size]); 
  pkt_size += sprintf(&msg[pkt_size], "%s", "]");
  return (uint16_t)pkt_size;
}

//Group_id
uint16_t create_joinsession(char* msg, uint32_t groupid) {
  int pkt_size = 0;
  pkt_size += bin8_to_msg(JOINSESSION, &msg[pkt_size]);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "%s", "[");
  pkt_size += bin32_to_msg(groupid, &msg[pkt_size]); 
  pkt_size += sprintf(&msg[pkt_size], "%s", "]");
  return (uint16_t)pkt_size;
}

//Arena id
uint16_t create_loginarena(char* msg, uint32_t arena_id) {
  int pkt_size = 0;
  pkt_size += bin8_to_msg(LOGINARENA, &msg[pkt_size]);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "%s", "[");
  pkt_size += bin32_to_msg(arena_id, &msg[pkt_size]);
  pkt_size += sprintf(&msg[pkt_size], "%s", "]");
  
  return (uint16_t)pkt_size;
}

uint16_t create_gssuccessful(char* msg, uint8_t msg_code) {
  int pkt_size = 0;
  pkt_size += bin8_to_msg(msg_code, &msg[pkt_size]);
  pkt_size++;
  return (uint16_t)pkt_size;
}

uint16_t create_gsfail(char* msg, uint8_t msg_code, uint32_t error_code) {
  int pkt_size = 0;
  pkt_size += bin8_to_msg(msg_code, &msg[pkt_size]);
  pkt_size++;
  
  pkt_size += sprintf(&msg[pkt_size], "[");
  pkt_size += bin32_to_msg((uint32_t)error_code, &msg[pkt_size]);
  pkt_size += sprintf(&msg[pkt_size], "]");

  return (uint16_t)pkt_size;
}

uint16_t create_joinwaitmodule(char* msg, char* ip, uint16_t port) {
  int pkt_size = 0;
  pkt_size += bin8_to_msg(JOINWAITMODULE, &msg[pkt_size]);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "[s%s", ip);
  pkt_size++;
  pkt_size += bin32_to_msg((uint32_t)port, &msg[pkt_size]);    
  pkt_size += sprintf(&msg[pkt_size], "%s", "]"); 

  return (uint16_t)pkt_size;
}

//pgroup (ARENA ID), port
uint16_t create_joinarena(char* msg, uint32_t arena_id, uint16_t port) {
  int pkt_size = 0;

  pkt_size += bin8_to_msg(JOINARENA, &msg[pkt_size]);
  pkt_size++;

  pkt_size += sprintf(&msg[pkt_size], "%s", "[");

  pkt_size += bin32_to_msg(arena_id, &msg[pkt_size]);
  pkt_size += bin32_to_msg((uint32_t)port, &msg[pkt_size]);
  
  pkt_size += sprintf(&msg[pkt_size], "%s", "]");
  
  return (uint16_t)pkt_size;
}

//LobbyId, Nr of players
uint16_t create_updategroupsize(char* msg, uint32_t groupid, uint32_t nr_players) {
  int pkt_size = 0;
  pkt_size += bin32_to_msg(groupid, &msg[pkt_size]);
  pkt_size += bin32_to_msg(nr_players, &msg[pkt_size]);
  return (uint16_t)pkt_size;
}

//Username, Game, GVersion, GSVersion, MaxPlayers, MaxObservers, %s (GameInfo?), Password, GroupId, PGroupId, %d, %d 
//GroupName, GroupId (new created)
uint16_t create_createsession(char* msg, char* session_name, uint32_t session_id) {
  int pkt_size = 0;

  pkt_size += bin8_to_msg(CREATESESSION, &msg[pkt_size]);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "[s%s", session_name);
  pkt_size++;  
  pkt_size += bin32_to_msg(session_id, &msg[pkt_size]);    
  pkt_size += sprintf(&msg[pkt_size], "%s", "]"); 

  return (uint16_t)pkt_size;
}

// [%s, %s, %s] 
uint16_t create_playerpoints(char* msg, const char* username, const char* game, const char *points) {
  int pkt_size = 0;

  pkt_size += bin8_to_msg((uint8_t)SCORECARD, &msg[pkt_size]);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "[s%s", username);
  pkt_size++;  
  pkt_size += sprintf(&msg[pkt_size], "s%s", game);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", points);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "%s", "]"); 

  return (uint16_t)pkt_size;
}

//Group ID, master name
uint16_t create_master_changed(char* msg, uint32_t session_id, char* username) {
  int pkt_size = 0;

  uint32_t group_id = session_id;
  
  pkt_size += bin32_to_msg(group_id, &msg[pkt_size]);
  
  pkt_size += sprintf(&msg[pkt_size], "s%s", username);
  msg[pkt_size++] = '\x00';
  
  return (uint16_t)pkt_size;
}

//pgroup (Arena ID), GroupID, ArenaName, IP
uint16_t create_new_arena(char* msg, uint32_t arena_id, uint32_t basicgroup_id, char* ip) {
  int pkt_size = 0;

  uint32_t pgroup_id = arena_id;
  uint32_t group_id = basicgroup_id;
  
  pkt_size += bin32_to_msg(pgroup_id, &msg[pkt_size]);
  pkt_size += bin32_to_msg(group_id, &msg[pkt_size]);
  
  pkt_size += sprintf(&msg[pkt_size], "s%s", "Shumania");
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", ip);
  msg[pkt_size++] = '\x00';
  
  return (uint16_t)pkt_size;
}

//PlayerName, GroupId, Observer (yes/no)
uint16_t create_joinnew(char* msg, char* username, uint32_t group_id) {
  int pkt_size = 0;

  pkt_size += sprintf(&msg[pkt_size], "s%s", username);
  pkt_size++;
  
  pkt_size += bin32_to_msg(group_id, &msg[pkt_size]);
  pkt_size += bin8_to_msg('\x00', &msg[pkt_size]);
  pkt_size++;
 
  return (uint16_t)pkt_size;
}

//PlayerName, GroupId
uint16_t create_joinleave(char* msg, char* username, uint32_t group_id) {
  int pkt_size = 0;

  pkt_size += sprintf(&msg[pkt_size], "s%s", username);
  pkt_size++;
  pkt_size += bin32_to_msg(group_id, &msg[pkt_size]);
 
  return (uint16_t)pkt_size;
}


// Group GroupId PGroupId  MaxP  MaxV  NbP  NbV  Master  Config  Info Game AllowedBranch
//  %s     %ld     %ld     %ld   %ld   %ld  %ld    %s     %ld     %s   %s       %s       
uint16_t create_new_basic_group(char* msg, char *name, uint32_t arena_id, uint32_t basicgroup_id, char* game, char* allowedbranch) {
  int pkt_size = 0;

  pkt_size += sprintf(&msg[pkt_size], "s%s", name[0] == '\0' ? "Shumania" : name);
  pkt_size++;
  pkt_size += bin32_to_msg(basicgroup_id, &msg[pkt_size]);
  pkt_size += bin32_to_msg(arena_id, &msg[pkt_size]);
  pkt_size += bin32_to_msg((uint32_t)100, &msg[pkt_size]);
  pkt_size += bin32_to_msg((uint32_t)0, &msg[pkt_size]);
  pkt_size += bin32_to_msg((uint32_t)0, &msg[pkt_size]);
  pkt_size += bin32_to_msg((uint32_t)0, &msg[pkt_size]);
  pkt_size += sprintf(&msg[pkt_size], "s%s", "");
  pkt_size++;
  pkt_size += bin32_to_msg((uint32_t)0, &msg[pkt_size]);
  pkt_size += sprintf(&msg[pkt_size], "s%s", "");
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", game);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", allowedbranch);
  pkt_size++;
  
  return (uint16_t)pkt_size;
}

//_ => ARENA, 0 => SESSION
// User, Session, d?, d?, d?, d?, d?, d?, Arena?, dConfig, owGame, Game
uint16_t create_getsession(char* msg, char* username, char* name, char* game, char* gameinfo, char* master, uint32_t session_id, uint32_t group_id, uint32_t max_players, uint32_t max_observers, uint32_t conf) {
  int pkt_size = 0;
  
  pkt_size += bin8_to_msg(GETSESSION, &msg[pkt_size]);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "[s%s", username);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", name);
  pkt_size++;
  pkt_size += bin32_to_msg(session_id, &msg[pkt_size]);
  pkt_size += bin32_to_msg(group_id, &msg[pkt_size]);  
  pkt_size += bin32_to_msg(max_players, &msg[pkt_size]);
  pkt_size += bin32_to_msg(max_observers, &msg[pkt_size]);
  pkt_size += bin32_to_msg(0, &msg[pkt_size]);
  pkt_size += bin32_to_msg(0, &msg[pkt_size]);
  pkt_size += sprintf(&msg[pkt_size], "s%s", master);
  pkt_size++; 
  pkt_size += bin32_to_msg(conf, &msg[pkt_size]);
  pkt_size += sprintf(&msg[pkt_size], "s%s", gameinfo);
  pkt_size++; 
  pkt_size += sprintf(&msg[pkt_size], "s%s", game);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "]");
 
  return (uint16_t)pkt_size;
}

//IrcAlias, acc.Username, acc.FirstName, acc.LastName, acc.Language, acc.Email, acc.PublicIP
uint16_t create_playerinfo(char* msg, char* username, char* ip, char extended) {
  int pkt_size = 0;

  pkt_size += bin8_to_msg(PLAYERINFO, &msg[pkt_size]);
  pkt_size++;

  pkt_size += sprintf(&msg[pkt_size], "[su%s", username);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", username);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", "");
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", "");
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", "");
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", "");
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", ip);
  pkt_size++;
  
  if (extended)
  {
    /* TEST SDO - is needed */
    //Sex
    pkt_size += bin32_to_msg((uint32_t)1, &msg[pkt_size]);

    //Photo
    pkt_size += bin32_to_msg((uint32_t)1, &msg[pkt_size]);
  
    //Game
    pkt_size += sprintf(&msg[pkt_size], "s%s", "");
    pkt_size++;

    //Webpage
    pkt_size += sprintf(&msg[pkt_size], "s%s", "");
    pkt_size++;
  }

  pkt_size += sprintf(&msg[pkt_size], "%s", "]");
  
  
  return (uint16_t)pkt_size;
}

uint16_t create_gs_hdr(char* msg, uint8_t msg_id, uint8_t msg_flag, uint16_t msg_size) {
  msg_size = (uint16_t)(msg_size + 6);
  msg[0] = '\x00';
  uint16_to_char(msg_size, &msg[1]);
  msg[3] = '\x00';
  msg[4] = (char)msg_id;
  msg[5] = (char)msg_flag;

  return msg_size;
}
