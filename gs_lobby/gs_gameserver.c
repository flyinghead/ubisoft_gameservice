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
 * Game Service Server functions for Dreamcast
 */

#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "gs_gameserver.h"
#include "gs_sql.h"
#include "../gs_common/gs_common.h"

#define RUDP_FLAG 0x800000
#define RUDP_MASK 0x7FFFFF

uint32_t serverSeq = 1;
server_data_t server_data;
FILE *udp_dump;

void send_functions(uint8_t send_flag, char* msg, uint16_t pkt_size, server_data_t *s, uint16_t player_id) {
  int i;
  
  switch(send_flag) {
  case SENDTOOTHERPLAYERS:
    pthread_mutex_lock(&s->mutex);
    for(i = 0; i < s->max_players; i++) {
      if (s->p_l[i] && (s->p_l[i]->player_id != player_id))
	write(s->p_l[i]->sock, msg, pkt_size);
    }
    pthread_mutex_unlock(&s->mutex);
    break;;
  case SENDTOPLAYERGROUP:
    gs_info("GAMESERVER%d - SENDTOPLAYERGROUP not in use", s->game_tcp_port);
    break;;
  case SENDTOPLAYER:
    if (pkt_size < 0xA)
      return;

    /* Refactor message before sending */
    memmove(&msg[0x08], &msg[0xA], (size_t)(pkt_size-0xA));
    pkt_size = (uint16_t)(pkt_size - 2);
    uint16_to_char(pkt_size, &msg[1]);
        
    pthread_mutex_lock(&s->mutex);
    for(i = 0; i < s->max_players; i++) {
      if (s->p_l[i] && (s->p_l[i]->player_id == player_id)) {
	write(s->p_l[i]->sock, msg, pkt_size);
    break;
      }
    }
    pthread_mutex_unlock(&s->mutex);
    break;;
  case SENDTOALLPLAYERS:
    pthread_mutex_lock(&s->mutex);
    for(i = 0; i < s->max_players; i++) {
      if (s->p_l[i])
	write(s->p_l[i]->sock, msg, pkt_size);
    }
    pthread_mutex_unlock(&s->mutex);
    break;;
  default:
    gs_info("GAMESERVER%d - TCP Flag not supported %u", s->game_tcp_port, send_flag);
    print_gs_data(msg, pkt_size);
  }
}

static uint32_t find_cli_seq(player_t *player, uint32_t sseq)
{
  uint32_t cseq = 0;
  for (int i = player->udp.seq_head; i != player->udp.seq_tail; i = (i + 1) % SEQ_TAB_LEN) {
      if (player->udp.seq_table[i].sseq > sseq)
	break;
      cseq = player->udp.seq_table[i].cseq;
  }
  return cseq;
}

static void add_cli_seq(player_t *player, uint32_t cseq, uint32_t sseq)
{
  player->udp.seq_table[player->udp.seq_tail].cseq = cseq;
  player->udp.seq_table[player->udp.seq_tail].sseq = sseq;
  player->udp.seq_tail = (player->udp.seq_tail + 1) % SEQ_TAB_LEN;
  if (player->udp.seq_head == player->udp.seq_tail)
    player->udp.seq_head = (player->udp.seq_head + 1) % SEQ_TAB_LEN;
}

void send_udp_player(player_t *player, char* msg, uint16_t pkt_size)
{
  uint32_t last_ack_seq = serverSeq;
  uint32_t last_rel_ack_seq = serverSeq;
  for (int i = 0; i < player->server->max_players; i++) {
      player_t *pl = player->server->p_l[i];
      if (pl == NULL || pl->player_id == player->player_id)
	continue;
      if (pl->udp.last_ack_seq < last_ack_seq)
	last_ack_seq = pl->udp.last_ack_seq;
      if (pl->udp.last_rel_ack_seq < last_rel_ack_seq)
	last_rel_ack_seq = pl->udp.last_rel_ack_seq;
  }
  last_ack_seq = find_cli_seq(player, last_ack_seq);
  last_rel_ack_seq = find_cli_seq(player, last_rel_ack_seq);
  if (last_rel_ack_seq != 0
      && last_rel_ack_seq >= player->udp.rel_client_seq
      && last_rel_ack_seq - player->udp.rel_client_seq <= 5)
    last_ack_seq |= RUDP_FLAG;
  uint24_to_char(last_ack_seq, &msg[3]);

  uint16_t pred_cli_time = 0;
  if (player->udp.last_time)
    pred_cli_time = (uint16_t)(char_to_uint16(&msg[6]) + player->udp.last_time - (uint16_t)player->udp.last_update);
  uint16_to_char(pred_cli_time, &msg[8]);

  sendto(player->server->udp_sock, msg, (size_t)pkt_size, 0,
	 (struct sockaddr*)&player->udp.addr,
	 (socklen_t)sizeof(struct sockaddr_in));
}

void send_udp_functions(int send_flag, char* msg, uint16_t pkt_size, server_data_t *s, uint16_t player_id) {
  int i;

  uint32_t reliable = (msg[0] & 0x80) << 16;
  uint24_to_char(serverSeq | reliable, &msg[0]);
  serverSeq++;
  uint16_to_char((uint16_t)get_time_ms(), &msg[6]);

  switch(send_flag) {
  case SENDTOOTHERPLAYERS:
    pthread_mutex_lock(&s->mutex);
    for(i = 0; i < s->max_players; i++) {
      player_t *player = s->p_l[i];
      if (player && player->player_id != player_id)
        send_udp_player(player, msg, pkt_size);
    }
    pthread_mutex_unlock(&s->mutex);
    break;;
  case SENDTOPLAYERGROUP:
    gs_info("GAMESERVER%d - SENDTOPLAYERGROUP not in use", s->game_tcp_port);
    break;;
  case SENDTOPLAYER:
    if (pkt_size < 0x12)
      return;

    /* Refactor message before sending */
    memmove(&msg[0x10], &msg[0x12], (size_t)(pkt_size-0x12));
    pkt_size = (uint16_t)(pkt_size - 2);
    uint16_to_char(pkt_size, &msg[1]);
        
    pthread_mutex_lock(&s->mutex);
    for(i = 0; i < s->max_players; i++) {
      player_t *player = s->p_l[i];
      if (player && player->player_id == player_id) {
        send_udp_player(player, msg, pkt_size);
	break;
      }
    }
    pthread_mutex_unlock(&s->mutex);
    break;;
  case SENDTOALLPLAYERS:
    pthread_mutex_lock(&s->mutex);
    for(i = 0; i < s->max_players; i++) {
      player_t *player = s->p_l[i];
      if (player)
	send_udp_player(player, msg, pkt_size);
    }
    pthread_mutex_unlock(&s->mutex);
    break;;
  default:
    gs_info("GAMESERVER%d - UDP Flag not supported %x", s->game_tcp_port, send_flag);
    print_gs_data(msg, pkt_size);
  }
}

uint16_t create_gameserver_hdr(char* msg, uint8_t msg_id, uint8_t msg_flag, uint16_t msg_size) {

  msg_size = (uint16_t)(msg_size + 8);
  msg[0] = '\x00';
  uint16_to_char(msg_size, &msg[1]);
  msg[3] = '\x40';
  msg[4] = (char)msg_flag;
  msg[5] = '\x00';
  msg[6] = '\x00';
  msg[7] = (char)msg_id;

  return msg_size;
}

/*
uint16_t create_gameserver_udp_hdr(char* msg, uint8_t msg_id, uint8_t msg_flag, uint16_t msg_size) {
  
  msg_size = (uint16_t)(msg_size + 16);
  msg[0] = '\x00';
  uint16_to_char(msg_size, &msg[1]);
  msg[3] = '\x60';
  msg[4] = (char)msg_flag;
  msg[5] = '\x00';
  msg[6] = '\x00';
  msg[7] = '\x00';
  msg[8] = '\x00';
  msg[9] = '\x00';
  msg[10] = '\x00';
  msg[11] = '\x00';
  msg[12] = '\x00';
  msg[13] = '\x00';
  msg[14] = '\x00';
  msg[15] = (char)msg_id;
  
  return msg_size;
}
*/

/* Create new player message */
uint16_t create_event_newplayer(char* msg, uint16_t playerid, char* username) {
  uint16_t pkt_size = 0;
  char un_buf[15];
  memset(un_buf, 0, sizeof(un_buf));
  strlcpy(un_buf, username, sizeof(un_buf));

  memcpy(msg, &playerid, sizeof(uint16_t));
  pkt_size = (uint16_t)(pkt_size + (sizeof(uint16_t)));
  
  sprintf(&msg[pkt_size], "%s", un_buf);
  pkt_size = (uint16_t)(pkt_size + 16);
  
  return (uint16_t)pkt_size;
}

/* Create player left message */
uint16_t create_event_playerleft(char* msg, uint16_t playerid) {
  uint16_t pkt_size = 0;
    
  memcpy(msg, &playerid, sizeof(uint16_t));
  pkt_size = (uint16_t)(pkt_size + (sizeof(uint16_t)));
    
  return (uint16_t)pkt_size;
}

/* Create ownid message */
uint16_t create_event_ownid(char* msg, uint16_t playerid, uint16_t nr_pl_now, uint16_t expected_pl) {
  uint16_t pkt_size = 0;
  
  memcpy(msg, &playerid, sizeof(uint16_t));
  memcpy(&msg[2], &nr_pl_now, sizeof(uint16_t));
  memcpy(&msg[4], &expected_pl, sizeof(uint16_t));
  
  pkt_size = (uint16_t)(sizeof(uint16_t)*3);
  
  return pkt_size;
}

/* Create playerinfos message */
uint16_t create_event_playerinfos(char* msg, uint16_t playerid, uint32_t points, uint32_t trophies) {
  uint16_t pkt_size = 0;
    
  memcpy(msg, &playerid, sizeof(uint16_t));
  memcpy(&msg[2], &points, sizeof(uint32_t));
  memcpy(&msg[6], &trophies, sizeof(uint32_t));
  pkt_size = (uint16_t)(sizeof(uint16_t) + sizeof(uint32_t)*2);
    
  return (uint16_t)pkt_size;
}

/* Create server time message */
uint16_t create_event_servertime(char* msg, time_t start_time) {
  time_t server_time = get_time_ms() - start_time;
  uint32_t sec = (uint32_t)(server_time / 1000);
  uint32_t msec = (uint32_t)(server_time % 1000);
  
  memcpy(msg, &sec, sizeof(uint32_t));
  memcpy(&msg[4], &msec, sizeof(uint32_t));
  
  return sizeof(uint32_t) * 2;
}

/* Create new master message */
uint16_t create_event_newmaster(char* msg, uint16_t playerid) {
  uint16_t pkt_size = 0;

  memcpy(msg, &playerid, sizeof(uint16_t));
  pkt_size = (uint16_t)(pkt_size + (sizeof(uint16_t)));
  
  return (uint16_t)pkt_size;
}

int add_gameserver_player(server_data_t *s, player_t *pl) {
  int i;
  uint16_t max_players = s->max_players;

  pthread_mutex_lock(&s->mutex);
  for(i=0;i<max_players;i++) {
    if(!(s->p_l[i])) {
      s->p_l[i] = pl;
      gs_info("GAMESERVER%d - Added player with sock: %d", s->game_tcp_port, pl->sock);
      pthread_mutex_unlock(&s->mutex);
      return 1;
    }
  }
  pthread_mutex_unlock(&s->mutex);
  gs_info("GAMESERVER%d - Could not add player with sock: %d", s->game_tcp_port, pl->sock);
  gs_info("GAMSERVER%d - Server full", s->game_tcp_port);
  return 0; 
}

void remove_gameserver_player(player_t *pl, char* msg) {
  server_data_t *s = pl->server;
  int max_players = s->max_players;
  int i;

  if (pl->player_id != 0) {
    /* Send player left */
    uint16_t pkt_size = create_event_playerleft(&msg[8], pl->player_id);
    pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_PLAYERLEFT, SENDTOSERVER, pkt_size);
    send_functions(SENDTOOTHERPLAYERS, msg, pkt_size, s, pl->player_id);

    pthread_mutex_lock(&s->mutex);
    /* If master left, change to the next in list */
    if(pl->is_master == 1) {
      s->master_id = 0;
      for(i=0;i<max_players;i++) {
	player_t *new_master = s->p_l[i];
	if (new_master && new_master->player_id != pl->player_id && new_master->player_id != 0) {
	  s->master_id = new_master->player_id;
	  s->master[0] = '\0';
	  new_master->is_master = 1;
	  gs_info("Master left the game, change to 0x%02x: %s", s->master_id, new_master->username);
	  pkt_size = create_event_newmaster(&msg[8], (uint16_t)s->master_id);
	  pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_NEWMASTER, SENDTOSERVER, pkt_size);
	  send_functions(SENDTOOTHERPLAYERS, msg, pkt_size, s, pl->player_id);
	  break;
	}
      }
      if (s->master_id == 0 && s->current_nr_of_players >= 2)
	gs_info("GAMESERVER%d - Can't find a new master. Aborting", s->game_tcp_port);
    }

    /* Find and remove user */
    for(i=0;i<max_players;i++) {
      if (s->p_l[i] && s->p_l[i]->player_id == pl->player_id) {
	gs_info("GAMESERVER%d - Removed player with 0x%02x", s->game_tcp_port, pl->player_id);
	s->p_l[i] = NULL;
	s->current_nr_of_players = (uint8_t)(s->current_nr_of_players - 1);
      }
    }
  }
  else {
    /* Player hasn't registered and is unknown */
    pthread_mutex_lock(&s->mutex);
    for (i = 0; i < max_players; i++) {
      if (s->p_l[i] == pl) {
	s->p_l[i] = NULL;
	break;
      }
    }
  }
  free(pl);
  if (s->current_nr_of_players == 0 || s->master_id == 0) {
    gs_info("GAMESERVER%d - Server is empty...exit", s->game_tcp_port);

    if (sqlite3_close(s->db) != SQLITE_OK) {
      gs_info("DB is busy during closing");
    }
    gs_info("GAMESERVER%d - Closed the DB", s->game_tcp_port);
    pthread_mutex_unlock(&s->mutex);
    exit(0);
  }
  pthread_mutex_unlock(&s->mutex);

  return;
}

/*
 * Function: get_user_from_addr
 * --------------------
 *
 * Returns player struct from addr Caller *must* lock the server mutex prior to the call.
 * 
 *  *s:        ptr to server data struct
 *  *addr:     sockaddr_in
 *
 *  returns: ptr to player struct
 *
 */
player_t* get_user_from_addr(server_data_t *s, struct sockaddr_in *addr) {
  int i=0;
  int max_clients = s->max_players;

  for(i=0;i<max_clients;i++) {
    if (s->p_l[i] != NULL) {
      if (s->p_l[i]->addr.sin_addr.s_addr == addr->sin_addr.s_addr) {
	return s->p_l[i];
      }
    }
  }
  return NULL;
}

int parse_gameserver_header(char *buf, int buf_len) {
  uint16_t pkt_size;
  
  //Parse header
  if (buf_len < 8)
    return 0;

  pkt_size = char_to_uint16(&buf[1]);

  if(buf_len >= pkt_size)
    return pkt_size;

  return 0;
}

void lobby_kick_player(server_data_t *server, uint16_t player_id)
{
  player_t *player = NULL;
  for(int i = 0; i < server->max_players; i++) {
    player = server->p_l[i];
    if (player && player->player_id == player_id)
      break;
    player = NULL;
  }
  if (player == NULL)
    return;
  char msg[MAX_UNAME_LEN + 2];
  msg[0] = 'K';
  msg[1] = (char)strlen(player->username) + 1;
  strncpy(&msg[2], player->username, MAX_UNAME_LEN);
  write(server->lobby_pipe, msg, (size_t)(msg[1] + 2));
}

/*
 * Function: server_msg_handler
 * --------------------
 *
 * Function that handles the server
 * calls
 * 
 *  *pl:      ptr to player stryct
 *  *msg:     outgoing client msg
 *  *buf:     incoming client msg
 *  buf_len   size of read incoming msg
 *
 *  returns: pkt size
 *
 */
ssize_t gameserver_msg_handler(int sock, player_t *pl, char *msg, char *buf, int buf_len) {
  server_data_t *s = pl->server;
  uint16_t pkt_size = 0, recv_size = 0;
  uint8_t send_flag = 0, recv_flag = 0;
  char uname_tmp[MAX_UNAME_LEN];
  char track_tmp[MAX_UNAME_LEN];
  uint32_t points = 0, trophies = 0, time = 0;
  int rc = 0;
    
  recv_size = char_to_uint16(&buf[1]);
  send_flag = (uint8_t)buf[4];
  recv_flag = (uint8_t)buf[7];
			 
  if (send_flag == SENDTOSERVER) {
    switch(recv_flag) {
    case EVENT_REGISTER:
      if (recv_size != 0x18) {
        gs_info("GAMESERVER%d - EVENT_REGISTER should have the size 0x18", s->game_tcp_port);
        return 0;
      }
      if (strlen(&buf[8]) >= MAX_UNAME_LEN)
        return 0;
      
      buf[buf_len] = '\0';

      pthread_mutex_lock(&s->mutex);
      /* enforce username unicity */
      for (int i = 0; i < s->max_players; i++) {
	  player_t *player = s->p_l[i];
	  if (player == NULL || strcmp(player->username, &buf[8]) != 0)
	    continue;
	  gs_info("GAMESERVER%d - Kicking duplicate user %s", s->game_tcp_port, player->username);
	  /* Close the client connection */
	  shutdown(player->sock, SHUT_RDWR);
      }
      strlcpy(pl->username, &buf[8], sizeof(pl->username));
      gs_info("GAMESERVER%d - User %s joined the Game Server", s->game_tcp_port, pl->username);
      if ((strcmp(pl->username, s->master)) == 0) {
        pl->is_master = 1;
        pl->player_id = 1;
        s->master_id = 1;
      }
      else {
        pl->player_id = 1;
        for (int i = 0; i < s->max_players; i++)
  	      if (s->p_l[i] && s->p_l[i]->player_id >= pl->player_id)
  	        pl->player_id = s->p_l[i]->player_id;
  	    pl->player_id += 1;
      }
      gs_info("GAMESERVER%d - Player %s got id: %d%s", s->game_tcp_port, pl->username,
	      pl->player_id, pl->is_master ? " (Master)" : "");

      /* New user added */
      s->current_nr_of_players = (uint8_t)(s->current_nr_of_players + 1);
     
      pkt_size = create_event_ownid(&msg[8], pl->player_id, s->current_nr_of_players, s->max_players);
      pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_OWNID, SENDTOALLPLAYERS, pkt_size);
      write(pl->sock, msg, pkt_size);
      /* Send player list */
      for(int i = 0; i < s->max_players; i++) {
	  if (s->p_l[i] && s->p_l[i]->player_id != pl->player_id) {
	      memset(msg, 0, MAX_PKT_SIZE);
	      pkt_size = create_event_newplayer(&msg[8], s->p_l[i]->player_id, s->p_l[i]->username);
	      pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_NEWPLAYER, SENDTOALLPLAYERS, pkt_size);
	      write(pl->sock, msg, pkt_size);
	  }
      }

      rc = load_player_record(s->db, pl->username, &pl->points, &pl->trophies);
      if (rc != 1) {
	gs_info("Could not fetch Points and Trophies for user %s", pl->username);
	pl->trophies = 0;
	pl->points = 0;
      }
      /* Notify other users */
      pkt_size = create_event_newplayer(&msg[8], pl->player_id, pl->username);
      pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_NEWPLAYER, SENDTOALLPLAYERS, pkt_size);
      send_functions(SENDTOOTHERPLAYERS, msg, pkt_size, s, pl->player_id);
      pthread_mutex_unlock(&s->mutex);

      pkt_size = 0;
      break;;
      
    case EVENT_PLAYERLEFT:
      if (recv_size >= 0xA) {
	pkt_size = create_event_playerleft(&msg[8], ntohs(char_to_uint16(&buf[0x08])));
	pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_PLAYERLEFT, SENDTOALLPLAYERS, pkt_size);
	send_functions(SENDTOOTHERPLAYERS, msg, (uint16_t)pkt_size, s, ntohs(char_to_uint16(&buf[0x08]))); 
      }
      pkt_size = 0;
      break;;
      
    case EVENT_SERVERTIME:
      pkt_size = create_event_servertime(&msg[8], s->start_time);
      pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_SERVERTIME, SENDTOALLPLAYERS, pkt_size);
      break;;

    case EVENT_PLAYERINFOS:
      gs_info("Got EVENT_PLAYERINFOS: no-op???");
      break;;
      
    case EVENT_TOPSCORES:
      pkt_size = (uint16_t)load_topscores_record(s->db, &msg[8], MAX_PKT_SIZE);
      if (pkt_size == 0) {
	gs_info("Could not send EVENT_TOPSCORES to %s", pl->username);
	return 0;
      }
      pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_TOPSCORES, SENDTOALLPLAYERS, pkt_size);
      break;;
      
    case EVENT_UPDATESCORES:
      if (recv_size == 0x20) {
	strlcpy(uname_tmp, &buf[8], sizeof(uname_tmp));
	points = ntohl(char_to_uint32(&buf[24]));
	trophies = ntohl(char_to_uint32(&buf[28]));
	rc = update_player_point(s->db, uname_tmp, points, trophies);
	if (rc == 0)
	  gs_info("Could not update player point on user %s", uname_tmp);
      }
      break;;

    case EVENT_UPDATETRACKSPEED:
      gs_info("Got EVENT_UPDATETRACKSPEED");
      print_gs_data(buf, (long unsigned int)buf_len);
      if (recv_size == 0x2C) {
	strlcpy(track_tmp, &buf[8], sizeof(track_tmp));
	strlcpy(uname_tmp, &buf[24], sizeof(uname_tmp));
	time = ntohl(char_to_uint32(&buf[40]));
	/* MONACO sends lap speed as track speed..... ARCADE */
	if (s->server_type == MONACO_SERVER)
	  rc = create_lap_record(s->db, uname_tmp, track_tmp, time, ARCADE_LAP_MODE);
	else
	  rc = create_track_record(s->db, uname_tmp, track_tmp, time);
	if (rc == 0)
	  gs_info("Could not store tracktime for user %s", uname_tmp);
      }
      break;;
  
    case EVENT_UPDATELAPSPEED:
      gs_info("Got EVENT_UPDATELAPSPEED");
      print_gs_data(buf, (long unsigned int)buf_len);
      if (recv_size == 0x2C) {
	strlcpy(track_tmp, &buf[8], sizeof(track_tmp));
	strlcpy(uname_tmp, &buf[24], sizeof(uname_tmp));
	time = ntohl(char_to_uint32(&buf[40]));
	/* MONACO sends track speed as lap speed..... ARCADE */
	if (s->server_type == MONACO_SERVER)
	  rc = create_track_record(s->db, uname_tmp, track_tmp, time);
	else
	  rc = create_lap_record(s->db, uname_tmp, track_tmp, time, ARCADE_LAP_MODE);
	if (rc == 0)
	  gs_info("Could not store laptime for user %s", uname_tmp);
      }
      break;;

    case EVENT_TRACKSRECORDS:
      pkt_size = (uint16_t)load_track_record(s->db, &msg[8], MAX_PKT_SIZE);
      if (pkt_size == 0) {
	gs_info("Could not send EVENT_TRACKRECORDS to %s", pl->username);
	return 0;
      }
      pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_TRACKSRECORDS, SENDTOALLPLAYERS, pkt_size);
      break;;
      
    case EVENT_SETTRACKSPEED:
      gs_info("Got EVENT_SETTRACKSPEED");
      print_gs_data(buf, (long unsigned int)buf_len);
      if (recv_size == 0x2C) {
	strlcpy(track_tmp, &buf[8], sizeof(track_tmp));
	strlcpy(uname_tmp, &buf[24], sizeof(uname_tmp));
	time = ntohl(char_to_uint32(&buf[40]));
	rc = create_track_record(s->db, uname_tmp, track_tmp, time);
	if (rc == 0)
	  gs_info("Could not store tracktime for user %s", uname_tmp);
      }
      break;;

    case EVENT_SETLAPSPEED:
      gs_info("Got EVENT_SETLAPSPEED");
      print_gs_data(buf, (long unsigned int)buf_len);
      if (recv_size == 0x2C) {
	strlcpy(track_tmp, &buf[8], sizeof(track_tmp));
	strlcpy(uname_tmp, &buf[24], sizeof(uname_tmp));
	time = ntohl(char_to_uint32(&buf[40]));
	/* IN MONACO THIS IS SIM MODE */
	if (s->server_type == MONACO_SERVER)
	  rc = create_lap_record(s->db, uname_tmp, track_tmp, time, SIM_LAP_MODE);
	else
	  rc = create_lap_record(s->db, uname_tmp, track_tmp, time, ARCADE_LAP_MODE);
	
	if (rc == 0)
	  gs_info("Could not store laptime for user %s", uname_tmp);
      }
      break;;
      
    case EVENT_FIVESCORESBEFORE:
    case EVENT_MONACO_FIVESCORESBEFORE:
      pkt_size = (uint16_t)load_fivescorebefore_record(s->db, pl->username, &msg[8], MAX_PKT_SIZE);
      if (pkt_size == 0) {
	gs_info("Could not send EVENT_FIVESCORESBEFORE to %s", pl->username);
	return 0;
      }
      pkt_size = create_gameserver_hdr(msg, (uint8_t)recv_flag, SENDTOALLPLAYERS, pkt_size);
      break;;
      
    case EVENT_FIVESCORESAFTER:
    case EVENT_MONACO_FIVESCORESAFTER:
      pkt_size = (uint16_t)load_fivescoreafter_record(s->db, pl->username, &msg[8], MAX_PKT_SIZE);
      if (pkt_size == 0) {
	gs_info("Could not send EVENT_FIVESCORESAFTER to %s", pl->username);
	return 0;
      }   
      pkt_size = create_gameserver_hdr(msg, (uint8_t)recv_flag, SENDTOALLPLAYERS, pkt_size);
      break;;
         
    case EVENT_DELETETRACKSRECORDS:
      gs_info("Got EVENT_DELETETRACKSRECORDS");
      print_gs_data(buf, (long unsigned int)buf_len);
      break;;
      
    /*
     * SDO Garage stuff
     */
    case GROUPDATA:
      gs_info("Got GROUPDATA");
      print_gs_data(buf, (long unsigned int)buf_len);
      return 0;

    case SDO_VERSION_CHECK:
      gs_info("Got VERSION_CHECK");
      print_gs_data(buf, (long unsigned int)buf_len);
      msg[8] = 1;	// OK
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_VERSION_CHECK, SENDTOPLAYER, 1);
      write(pl->sock, msg, pkt_size);
      // Must be sent to the client or many database updates are skipped.
      msg[8] = 1;
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_DATABASE_STATUS, SENDTOPLAYER, 1);
      break;

    case SDO_PRICES_LIST:
      gs_info("Got PRICES_LIST");
      print_gs_data(buf, (long unsigned int)buf_len);
      // int(be) [1-8] type
      // type 1: car
      //	int(be) car# [0-21]
      //	string(size@0) ignored?
      //	int price
      //    byte ignored?
      //    byte ignored?
      // type 2: tires
      //    int(be) index [0-5]: Basic, Slick, Wet, Super Dry, Snow, Spiked
      //    int(be) price
      // type 3: nitro1,2,3 then mags?
      //    int(be) index [0-93]
      //    int(be) price
      // type 4-8: ?
      //    int(be) id
      //    int(be) price
      {
	uint32_t carPrices[] = {
	    // class D
	    17500, 15000, 15000, 10000, 10000,
	    // class C
	    40000, 65000, 55000, 50000, 45000, 60000,
	    // class B
	    120000, 180000, 140000, 160000, 220000, 200000,
	    // class A
	    450000, 550000, 650000, 750000, 850000,
	};
	const size_t count = sizeof(carPrices) / sizeof(carPrices[0]);
	load_price_list(s->db, 1, carPrices, (int)count);
	int size = uint32_to_char((uint32_t)count, &msg[8]);	// list size (be)
	for (size_t i = 0; i != count; i++) {
	    size += uint32_to_char(1, &msg[8 + size]);            // type=car
	    size += uint32_to_char((uint32_t)i, &msg[8 + size]);  // car #
	    msg[8 + size++] = 0;                                      // name (ignored)
	    size += uint32_to_char(carPrices[i], &msg[8 + size]); // price
	    msg[8 + size++] = 0;
	    msg[8 + size++] = 0;
	}
	pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_PRICES_LIST, SENDTOPLAYER, (uint16_t)size);
      }
      break;

    case SDO_GAME_DEFINES:
      gs_info("Got GAME_DEFINES");
      print_gs_data(buf, (long unsigned int)buf_len);
      // TODO
      // loop 4: loop 5 ints -> gameDefines[4-23]
      // int -> gameDef[0]
      // int ->         1
      // int/100 ->     2
      // int/100 ->     3
      // 5 * int ->   24-29
      // int/100 ->    30
      // int/100 ->    31
      // int/100 ->    32
      // 4 * int ->    33-36
      // 4 * int ->    37-40
      // 4 * int ->    41-44
      // 4 * int ->    45-48
      // 4 * int ->    49-52
      // 16 * 4 * 3 * 2 int -> circuits
      //   16 circuits: aspen1, aspen2, atkey1, atkey2, canada1, canada2, canada3, holly1, holly2,
      //                mexico, montreal1, montreal2, montreal3, nevada, newyork1, newyork2
      //   4 car classes (A to D)
      //   3 radars
      //   2 limits (forward, reverse)
      {
	int data[436] = {};
	// Ranking bonuses
	// class D
	data[0] = 10080;	// #1
	data[1] = 6000;		// #2
	data[2] = 3000;		// #3
	data[3] = 1500;		// #4
	data[4] = 600;		// #5
	// class C
	data[5] = 15120;	// #1
	data[6] = 9000;		// #2
	data[7] = 4500;		// #3
	data[8] = 2250;		// #4
	data[9] = 900;		// #5
	// class B
	data[10] = 25200;	// #1
	data[11] = 15000;	// #2
	data[12] = 7500;	// #3
	data[13] = 3750;	// #4
	data[14] = 1500;	// #5
	// class A
	data[15] = 50400;	// #1
	data[16] = 30000;	// #2
	data[17] = 15000;	// #3
	data[18] = 7500;	// #4
	data[19] = 3000;	// #5

	data[20] = 6661;	// TODO ?
	data[21] = 5000;	// Paint job price
	data[22] = 100;		// TODO % (?)
	data[23] = 100;		// TODO % (?)
	data[24] = 6662;	// TODO ?
	data[25] = 6663;	// TODO ?

	data[26] = 160000;	// class C points
	data[27] = 800000;	// class B points
	data[28] = 4000000;	// class A points

	data[29] = 6664;	// TODO ?
	data[30] = 100;		// TODO % ?
	data[31] = 100;		// % repair cost multiplier
	data[32] = 100;		// % cash -> driver points

	data[33] = 500;		// race bonus 1 (per class)
	data[34] = 1000;
	data[35] = 2000;
	data[36] = 4000;
	data[37] = 500;		// race bonus 2 (per class)
	data[38] = 1000;
	data[39] = 2000;
	data[40] = 4000;
	data[41] = 500;		// race bonus 3 (per class)
	data[42] = 1000;
	data[43] = 2000;
	data[44] = 4000;

	data[45] = 500;		// radar busted premiums (per class)
	data[46] = 1000;
	data[47] = 2000;
	data[48] = 4000;
	data[49] = 10;		// radar busted bonus per mph (per class)
	data[50] = 25;
	data[51] = 50;
	data[52] = 100;
	load_game_defines(s->db, data, sizeof(data) / sizeof(data[0]));
	// montreal1 (forward)
	size_t idx = 53 + 10 * 4 * 3 * 2;
	// class A
	data[idx] = 117; idx += 2;
	data[idx] = 96; idx += 2;
	data[idx] = 109; idx += 2;
	// class B
	data[idx] = 107; idx += 2;
	data[idx] = 88; idx += 2;
	data[idx] = 100; idx += 2;
	// class C
	data[idx] = 98; idx += 2; // actual value
	data[idx] = 80; idx += 2; // actual value
	data[idx] = 91; idx += 2; // actual value
	// class D
	data[idx] = 92; idx += 2;
	data[idx] = 75; idx += 2;
	data[idx] = 85; idx += 2;
	// (reverse on odd indexes)
	// newyork1 (forward)
	idx = 53 + 14 * 4 * 3 * 2;
	// class A
	data[idx] = 104; idx += 2;
	data[idx] = 127; idx += 2;
	data[idx] = 115; idx += 2; // unknown
	// class B
	data[idx] = 95; idx += 2; // actual value
	data[idx] = 116; idx += 2; // actual value
	data[idx] = 105; idx += 2; // unknown
	// class C
	data[idx] = 87; idx += 2;
	data[idx] = 106; idx += 2;
	data[idx] = 96; idx += 2; // unknown
	// class D
	data[idx] = 81; idx += 2;
	data[idx] = 99; idx += 2;
	data[idx] = 90; idx += 2; // unknown
	memcpy(&msg[8], data, sizeof(data));
	pkt_size = sizeof(data);
      }
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_GAME_DEFINES, SENDTOPLAYER, pkt_size);
      break;

    case SDO_DBINFO_PLAYERDATA:
      gs_info("Got DBINFO_PLAYERDATA");
      print_gs_data(buf, (long unsigned int)buf_len);
      // 6 ints(le)			-> offset 0
      //   0: driver points
      //   1: user cash
      //   5: seasons played
      // 16 bytes
      // 1 byte: tires bitmap
      // 10 * 101 bytes		-> offset 0x200, garage
      //  byte 0: ff=empty,else=car_type
      //       1: car color?
      //     int: ?
      //    byte: ?
      // 3 bytes: ?
      //    byte: ?
      // byte 11: ?
      // offset 12: 5 * 3 ints
      //    byte: ?
      // 4 bytes: ?
      //    byte:
      //    byte:
      //     int:
      //   short:
      //    byte:
      {
        // Fetch from database
        int size = MAX_PKT_SIZE - 8;
        if (load_player_data(s->db, pl->username, (uint8_t *)&msg[8], &size) != 1 || size == 0)
        {
          // Create a new user
          pkt_size = 0;
          for (int i = 0; i < 10; i++) {
            *(int *)&msg[8 + pkt_size] = i == 1 ? load_initial_cash(s->db) : 0;
            pkt_size += 4;
          }
          msg[8 + pkt_size++] = 1; // basic tires
          // garage
          for (int i = 0; i < 10; i++) {
            memset(&msg[8 + pkt_size], 0, 101);
            msg[8 + pkt_size] = (char)0xff;	// empty slot
            pkt_size += 101;
          }
        }
        else
        {
          pkt_size = (uint16_t)size;
          for (int i = 0; i < 10; i++)
          {
            size = MAX_PKT_SIZE - 8 - pkt_size;
            load_player_car(s->db, pl->username, i, (uint8_t *)&msg[8 + pkt_size], &size);
            if (size != 101) {
              msg[8 + pkt_size] = (char)0xff;
              size = 101;
            }
            pkt_size = (uint16_t)(pkt_size + size);
          }
        }
        pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_DBINFO_PLAYERDATA, SENDTOPLAYER, pkt_size);
      }
      break;

    case SDO_DBUPDATE_PLAYERSTAT:
      gs_info("Got DBUPDATE_PLAYERSTAT");
      update_player_data(s->db, pl->username, (const uint8_t *)&buf[8], 41);
      pkt_size = 0;
      break;
    case SDO_DBUPDATE_PLAYERCAR:
      // msg[8] is car#, rest is car blob
      update_player_car(s->db, pl->username, buf[8], (const uint8_t *)&buf[9], 101);
      pkt_size = 0;
      break;

    case SDO_DBINFO_FULLSTATS:
      {
	gs_info("Got DBINFO_FULLSTATS");
	print_gs_data(buf, (long unsigned int)buf_len);
	msg[8] = buf[8]; // need to send back the value
	msg[9] = buf[9];
	int size = MAX_PKT_SIZE - 10;
	load_player_fullstats(s->db, pl->username, (uint8_t *)&msg[10], &size);
	if (size != 0) {
	  size = 473;	// Should be 473 bytes
	  size += 2;
	  /*
	  *(int *)&msg[410] = 11;
	  *(int *)&msg[414] = 12;
	  *(int *)&msg[418] = 13;	// std races
	  *(int *)&msg[422] = 14;	// 1st place victories
	  *(int *)&msg[426] = 16;	// trial races
	  *(int *)&msg[430] = 20;	// trial bets -> trial avg = won / bets
	  *(int *)&msg[434] = 20;	// trial won
	  *(int *)&msg[438] = 18;	// cash won in trial
	  *(int *)&msg[442] = 19;	// vendetta races -> vendetta avg = cars won / races
	  *(int *)&msg[446] = 20;	// cars won
	  *(int *)&msg[450] = 6;
	  *(int *)&msg[454] = 7;
	  *(int *)&msg[458] = 8;
	  *(int *)&msg[462] = 9;
	  */
	  *(int *)&msg[466] = 190;	// std avg multiplier?
	  /*
//	  *(int *)&msg[470] = 26;	// 5 bytes? ff ff ff ff ff
	  *(int *)&msg[475] = 0;	// favorite track mode
	  *(int *)&msg[479] = 7;	// favorite track
	  */
	}
	pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_DBINFO_FULLSTATS, SENDTOPLAYER, (uint16_t)size);
      }
      break;
    case SDO_DBUPDATE_FULLSTATS:
      gs_info("Got DBUPDATE_FULLSTATS");
      print_gs_data(buf, (long unsigned int)buf_len);
      update_player_fullstats(s->db, pl->username, (const uint8_t *)&buf[8], buf_len - 8);
      pkt_size = 0;
      break;

    case SDO_REQUEST_MOTD:
      gs_info("Got REQUEST_MOTD");
      print_gs_data(buf, (long unsigned int)buf_len);
      load_motd(s->db, &msg[8], MAX_PKT_SIZE - 8);
      pkt_size = (uint16_t)(strlen(&msg[8]) + 1);
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_REQUEST_MOTD, SENDTOPLAYER, pkt_size);
      break;

    case SDO_UPDATE_SESSION_INFO:
      gs_info("Got SDO_UPDATE_SESSION_INFO");
      print_gs_data(buf, (long unsigned int)buf_len);
      // 0000 | 00 00 2D 40 04 03 00 8D 00 00 00 00 00 00 00 00 | ..-@............
      // 0010 | 05 00 00 00 00 30 20 30 20 30 20 30 20 30 20 30 | .....0 0 0 0 0 0
      //   or   05 8C FE nn nn 30 20 30 20 30 20 30 20 30 20 30 | .....0 0 0 0 0 0  with nnnn increasing
      // 0020 | 20 35 20 32 20 34 20 34 20 31 20 30 00          |  5 2 4 4 1 0.
      // 7      0          0      0         3        0      5       2     4     4      1      5000
      // track# weather    time   reverse   mode     mirror max     laps  max   max    nitro  wager
      //        0=clear    0=day            3=std           players       car   driver
      //        1=cloudy   1=dusk           4=trial                       class class
      //        ...        ...
      {
	unsigned idx = 9;
	uint32_t passwd_size = char_to_uint32(&buf[idx]);
	idx += 4 + passwd_size;
	//uint32_t max_players = char_to_uint32(&buf[idx]);
	idx += 4;
	idx += 4; // unknown
	strlcpy(s->session_info, &buf[idx], sizeof(s->session_info));
	pkt_size = (uint16_t)(idx - 8);	// session info not included
	memcpy(msg + 8, buf + 8, pkt_size);
	pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_UPDATE_SESSION_INFO, SENDTOPLAYER, pkt_size);	// send back beginning of packet
	msg[5] = 0x04; // from server??
	write(pl->sock, msg, pkt_size);
    	char msg[64] = { 'S' };
    	unsigned len = (unsigned)buf_len - idx;
    	if (len + 2 > sizeof(msg)) {
    	  gs_error("SDO_UPDATE_SESSION_INFO: overflow: %d bytes", len);
    	}
    	else {
    	  msg[1] = (char)len;
    	  memcpy(&msg[2], &buf[idx], len);
    	  ssize_t ret = write(s->lobby_pipe, msg, len + 2);
    	  if (ret < 0)
    	    perror("write(pipe)");
    	}
	pkt_size = 0;
      }
      break;

    case SDO_LOCK_ROOM:
      gs_info("Got SDO_LOCK_ROOM");
      print_gs_data(buf, (long unsigned int)buf_len);
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_LOCK_ROOM, SENDTOALLPLAYERS, 0);
      send_functions(SENDTOOTHERPLAYERS, msg, (uint16_t)pkt_size, s, pl->player_id);
      pkt_size = 0;
      s->locked = 1;
      {
    	char msg = 'L';
    	ssize_t ret = write(s->lobby_pipe, &msg, sizeof(msg));
    	if (ret < 0)
    	  perror("write(pipe)");
      }
      break;

    case SDO_UNLOCK_ROOM:
      gs_info("Got SDO_UNLOCK_ROOM");
      print_gs_data(buf, (long unsigned int)buf_len);
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_UNLOCK_ROOM, SENDTOALLPLAYERS, 0);
      send_functions(SENDTOOTHERPLAYERS, msg, (uint16_t)pkt_size, s, pl->player_id);
      pkt_size = 0;
      s->locked = 0;
      {
    	char msg = 'U';
    	ssize_t ret = write(s->lobby_pipe, &msg, sizeof(msg));
    	if (ret < 0)
    	  perror("write(pipe)");
      }
      break;

    case SDO_COMMIT:
      gs_info("Got SDO_COMMIT");
      break;

    case SDO_LOCAL_END_OF_RACE:
      gs_info("Got SDO_LOCAL_END_OF_RACE");
      break;

    case SDO_PLAYER_KICK:
      // 0000 | 00 00 0A 40 04 01 00 74 00 02                   | ...@...t..
      {
	uint16_t kicked_id = char_to_uint16(&buf[8]);
	pthread_mutex_lock(&s->mutex);
	for (int i = 0; i < s->max_players; i++) {
	    if (s->p_l[i] && s->p_l[i]->player_id == kicked_id) {
		pkt_size = (uint16_t)uint32_to_char(1, &msg[8]);
		pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_PLAYER_KICK, SENDTOPLAYER, pkt_size);
		write(s->p_l[i]->sock, msg, pkt_size);
		pkt_size = 0;
		break;
	    }
	}
	pthread_mutex_unlock(&s->mutex);
      }
      break;

    case SDO_GETBESTLAP:
      {
	int laptime = -1;
	if (s->session_info[0] != '\0') {
	  int track_num, reverse, mirror;
	  sscanf(s->session_info, "%d %*d %*d %d %*d %d", &track_num, &reverse, &mirror);
	  int race_mode = reverse | (mirror << 1);
	  gs_info("Got SDO_GETBESTLAP: track %d reverse %d mirror %d", track_num, reverse, mirror);
	  laptime = load_best_lap(s->db, track_num, race_mode);
	}
	*(int *)&msg[8] = laptime;
	pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_GETBESTLAP, SENDTOPLAYER, 4);
      }
      break;

    case SDO_TRACKRECORDS_UPDATE:
      {
	gs_info("Got SDO_TRACKRECORDS_UPDATE");
	print_gs_data(buf, (unsigned)buf_len);
	// 0000 | 00 00 1C 40 04 03 00 C7 04 00 00 00 00 00 00 00 | ...@............
	//                                track#      mode
	// 0010 | 00 00 00 00 00 00 00 00 73 E1 2D 00             | ........s.-.
	//                                max speed?
	// 0000 | 00 00 1C 40 04 01 00 C7 07 00 00 00 00 00 00 00 | ...@............
	//                                track#      mode
	// 0010 | C2 EA 7F 00 00 00 00 00 46 DF 34 00             | .......F.4.
	//        lap time                max speed?
	// 3 laps:
	// 0000 | 00 00 1C 40 04 01 00 C7 07 00 00 00 00 00 00 00 | ...@............
	// 0010 | F6 28 66 00 12 98 40 01 B1 5A 39 00             | .(f...@..Z9.
	//        lap time    race time   max speed
	// FIXME max speed doesn't depend on track mode? DNF player doesn't set the track mode when recording its max speed
	int track_num = *(int *)&buf[8];
	int track_mode = *(int *)&buf[12];
	int lap_time = *(int *)&buf[16];
	int race_time = *(int *)&buf[20];
	int max_speed = *(int *)&buf[24];
	int new_record = update_track_record(s->db, pl->username, track_num, track_mode, lap_time, race_time, max_speed);
	if (new_record > 0)
	{
	  // Reply if new personal or world record
	  // param1 is a bitmap: 0: laptime, 1: racetime, 2: maxspeed
	  *(int *)&msg[8] = new_record & 0xf;
	  // param2 is the same for world records
	  *(int *)&msg[12] = (new_record >> 4) & 0xf;
	  pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_TRACKRECORDS_UPDATE, SENDTOPLAYER, 8);
	}
      }
      break;

    case SDO_TRACKRECORDS:
      gs_info("Got SDO_TRACKRECORDS");
      print_gs_data(buf, (unsigned)buf_len);
      // holly reverse/mirror:
      // 0000 | 00 00 0E 40 04 01 00 C8 00 00 00 00 07 03

      // 3 * {	// best race time, best speed, best lap time
      //    u8 count			// top 3
      //       char[16] name
      //       u32 time/speed
      //    u8 count			// your best (1)
      //       char[16] name
      //       u32 time
      // }
      {
	int class = buf[8];	// 4: all, 0: class D, 1: class C, ...
	int track = buf[12];
	int mode = buf[13];	// 0: normal, 1: reverse, 2:mirror, 3:reverse/mirror
	pkt_size = (uint16_t)load_sdo_track_record(s->db, pl->username, track, mode, class, &msg[8]);
	pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_TRACKRECORDS, SENDTOPLAYER, pkt_size);
      }
      break;

    case SDO_STATS_POINT:
    case SDO_STATS_CASH:
    case SDO_STATS_STANDARDAVG:
    case SDO_STATS_STANDARDWIN:
    case SDO_STATS_TRIALAVG:	// %: 990 is 0.099%
    case SDO_STATS_TRIALWIN:
    case SDO_STATS_VENDETTAAVG:	// %: 990 is 0.099%
    case SDO_STATS_VENDETTAWIN:
      gs_info("Got SDO_STATS_xxx %02x", recv_flag);
      print_gs_data(buf, (unsigned)buf_len);
      // 4 groups? * u8 count (< 10) * char name[16] + u32 driverPoints
      // groups: top 10, 5 players before, current player, 5 players after
      // count[0] ints
      // count[1] ints
      // count[2] ints
      // count[3] ints
      {
	int class = buf[8];	// 4: all, 0: class D, 1: class C, ...
	pkt_size = (uint16_t)load_hall_of_fame(s->db, pl->username, recv_flag - SDO_STATS_POINT, class, &msg[8]);
	pkt_size = create_gameserver_hdr(msg, recv_flag, SENDTOPLAYER, pkt_size);
      }
      break;

    case SDO_DBUPDATE_STANDARD:
      // 0000 | 00 00 14 40 04 01 00 89 02 00 00 00 01 00 00 00 | ...@............
      // 0010 | 01 00 00 00             ?           race count  | ....
      //        wins
      gs_info("Got SDO_DBUPDATE_STANDARD");
      print_gs_data(buf, (unsigned)buf_len);
      update_std_race(s->db, pl->username, *(int *)&buf[12], *(int *)&buf[16]);
      break;

    case SDO_DBUPDATE_TRIAL:
      // 0000 | 00 00 1C 40 04 02 00 8A 00 00 00 00 01 00 00 00 | ...@............
      //                                            trial races
      // 0010 | 03 00 00 00 03 00 00 00 4E C3 00 00             | ........N...
      //        # trials    won trials  cash won ($49998)
      gs_info("Got SDO_DBUPDATE_TRIAL");
      print_gs_data(buf, (unsigned)buf_len);
      update_trial_race(s->db, pl->username, *(int *)&buf[12], *(int *)&buf[16], *(int *)&buf[20], *(int *)&buf[24]);
      break;

    case SDO_DBUPDATE_VENDETTA:
      gs_info("Got SDO_DBUPDATE_VENDETTA");
      print_gs_data(buf, (unsigned)buf_len);
      update_vendetta_race(s->db, pl->username, *(int *)&buf[12], *(int *)&buf[16]);
      break;

    case SDO_PLAYER_QUIT_RACE:
      lobby_kick_player(s, *(uint16_t *)&buf[5]);
      break;

    default:
      gs_info("GAMESERVER%d - Flag not supported %x", s->game_tcp_port, recv_flag);
      print_gs_data(buf, (long unsigned int)buf_len);
      return 0;
    }
  } else if (send_flag == SENDTOPLAYER) {
    if (buf[7] == SDO_START_SYNCHRO)
      gs_info("%s -> %d: SDO_START_SYNCHRO", pl->username, ntohs(char_to_uint16(&buf[0x08])));
    if (recv_size >= 0xA)
      send_functions(send_flag, buf, (uint16_t)buf_len, s, ntohs(char_to_uint16(&buf[0x08])));
  } else {
    if (buf[7] == SDO_START_RACE)
      gs_info("GAMESERVER%d - Race start", s->game_tcp_port);
    else if (buf[7] == SDO_START_TIME)
      gs_info("GAMESERVER%d - %s to all(%d): Time start", s->game_tcp_port, pl->username, send_flag);
    send_functions(send_flag, buf, (uint16_t)buf_len, s, pl->player_id);
  }

  return pkt_size;
}

static void create_gameserver_udp_header(char* msg, uint cliSeq)
{
  /* Server sequence */
  uint24_to_char(serverSeq, &msg[0]);
  serverSeq++;
  /* Last received client sequence */
  uint24_to_char(cliSeq, &msg[3]);
  /* Server time */
  uint16_to_char((uint16_t)get_time_ms(), &msg[6]);
  /* Predicted client time */
  uint16_to_char(0, &msg[8]);
}

static uint16_t create_gameserver_udp_segment(char* msg, uint8_t msg_id, uint8_t msg_flag, uint16_t msg_size)
{
  msg[0] = (char)(msg_size + 4);
  msg[1] = (char)(0x10 | msg_flag);
  msg[3] = (char)msg_id;

  return msg_size + 4;
}

/*
 * Function: udp_msg_handler
 * --------------------
 *
 * Function that handles incoming UDP pkt
 * 
 *  *buf:        ptr to buffer
 *   buf_len:    size of buffer
 *  *s:          ptr to server data struct
 *  *client:     ptr to client sockaddr struct
 *
 *  returns: size of pkt
 *           
 */
int udp_msg_handler(char* buf, int buf_len, server_data_t *s, struct sockaddr_in *client) {
  char msg[MAX_PKT_SIZE];
  
  if (buf_len < 10) {
    gs_info("GAMESERVER%d - Small UDP msg ignored (%d bytes)", s->game_tcp_port, buf_len);
    return 0;
  }

  player_t* pl = NULL;
  pthread_mutex_lock(&s->mutex);
  if ((pl = get_user_from_addr(s, client)) == NULL) {
    pthread_mutex_unlock(&s->mutex);
    gs_info("GAMESERVER%d - Invalid user", s->game_tcp_port);
    return 0;
  }

  int new_connection = 0;
  if (pl->udp.ready == 0 && pl->player_id != 0) {
    pl->udp.addr = *client;
    new_connection = 1;
  }

  /* Parse header */
  time_t now = get_time_ms();
  pl->udp.client_seq = char_to_uint24(&buf[0]);
  if (pl->udp.client_seq & RUDP_FLAG) {
      pl->udp.client_seq &= RUDP_MASK;
      pl->udp.rel_client_seq = pl->udp.client_seq;
  }
  add_cli_seq(pl, pl->udp.client_seq, serverSeq);
  pl->udp.last_ack_seq = char_to_uint24(&buf[3]);
  if (pl->udp.last_ack_seq & RUDP_FLAG) {
      pl->udp.last_ack_seq &= RUDP_MASK;
      pl->udp.last_rel_ack_seq = pl->udp.last_ack_seq;
  }
  pl->udp.last_time = char_to_uint16(&buf[6]);
  pl->udp.last_update = now;

  /* Respond to packets to the server */
  int send_to_players = 0;
  uint16_t pkt_size = 10;
  char *p = &buf[10];
  while (p - buf < buf_len)
  {
    int size = *p & 0xff;
    uint8_t msg_id = (uint8_t)(p[3] & 0xff);
    int send_flag = p[1] & 0xf;
    p += size;
    if (p - buf > buf_len)
      break;
  
    if (send_flag == SENDTOSERVER)
    {
	switch(msg_id) {
	  case EVENT_UDPCONNECT:
	    if (new_connection) {
		gs_info("Got UDPCONNECT");
		pl->udp.ready = 1;
		pkt_size += create_gameserver_udp_segment(&msg[pkt_size], (uint8_t)EVENT_UDPCONNECT, SENDTOALLPLAYERS, 0);

		char tmsg[MAX_PKT_SIZE];
		uint16_t tpkt_size = create_event_newmaster(&tmsg[8], (uint16_t)s->master_id);
		tpkt_size = create_gameserver_hdr(tmsg, (uint8_t)EVENT_NEWMASTER, SENDTOALLPLAYERS, tpkt_size);
		write(pl->sock, tmsg, tpkt_size);

		tpkt_size = create_event_playerinfos(&tmsg[8], pl->player_id, (uint32_t)pl->points, (uint32_t)pl->trophies);
		tpkt_size = create_gameserver_hdr(tmsg, (uint8_t)EVENT_PLAYERINFOS, SENDTOALLPLAYERS, tpkt_size);
		write(pl->sock, tmsg, tpkt_size);
	    }
	    break;

	  case EVENT_RATE:
	    {
	      uint32_t rate = char_to_uint32(p - 4);
	      gs_info("Got EVENT_RATE[%d] rate %d", pl->player_id, rate);
	      pkt_size += create_gameserver_udp_segment(&msg[pkt_size], (uint8_t)SDO_DUMMY, SENDTOPLAYER, 0);
	    }
	    break;

	  case SDO_DUMMY:
	    break;

	  default:
	    gs_info("GAMESERVER%d - Flag not supported %x", s->game_tcp_port, msg_id);
	    print_gs_data(buf, (long unsigned int)buf_len);
	    break;
	}
    } else {
	send_to_players = send_flag;
    }
  }
  if (pkt_size > 10) {
      uint32_t cli_seq = char_to_uint24(&buf[0]);
      if ((cli_seq & RUDP_FLAG) && send_to_players)
	/* will ack when players ack */
	cli_seq &= RUDP_MASK;
      create_gameserver_udp_header(msg, cli_seq);
      uint16_t pred_cli_time = 0;
      if (pl->udp.last_time)
	pred_cli_time = (uint16_t)(char_to_uint16(&msg[6]) + pl->udp.last_time - (uint16_t)pl->udp.last_update);
      uint16_to_char(pred_cli_time, &msg[8]);
      sendto(s->udp_sock, msg, (size_t)pkt_size, 0,
	     (struct sockaddr*)&pl->udp.addr,
	     (socklen_t)sizeof(struct sockaddr_in));
  }
  /* Broadcast packets to players */
  if (send_to_players)
      send_udp_functions(send_to_players, buf, (uint16_t)buf_len, s, pl->player_id);
  /* Handle timeouts */
  for (int i = 0; i < (int)s->max_players; i++)
  {
    player_t *player = s->p_l[i];
    if (player && player->udp.last_update != 0 && (now - player->udp.last_update) >= 30000) {
      gs_info("GAMESERVER%d - User %s (%d) timed out", s->game_tcp_port, player->username, player->player_id);
      /* Notify lobby to remove player from session */
      lobby_kick_player(s, player->player_id);
      /* Close the client connection */
      shutdown(player->sock, SHUT_RDWR);
    }
  }
  pthread_mutex_unlock(&s->mutex);
  
  return 0;
}

/*
 * Function: gameserver_udp_server_handler
 * --------------------
 *
 * Function that handles incoming udp pkt
 * for the game server
 * 
 *  *data:        ptr to server data struct
 *
 *  returns: void
 *           
 */
void *gameserver_udp_server_handler(void *data) {
  char c_msg[MAX_PKT_SIZE];
  ssize_t read_size = 0;
  int socket_desc = 0, fdmax = 0, flags = 0, ret = 0;
  struct sockaddr_in server = { 0 }, client = { 0 };
  server_data_t *s_data = (server_data_t *)data;
  socklen_t slen = sizeof(client);
  fd_set master, read_fds;
  struct timeval tv;
  
  socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_desc == -1) {
    gs_info("GAMESERVER%d - Could not create socket", s_data->game_tcp_port);
    return 0;
  }
  flags = fcntl(socket_desc, F_GETFL);
  flags |= O_NONBLOCK;
  fcntl(socket_desc, F_SETFL, flags);
  
  int optval = 1;
  setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons( s_data->game_udp_port );
    
  if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0) {
    gs_error("GAMESERVER%d - UDP bind failed. Error", s_data->game_tcp_port);
    return 0;
  }

  FD_ZERO(&master);
  FD_ZERO(&read_fds);
  FD_SET(socket_desc, &master);
  fdmax = socket_desc + 1;
  s_data->udp_sock = socket_desc;
       
  while (1) {
    read_fds = master;
    /* No udp packet in 120 sec */
    tv.tv_sec = 120;
    ret = select(fdmax, &read_fds, NULL, NULL, &tv);
    if (ret == -1) {
      gs_error("GAMSERVER%d  - Error in select", s_data->game_tcp_port);
      break;
    }

    if (ret == 0) {
      gs_info("GAMESERVER%d - No UDP activity...exit", s_data->game_tcp_port);
      if (sqlite3_close(s_data->db) != SQLITE_OK) {
	gs_info("DB is busy during closing");
      }
      gs_info("GAMESERVER%d - Closed the DB", s_data->game_tcp_port);
      close(socket_desc);
      exit(0);
    }
    
    if (FD_ISSET(socket_desc, &read_fds)) {
      read_size = recvfrom(socket_desc, c_msg, sizeof(c_msg), 0, (struct sockaddr *)&client, &slen);
      
      if (read_size < 0) {
	gs_error("GAMESERVER%d - ERROR in recvfrom", s_data->game_tcp_port);
	break;
      }
      if (udp_dump != NULL)
      {
	time_t now = get_time_ms();
	fwrite(&now, sizeof(now), 1, udp_dump);
	fwrite(&client.sin_addr.s_addr, 4, 1, udp_dump);
	fwrite(&client.sin_port, 2, 1, udp_dump);
	fwrite(&read_size, 4, 1, udp_dump);
	fwrite(c_msg, 1, (size_t)read_size, udp_dump);
      }
      udp_msg_handler(c_msg, (int)read_size, s_data, &client);
      memset(c_msg, 0, sizeof(c_msg));
    }
  }
  close(socket_desc);
  
  return 0;
}

/*
 * Function: gs_server_client_handler
 * --------------------
 *
 * Function that handles the Server TCP clients
 * 
 *  *data: ptr to player struct
 *
 *  returns: void
 *
 */
void *gs_gameserver_client_handler(void *data) {
  player_t *pl = (player_t *)data;
  int sock = pl->sock; 
  ssize_t read_size;
  char c_msg[MAX_PKT_SIZE], s_msg[MAX_PKT_SIZE];
  server_data_t *s = pl->server;

  struct timeval tv;
  tv.tv_sec = 1500;       /* Timeout in seconds */
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,(char *)&tv,sizeof(struct timeval));
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(char *)&tv,sizeof(struct timeval));
  
  int index = 0;
  //Receive a message from client
  while ((read_size = recv(sock, &c_msg[index], sizeof(c_msg) - (size_t)index, 0)) > 0) {
    read_size += index;
    index = 0;
    while (read_size > 0) {
      int n_index;
      if ((n_index = parse_gameserver_header(&c_msg[index], (int)read_size)) > 0) {
	memset(s_msg, 0, sizeof(s_msg));
	ssize_t write_size = gameserver_msg_handler(sock, pl, s_msg, &c_msg[index], (int)n_index);
	if (write_size > 0) {
	  write(sock, s_msg, (size_t)write_size);
	}
	else if (write_size < 0) {
	  gs_error("GAMESERVER%d - Client with socket %d is not following protocol - Disconnecting", s->game_tcp_port, sock);
	  close(sock);
	  remove_gameserver_player(pl, s_msg);
	  return 0;
	}
	//Decrease size
	read_size -= n_index;
	//Update pointer in recv buff
	index += n_index;
      } else {
	if (read_size == sizeof(c_msg)) {
	    gs_error("GAMESERVER%d - Client with socket %d large packet - Disconnecting", s->game_tcp_port, sock);
	    close(sock);
	    remove_gameserver_player(pl, s_msg);
	    return 0;
	}
	if (read_size > 0 && index > 0)
	  // move partial packet to beginning of buffer
	  memmove(&c_msg[0], &c_msg[index], (size_t)read_size);
	index = (int)read_size;
	break;
      }
      if (read_size == 0)
	index = 0;
    }
  }
  
  close(sock);
  remove_gameserver_player(pl, s_msg);
  
  return 0;
}

static void signal_handler(int s) {
  gs_info("GAMESERVER%d - Caught signal %d. Exiting", server_data.game_tcp_port, s);
  exit(0);
}

static void delete_pidfile() {
  if (remove(server_data.pidfile) != 0)
    gs_error("GAMESERVER%d - Could not remove %s", server_data.game_tcp_port, server_data.pidfile);
}

static void close_udp_dump() {
  if (udp_dump != NULL)
    fclose(udp_dump);
}

int main (int argc, char *argv[]) {
  int socket_desc , client_sock , c, optval, opt;
  struct sockaddr_in server = { 0 }, client = { 0 };
  uint16_t port = 0;
  uint8_t nr = 0, server_type = 0;
  char *master = NULL, *db_path = NULL;
  
  server_data.lobby_pipe = -1;
  while ((opt = getopt (argc, argv, "p:n:m:d:t:i:v")) != -1) {
    switch (opt) {
    case 'p':
      port = (uint16_t)str2int(optarg);
      break;
    case 'n':
      nr = (uint8_t)str2int(optarg);
      break;
    case 'm':
      if (strlen(optarg) >= MAX_UNAME_LEN || strlen(optarg) == 0) {
	gs_info("GAMESERVER - Not a valid master username");
	return 0;
      }
      master = optarg;
      break;
    case 'd':
      if (strlen(optarg) >= MAX_UNAME_LEN || strlen(optarg) == 0) {
	gs_info("GAMESERVER - Not a valid db path");
	return 0;
      }
      db_path = optarg;
      break;
    case 't':
      server_type = (uint8_t)str2int(optarg);
      break;
    case 'i':
      server_data.lobby_pipe = str2int(optarg);
      break;
    case 'v':
      {
	char fname[128];
	sprintf(fname, "racedata-%d.bin", getpid());
	udp_dump = fopen(fname, "w");
	if (udp_dump != NULL) {
	  gs_info("Dumping race data to %s", fname);
	  atexit(close_udp_dump);
	}
      }
      break;
    }
  }
  
  if (port == 0 || nr == 0 || server_type == 0 || server_data.lobby_pipe == -1) {
    gs_info("GAMESERVER - Missing mandatory fields\n -p <port>\n -n <Number of players>\n -d<DB_PATH> -m<Username of Master> -t <SERVER_TYPE> -i <pipefd>");
    return 0;
  }
  if (master == NULL) {
    gs_info("GAMESERVER - Missing Master username");
    return 0;
  } else {
    strlcpy(server_data.master, master, sizeof(server_data.master));
  }
  if (db_path == NULL) {
    gs_info("GAMESERVER - Missing DB PATH");
    return 0;
  } else {
    strlcpy(server_data.server_db_path, db_path, sizeof(server_data.server_db_path));
  }
  signal(SIGPIPE, signal_handler);
  signal(SIGTERM, signal_handler);
  signal(SIGHUP, signal_handler);
  signal(SIGINT, signal_handler);

  sprintf(server_data.pidfile, "/tmp/gameserver%d.pid", port);
  int fd;
  if ((fd = creat(server_data.pidfile, 644)) < 0) {
    gs_error("Could not create gameserver file %s", server_data.pidfile);
    return 0;
  }
  close(fd);
  atexit(delete_pidfile);

  /* Populate server data struct */
  server_data.max_players = nr;
  server_data.p_l = calloc((size_t)nr, sizeof(player_t *));
  server_data.game_tcp_port = port;
  server_data.game_udp_port = (uint16_t)(port + 2);
  server_data.current_nr_of_players = 0;
  if (server_type == SDO_SERVER)
    server_data.master_id = 1;
  else
    server_data.master_id = (uint16_t)(server_data.max_players + 2);
  server_data.server_type = server_type;
  pthread_mutexattr_t mutexattr;
  pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&server_data.mutex, &mutexattr);
  server_data.session_info[0] = '\0';
    
  //OK - Connect to DB
  server_data.db = open_gs_db(server_data.server_db_path);
  if (server_data.db == NULL) {
    gs_error("Could not connect to database");
    return 0;
  }

  server_data.start_time = get_time_ms();
 
  gs_info("GAMESERVER%d - Starting game server with TCP-Port: %d UDP-port: %d Master: %s Max Players: %d DB PATH: %s SERVER TYPE: %d",
	  server_data.game_tcp_port, server_data.game_tcp_port, server_data.game_udp_port, server_data.master, server_data.max_players, server_data.server_db_path, server_data.server_type);
  
  socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_desc == -1) {
    gs_info("GAMESERVER%d - Could not create socket", server_data.game_tcp_port);
    sqlite3_close(server_data.db);
    return 0;
  }

  optval = 1;
  setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));
  
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons(server_data.game_tcp_port);
  
  if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0) {
    gs_error("Bind failed. Error");
    sqlite3_close(server_data.db);
    return 0;
  }

  listen(socket_desc , 3);
  
  pthread_t thread_id;
  c = sizeof(struct sockaddr_in);

  pthread_t thread_id_udp;
  if( pthread_create(&thread_id_udp, NULL, gameserver_udp_server_handler, (void*)&server_data) < 0) {
    perror("Could not create thread");
    sqlite3_close(server_data.db);
    return 0;
  }
  pthread_detach(thread_id_udp);
    
  while ((client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) >= 0) {
    if (server_data.locked) {
      gs_error("Game server locked. Connection refused");
      close(client_sock);
      continue;
    }
    //Store player data
    player_t *pl = (player_t *)calloc(1, sizeof(player_t));
    pl->addr = client;
    pl->sock = client_sock;
    pl->server = &server_data;
    pl->udp.last_update = get_time_ms();
    if (!add_gameserver_player(&server_data, pl)) {
      free(pl);
      close(client_sock);
      continue;
    }
    
    if (pthread_create(&thread_id, NULL, gs_gameserver_client_handler, (void*)pl) < 0) {
      gs_error("GAMESERVER%d - Could not create thread", server_data.game_tcp_port);
      break;
    }
    pthread_detach(thread_id);
  }

  if (client_sock < 0)
    gs_error("GAMESERVER%d - Accept failed", server_data.game_tcp_port);
  sqlite3_close(server_data.db);

  return 0;
}
