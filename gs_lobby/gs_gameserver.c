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
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "gs_gameserver.h"
#include "gs_sql.h"
#include "../gs_common/gs_common.h"

void send_functions(uint8_t send_flag, char* msg, uint16_t pkt_size, server_data_t *s, uint16_t player_id) {
  int i;
  
  switch(send_flag) {
  case SENDTOOTHERPLAYERS:
    for(i = 0; i < s->max_players; i++) {
      if (s->p_l[i] && (s->p_l[i]->player_id != player_id))
	write(s->p_l[i]->sock, msg, pkt_size);
    }
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
        
    for(i = 0; i < s->max_players; i++) {
      if (s->p_l[i] && (s->p_l[i]->player_id == player_id)) {
	write(s->p_l[i]->sock, msg, pkt_size);
	return;
      }
    }
    break;;
  case SENDTOALLPLAYERS:
    for(i = 0; i < s->max_players; i++) {
      if (s->p_l[i])
	write(s->p_l[i]->sock, msg, pkt_size);
    }
    break;;
  default:
    gs_info("GAMESERVER%d - Flag not supported %u", s->game_tcp_port, send_flag);
  }
}

void send_udp_functions(uint8_t send_flag, char* msg, uint16_t pkt_size, server_data_t *s, uint16_t player_id) {
  int i;
 
  switch(send_flag) {
  case SENDTOOTHERPLAYERS:
    for(i = 0; i < s->max_players; i++) {
      if (s->p_l[i] && (s->p_l[i]->player_id != player_id))
	sendto(s->udp_sock, msg, (size_t)pkt_size, 0,
	       (struct sockaddr*)&s->p_l[i]->udp_addr,
	       (socklen_t)sizeof(struct sockaddr_in));
    }
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
        
    for(i = 0; i < s->max_players; i++) {
      if (s->p_l[i] && (s->p_l[i]->player_id == player_id)) {
	sendto(s->udp_sock, msg, (size_t)pkt_size, 0,
	       (struct sockaddr*)&s->p_l[i]->udp_addr,
	       (socklen_t)sizeof(struct sockaddr_in));
	return;
      }
    }
    break;;
  case SENDTOALLPLAYERS:
    for(i = 0; i < s->max_players; i++) {
      if (s->p_l[i])
	sendto(s->udp_sock, msg, (size_t)pkt_size, 0,
	       (struct sockaddr*)&s->p_l[i]->udp_addr,
	       (socklen_t)sizeof(struct sockaddr_in));
    }
    break;;
  default:
    gs_info("GAMESERVER%d - Flag not supported %x", s->game_tcp_port, send_flag);
    print_gs_data(msg, (long unsigned int)pkt_size);
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

int serverSeq = 1;

uint16_t create_gameserver_udp_hdr(char* msg, uint cliSeq, uint8_t msg_id, uint8_t msg_flag, uint16_t msg_size)
{
  msg[0] = serverSeq >> 16;
  msg[1] = serverSeq >> 8;
  msg[2] = serverSeq;
  serverSeq++;
  msg[3] = cliSeq >> 16;
  msg[4] = cliSeq >> 8;
  msg[5] = cliSeq;
  memset(&msg[6], 0, 4);	// no times?
  // clients send its time in ms in msg[6-7]
  // sends something in msg[8-9]?? ~500

  msg[10] = msg_size + 4;
  msg[11] = 0x10 | msg_flag;
  msg[13] = msg_id;

  return msg_size + 14;
}

/* Create new player message */
uint16_t create_event_newplayer(char* msg, uint16_t playerid, char* username) {
  uint16_t pkt_size = 0;
  char un_buf[15];
  memset(un_buf, 0, sizeof(un_buf));
  strlcpy(un_buf, username, strlen(username)+1);

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
uint16_t create_event_servertime(char* msg, struct timespec start_time) {
  uint16_t pkt_size = 0;
  struct timespec end_time;
  clock_gettime(CLOCK_REALTIME, &end_time);
  uint32_t elapsed_sec = 0, elapsed_msec = 0;

  elapsed_sec = (uint32_t)(end_time.tv_sec);
  elapsed_msec = (uint32_t)((end_time.tv_nsec)/1000000);
  
  memcpy(msg, &elapsed_sec, sizeof(uint32_t));
  memcpy(&msg[4], &elapsed_msec, sizeof(uint32_t));
  pkt_size = sizeof(uint32_t)*2;
  
  return (uint16_t)pkt_size;
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
  memset(pl->username, 0, MAX_UNAME_LEN);

  pl->is_master = 0;
  pl->udp_ready = 0;
  pl->player_id = 0;
  
  for(i=0;i<max_players;i++) {
    if(!(s->p_l[i])) {
      s->p_l[i] = pl;
      gs_info("GAMESERVER%d - Added player with sock: %d", s->game_tcp_port, pl->sock);
      return 1;
    }
  }
  gs_info("GAMESERVER%d - Could not add player with sock: %d", s->game_tcp_port, pl->sock);
  gs_info("GAMSERVER%d - Server full", s->game_tcp_port);
  return 0; 
}

void remove_gameserver_player(player_t *pl, char* msg) {
  server_data_t *s = pl->data;
  int max_players = s->max_players;
  uint16_t pkt_size = 0;
  int i=0;

  /* Send player left */
  pkt_size = create_event_playerleft(&msg[8], pl->player_id);
  pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_PLAYERLEFT, SENDTOSERVER, pkt_size);
  send_functions(SENDTOOTHERPLAYERS, msg, pkt_size, s, pl->player_id);

  /* If master left, change to the next in list */
  if(pl->is_master == 1) {
    for(i=0;i<max_players;i++) {
      if ( s->p_l[i] && s->p_l[i]->player_id != pl->player_id) {
	s->master_id = s->p_l[i]->player_id;
	strlcpy(s->master, pl->username, strlen(pl->username) + 1);
	s->p_l[i]->is_master = 1;
	gs_info("Master left the game, change to 0x%02x", s->master_id);
	pkt_size = create_event_newmaster(&msg[8], (uint16_t)s->master_id);
	pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_NEWMASTER, SENDTOSERVER, pkt_size);
	send_functions(SENDTOOTHERPLAYERS, msg, pkt_size, s, pl->player_id);
	break;
      }
    }
  }

  /* Find and remove user */
  for(i=0;i<max_players;i++) {
    if (s->p_l[i] && s->p_l[i]->player_id == pl->player_id) {
      gs_info("GAMESERVER%d - Removed player with 0x%02x", s->game_tcp_port, pl->player_id);
      s->p_l[i] = NULL;
      s->current_nr_of_players = (uint8_t)(s->current_nr_of_players - 1);
    }
  }

  return;
}

/*
 * Function: get_user_from_addr
 * --------------------
 *
 * Returns player struct from addr
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
      if((s->p_l[i]->addr.sin_addr.s_addr == addr->sin_addr.s_addr)) {
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
uint16_t gameserver_msg_handler(int sock, player_t *pl, char *msg, char *buf, int buf_len) {
  server_data_t *s = (server_data_t *)pl->data;
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

      strlcpy(pl->username, &buf[8], strlen(&buf[8])+1);
      gs_info("GAMESERVER%d - User %s joined the Game Server", s->game_tcp_port, pl->username);
      if ((strcmp(pl->username, s->master)) == 0) {
	pl->is_master = 1;
	gs_info("GAMESERVER%d - User is Game Master", s->game_tcp_port);
	pl->player_id = 1;
	s->master_id = 1;
      } else {
	gs_info("GAMESERVER%d - User is not Game Master", s->game_tcp_port);
	pl->player_id = 1;
	for (int i = 0; i < s->max_players; i++)
	  if (s->p_l[i] && s->p_l[i]->player_id >= pl->player_id)
	    pl->player_id = s->p_l[i]->player_id;
	pl->player_id += 1;
      }
      gs_info("GAMESERVER%d - Player got id: 0x%02x", s->game_tcp_port, pl->player_id);
     
      pkt_size = create_event_ownid(&msg[8], pl->player_id, s->current_nr_of_players + 1, s->max_players);
      pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_OWNID, SENDTOALLPLAYERS, pkt_size);
      write(pl->sock, msg, pkt_size);

      rc = load_player_record(s->db, pl->username, &pl->points, &pl->trophies);
      if (rc != 1) {
	gs_info("Could not fetch Points and Trophies for user %s", pl->username);
	pl->trophies = 0;
	pl->points = 0;
      }

      /* New user added */
      s->current_nr_of_players = (uint8_t)(s->current_nr_of_players + 1);
      
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
	strlcpy(uname_tmp, &buf[8], 16);
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
	strlcpy(track_tmp, &buf[8], 16);
	strlcpy(uname_tmp, &buf[24], 16);
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
	strlcpy(track_tmp, &buf[8], 16);
	strlcpy(uname_tmp, &buf[24], 16);
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
	strlcpy(track_tmp, &buf[8], 16);
	strlcpy(uname_tmp, &buf[24], 16);
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
	strlcpy(track_tmp, &buf[8], 16);
	strlcpy(uname_tmp, &buf[24], 16);
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
    	  /*
    	    D Class:
    	    Europa $17'500
	    Virtuose $15'000
	    Montana $15'000
	    Desert $10'000
	    Thunder $10'000

	    C Class:
	    Belray $40'000
	    Indy Gt1 $65'000
	    Orion $55'000
	    Special $50'000
	    Spacecab $45'000
	    Duffingburg $60'000

	    B Class:
	    Solaris $120'000
	    Cortex $180'000
	    Firebug $140'000
	    Husky $160'000
	    Gunzzo $220'000
	    Goliath $200'000

	    A Class:
	    V Wings $450000
	    LA Millenium $550000
	    Mistery X $65000
	    Macro F1 $750000
	    Alien $850000
	    */
	  static const uint32_t carPrices[] = {
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
    	  pkt_size = uint32_to_char((uint32_t)count, &msg[8]);	// list size (be)
    	  for (size_t i = 0; i != count; i++)
    	  {
    	    pkt_size += uint32_to_char(1, &msg[8 + pkt_size]);            // type=car
    	    pkt_size += uint32_to_char((uint32_t)i, &msg[8 + pkt_size]);  // car #
    	    msg[8 + pkt_size++] = 0;                                      // name (ignored)
    	    pkt_size += uint32_to_char(carPrices[i], &msg[8 + pkt_size]); // price
    	    msg[8 + pkt_size++] = 0;
    	    msg[8 + pkt_size++] = 0;
    	  }
    	  /*
    	  pkt_size = uint32_to_char(6, &msg[8]);	// list size (be)
    	  for (int i = 0; i < 6; i++) {
    		  pkt_size += uint32_to_char(2, &msg[8 + pkt_size]);	// type=tire
    		  pkt_size += uint32_to_char(i, &msg[8 + pkt_size]);	// tires #
    		  pkt_size += uint32_to_char((i + 1) * 100, &msg[8 + pkt_size]); // price
    	  }
    	  */
      }
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_PRICES_LIST, SENDTOPLAYER, pkt_size);
      write(pl->sock, msg, pkt_size);
      pkt_size = 0;
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
      pkt_size = 0;
      /*
      for (int i = 0; i < 21; i++) {
    	  unsigned v = 1;
    	  pkt_size += (uint16_t)uint32_to_char(v, &msg[8 + pkt_size]);
      }
      */
      {
	    int data[436] = {};
	    // FIXME cash won doesn't account towards driver points
	    // Ranking bonuses
	    // class D
	    data[0] = 13000;	// #1
	    data[1] = 7700;	// #2
	    data[2] = 4000;	// #3
	    data[3] = 2000;	// #4
	    data[4] = 1000;	// #5
	    // class C
	    data[5] = 16200;	// #1
	    data[6] = 9600;	// #2
	    data[7] = 4800;	// #3
	    data[8] = 2400;	// #4
	    data[9] = 960;	// #5
	    // class B
	    data[10] = 20200;	// #1
	    data[11] = 12000;	// #2
	    data[12] = 6000;	// #3
	    data[13] = 3000;	// #4
	    data[14] = 1200;	// #5
	    // class A
	    data[15] = 25200;	// #1
	    data[16] = 15000;	// #2
	    data[17] = 7500;	// #3
	    data[18] = 3750;	// #4
	    data[19] = 1500;	// #5

	    data[22] = 100;	// ?
	    data[23] = 100;	// ?

	    data[26] = 160000;	// class C points
	    data[27] = 800000;	// class B points
	    data[28] = 4000000;	// class A points

	    data[33] = 1500;	// race bonus 1
	    data[34] = 1650;
	    data[35] = 1750;
	    data[36] = 1900;
	    data[37] = 1500;	// race bonus 2
	    data[38] = 1650;
	    data[39] = 1750;
	    data[40] = 1900;
	    data[41] = 1500;	// race bonus 3
	    data[42] = 1650;
	    data[43] = 1750;
	    data[44] = 1900;

	    data[45] = 1000;	// radar busted premiums (per class)
	    data[46] = 1150;
	    data[47] = 1250;
	    data[48] = 1400;
	    data[49] = 16;	// radar busted bonus per mph (per class)
	    data[50] = 18;
	    data[51] = 20;
	    data[52] = 22;
	    memcpy(&msg[8], data, sizeof(data));
	    pkt_size = sizeof(data);
      }
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_GAME_DEFINES, SENDTOPLAYER, pkt_size);
      write(pl->sock, msg, pkt_size);
      pkt_size = 0;
      break;

    case SDO_DBINFO_PLAYERDATA:
      gs_info("Got DBINFO_PLAYERDATA");
      print_gs_data(buf, (long unsigned int)buf_len);
      // 6 ints(le)			-> offset 0
      //   0: driver points (or next class?)
      //   1: user cash
      //   5: seasons played
      // 16 bytes
      // 1 byte
      // 10 * 101 bytes		-> offset 0x200, cars
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
      // TODO need to have regular tires in inventory or freeze when selecting tires w/o buying first
      pkt_size = 0;
      // Fetch from database
      {
	int size = MAX_PKT_SIZE - 8;
	if (load_player_data(s->db, pl->username, (uint8_t *)&msg[8], &size) != 1) {
	    // TODO error?
	}
	else if (size != 0)
	{
	  pkt_size = size;
	  for (int i = 0; i < 10; i++)
	  {
            size = MAX_PKT_SIZE - 8 - pkt_size;
	    load_player_car(s->db, pl->username, i, (uint8_t *)&msg[8 + pkt_size], &size);
	    if (size != 101) {
		msg[8 + pkt_size] = 0xff;
		size = 101;
	    }
	    pkt_size += size;
	  }
	  pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_DBINFO_PLAYERDATA, SENDTOPLAYER, pkt_size);
	  break;
	}
      }
      // Create a new user
      for (int i = 0; i < 10; i++) {
    	*(int *)&msg[8 + pkt_size] = i == 1 ? 100000 : 0;	// need $10'000 to start with
	    pkt_size += 4;
      }
      msg[8 + pkt_size++] = '\0';
      for (int i = 0; i < 10; i++) {
    	  memset(&msg[8 + pkt_size], 0, 101);
    	  msg[8 + pkt_size] = 0xff;
    	  pkt_size += 101;
      }
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_DBINFO_PLAYERDATA, SENDTOPLAYER, pkt_size);
      write(pl->sock, msg, pkt_size);
      pkt_size = 0;
      break;

    case SDO_DBUPDATE_PLAYERSTAT:
      gs_info("Got DBUPDATE_PLAYERSTAT");
      // TODO it's called 3 times in a row. is it expecting a reply?
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
	if (size != 0)
	  size += 2;
	pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_DBINFO_FULLSTATS, SENDTOPLAYER, size);
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
      strcpy(&msg[8], "Welcome to DCNet Speed Devils server!");
      pkt_size = strlen("Welcome to DCNet Speed Devils server!") + 1;
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_REQUEST_MOTD, SENDTOPLAYER, pkt_size);
      write(pl->sock, msg, pkt_size);
      pkt_size = 0;
      break;

    case SDO_UPDATE_SESSION_INFO:
      gs_info("Got SDO_UPDATE_SESSION_INFO");
      print_gs_data(buf, (long unsigned int)buf_len);
      // 0000 | 00 00 2D 40 04 03 00 8D 00 00 00 00 00 00 00 00 | ..-@............
      // 0010 | 05 00 00 00 00 30 20 30 20 30 20 30 20 30 20 30 | .....0 0 0 0 0 0
      //   or   05 8C FE nn nn 30 20 30 20 30 20 30 20 30 20 30 | .....0 0 0 0 0 0  with nnnn increasing
      // 0020 | 20 35 20 32 20 34 20 34 20 31 20 30 00          |  5 2 4 4 1 0.
      pkt_size = buf_len - 24 - 8;
      memcpy(msg + 8, buf + 8, pkt_size);
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_UPDATE_SESSION_INFO, SENDTOPLAYER, pkt_size);	// send back beginning of packet
      msg[5] = 0x04; // from server??
      write(pl->sock, msg, pkt_size);
      pkt_size = 0;
      break;

    case SDO_LOCK_ROOM:
      gs_info("Got SDO_LOCK_ROOM");
      print_gs_data(buf, (long unsigned int)buf_len);
      // FIXME don't have access to the session but this seems to work for other players in the game
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_LOCK_ROOM, SENDTOALLPLAYERS, 0);
      send_functions(SENDTOOTHERPLAYERS, msg, (uint16_t)pkt_size, s, pl->player_id);
      pkt_size = 0;
      break;

    case SDO_UNLOCK_ROOM:
      gs_info("Got SDO_UNLOCK_ROOM");
      print_gs_data(buf, (long unsigned int)buf_len);
      pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_UNLOCK_ROOM, SENDTOALLPLAYERS, 0);
      send_functions(SENDTOOTHERPLAYERS, msg, (uint16_t)pkt_size, s, pl->player_id);
      pkt_size = 0;
      break;

    // TODO case SDO_GETBESTLAP:

    default:
      gs_info("GAMESERVER%d - Flag not supported %x", s->game_tcp_port, recv_flag);
      print_gs_data(buf, (long unsigned int)buf_len);
      return 0;
    }
  } else if (send_flag == SENDTOPLAYER) {
    if (recv_size >= 0xA)
      send_functions(send_flag, buf, (uint16_t)buf_len, s, ntohs(char_to_uint16(&buf[0x08])));
  } else {
    send_functions(send_flag, buf, (uint16_t)buf_len, s, pl->player_id);
  }

  return pkt_size;
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
  uint16_t recv_size = 0, pkt_size = 0;
  uint8_t send_flag = 0;
  uint8_t msg_id = 0;
  char msg[MAX_PKT_SIZE];
  int i = 0;
  
  player_t* pl = NULL;
  
  if ( ( pl = ( get_user_from_addr(s, client))) == NULL )  {
    gs_info("GAMESERVER%d - Invalid user", s->game_tcp_port);
    return 0;
  }

  int new_connection = 0;
  if (pl->udp_ready == 0) {
    pl->udp_addr = *client;
    pl->udp_ready = 1;
    new_connection = 1;
  }

  /* Parse header */
  if (buf_len < 10) {
	  gs_info("GAMESERVER%d - Small UDP msg ignored (%d bytes)", s->game_tcp_port, buf_len);
    return 0;
  }
  unsigned cliSeq = ((buf[0] & 0xff) << 16) | ((buf[1] & 0xff) << 8) | (buf[2] & 0xff);
  char *p = &buf[10];
  while (p - buf < buf_len)
  {
    int size = *p & 0xff;
    msg_id = p[3] & 0xff;
    send_flag = p[1] & 0xf;
    p += size;
    if (p - buf > buf_len)
      break;
  
    if (send_flag == SENDTOSERVER)
    {
	  switch(msg_id) {
	    case EVENT_UDPCONNECT:
	      if (new_connection) /* s->max_players == s->current_nr_of_players) */ {
	    	gs_info("Got UDPCONNECT\n");
		    pkt_size = create_gameserver_udp_hdr(msg, cliSeq, (uint8_t)EVENT_UDPCONNECT, SENDTOALLPLAYERS, 0);
		    sendto(s->udp_sock, msg, (size_t)pkt_size, 0,
			   (struct sockaddr*)&pl->udp_addr,
			   (socklen_t)sizeof(struct sockaddr_in));

		    for(i = 0; i < s->max_players; i++) {
			  if ( s->p_l[i] && s->p_l[i]->player_id != pl->player_id) {
				memset(msg, 0, MAX_PKT_SIZE);
				pkt_size = create_event_newplayer(&msg[8], (uint16_t)s->p_l[i]->player_id, s->p_l[i]->username);
				pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_NEWPLAYER, SENDTOALLPLAYERS, pkt_size);
				write(pl->sock, msg, pkt_size);
			  }
		    }
            pkt_size = create_event_newplayer(&msg[8], (uint16_t)pl->player_id, pl->username);
            pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_NEWPLAYER, SENDTOALLPLAYERS, pkt_size);
            send_functions(SENDTOOTHERPLAYERS, msg, pkt_size, s, pl->player_id);

		    pkt_size = create_event_newmaster(&msg[8], (uint16_t)s->master_id);
		    pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_NEWMASTER, SENDTOALLPLAYERS, pkt_size);
		    write(pl->sock, msg, pkt_size);

		    pkt_size = create_event_playerinfos(&msg[8], pl->player_id, (uint32_t)pl->points, (uint32_t)pl->trophies);
		    pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_PLAYERINFOS, SENDTOALLPLAYERS, pkt_size);
		    write(pl->sock, msg, pkt_size);
		    
		    pkt_size = create_gameserver_hdr(msg, (uint8_t)SDO_IN_WAITROOM, SENDTOOTHERPLAYERS, 0);
            *(uint16_t *)&msg[5] = s->master_id;
            write(pl->sock, msg, pkt_size);
	      }
	      break;

	    case EVENT_RATE:
	      {
	    	gs_info("Got EVENT_RATE %d\n", char_to_uint32(p - 4));
	    	pkt_size = create_gameserver_udp_hdr(msg, cliSeq, (uint8_t)EVENT_RATE, SENDTOPLAYER, 4);
	    	memcpy(&msg[14], p - 4, 4);
	    	sendto(s->udp_sock, msg, (size_t)pkt_size, 0,
	    				   (struct sockaddr*)&pl->udp_addr,
	    				   (socklen_t)sizeof(struct sockaddr_in));
	      }
	      break;

	    default:
	      gs_info("GAMESERVER%d - Flag not supported %x", s->game_tcp_port, msg_id);
	      print_gs_data(buf, (long unsigned int)buf_len);
	      break;
	  }
    } else if (send_flag == SENDTOPLAYER) {
	  if (recv_size >= 0x12) {
	    send_udp_functions(send_flag, buf, (uint16_t)buf_len, s, ntohs(char_to_uint16(&buf[0x10])));
	  }
    } else {
	  send_udp_functions(send_flag, buf, (uint16_t)(buf_len), s, pl->player_id);
    }
  }
  
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
      return 0;
    }

    if (ret == 0) {
      gs_info("GAMESERVER%d - No UDP activity...exit", s_data->game_tcp_port);
      if ( remove(s_data->pidfile) != 0 )
	gs_error("Could not remove %s", s_data->pidfile);

      if (sqlite3_close(s_data->db) != SQLITE_OK) {
	gs_info("DB is busy during closing");
      }
      gs_info("GAMESERVER%d - Closed the DB", s_data->game_tcp_port);
      exit(0);
    }
    
    if (FD_ISSET(socket_desc, &read_fds)) {
      read_size = recvfrom(socket_desc, c_msg, sizeof(c_msg), 0, (struct sockaddr *)&client, &slen);
      
      if (read_size < 0) {
	gs_error("GAMESERVER%d - ERROR in recvfrom", s_data->game_tcp_port);
	if ( remove(s_data->pidfile) != 0 )
	  gs_error("Could not remove %s", s_data->pidfile);
	exit(0);
      }
      
      udp_msg_handler(c_msg, (int)read_size, s_data, &client);
      memset(c_msg, 0, sizeof(c_msg));
    }
  }
  
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
  ssize_t read_size=0;
  size_t write_size=0;
  char c_msg[MAX_PKT_SIZE], s_msg[MAX_PKT_SIZE];
  memset(c_msg, 0, sizeof(c_msg));
  memset(s_msg, 0, sizeof(s_msg));
  server_data_t *s = (server_data_t *)pl->data;

  struct timeval tv;
  tv.tv_sec = 1500;       /* Timeout in seconds */
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,(char *)&tv,sizeof(struct timeval));
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(char *)&tv,sizeof(struct timeval));
  
  int index = 0;
  //Receive a message from client
  while( (read_size = recv(sock, &c_msg[index], sizeof(c_msg) - index, 0)) > 0 ) {
    read_size += index;
    index = 0;
    while(read_size > 0) {
      int n_index;
      if ((n_index = parse_gameserver_header(&c_msg[index], (int)read_size)) > 0) {
	write_size = (ssize_t)gameserver_msg_handler(sock, pl, s_msg, &c_msg[index], (int)n_index);
	if (write_size > 0) {
	  write(sock, s_msg, write_size);
	}
	if (write_size < 0) {
	  gs_error("GAMESERVER%d - Client with socket %d is not following protocol - Disconnecting", s->game_tcp_port, sock);
	  close(sock);
	  remove_gameserver_player(pl, s_msg);
	  free(pl);
	  return 0;
	}
	//Decrease size
	read_size -= n_index;
	//Update pointer in recv buff
	index += n_index;
      } else {
	if (read_size > 0)
	  // move partial packet to beginning of buffer
	  memmove(&c_msg[0], &c_msg[index], read_size);
	index = read_size;
	break;
      }
      memset(s_msg, 0, sizeof(s_msg));
      if (read_size == 0)
	index = 0;
    }
    fflush(stdout);
  }
  
  close(sock);
  fflush(stdout);

  remove_gameserver_player(pl, s_msg);
  free(pl);

  if (s->current_nr_of_players == 0) {
    gs_info("GAMESERVER%d - Server is empty...exit", s->game_tcp_port);

    if ( remove(s->pidfile) != 0 )
      gs_error("Could not remove %s", s->pidfile);

    if (sqlite3_close(s->db) != SQLITE_OK) {
      gs_info("DB is busy during closing");
    }
    gs_info("GAMESERVER%d - Closed the DB", s->game_tcp_port);
    exit(0);
  }
  
  return 0;
}

int main (int argc, char *argv[]) {
  server_data_t s_data = { 0 };
  int socket_desc , client_sock , c, optval, i, opt;
  struct sockaddr_in server = { 0 }, client = { 0 };
  uint16_t port = 0;
  uint8_t nr = 0, server_type = 0;
  char *master = NULL, *db_path = NULL;
  
  while ((opt = getopt (argc, argv, "p:n:m:d:t:")) != -1) {
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
    }
  }
  
  if (port == 0 || nr == 0 || server_type == 0) {
    gs_info("GAMESERVER - Missing mandatory fields\n -p <port>\n -n <Number of players>\n -d<DB_PATH> -m<Username of Master -t <SERVER_TYPE>>");
    return 0;
  }
  if (master == NULL) {
    gs_info("GAMESERVER - Missing Master username");
    return 0;
  } else {
    strlcpy(s_data.master, master, strlen(master)+1);
  }
  if (db_path == NULL) {
    gs_info("GAMESERVER - Missing DB PATH");
    return 0;
  } else {
    strlcpy(s_data.server_db_path, db_path, strlen(db_path)+1);
  }

  sprintf(s_data.pidfile, "/tmp/gameserver%d.pid", port);
  if ( creat( s_data.pidfile, 644 ) < 0 ) {
    gs_error("Could not create gameserver file %s", s_data.pidfile);
    return 0;
  }

  /* Populate server data struct */
  s_data.max_players = nr;
  s_data.p_l = calloc((size_t)nr, sizeof(server_data_t *));
  for (i = 0; i < s_data.max_players; i++)
    s_data.p_l[i] = NULL;
  s_data.game_tcp_port = port;
  s_data.game_udp_port = (uint16_t)(port + 2);
  s_data.current_nr_of_players = 0;
  s_data.master_id = (uint16_t)(s_data.max_players + 2);
  s_data.server_type = server_type;
    
  //OK - Connect to DB
  s_data.db = open_gs_db(s_data.server_db_path);
  if (s_data.db == NULL) {
    gs_error("Could not connect to database");
    return 0;
  }

  clock_gettime(CLOCK_REALTIME, &s_data.start_time);
 
  gs_info("GAMESERVER%d - Starting game server with TCP-Port: %d UDP-port: %d Master: %s Max Players: %d DB PATH: %s SERVER TYPE: %d",
	  s_data.game_tcp_port, s_data.game_tcp_port, s_data.game_udp_port, s_data.master, s_data.max_players, s_data.server_db_path, s_data.server_type);
  
  socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_desc == -1) {
    gs_info("GAMESERVER%d - Could not create socket", s_data.game_tcp_port);
    sqlite3_close(s_data.db);
    return 0;
  }

  optval = 1;
  setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));
  
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons( s_data.game_tcp_port );
  
  if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0) {
    gs_error("Bind failed. Error");
    sqlite3_close(s_data.db);
    return 0;
  }

  listen(socket_desc , 3);
  
  pthread_t thread_id;
  c = sizeof(struct sockaddr_in);

  pthread_t thread_id_udp;
  if( pthread_create( &thread_id_udp , NULL ,  gameserver_udp_server_handler , (void*)&s_data) < 0) {
    perror("Could not create thread");
    sqlite3_close(s_data.db);
    return 0;
  }
  pthread_detach(thread_id_udp);
    
  while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) ) {
    //Store player data
    player_t *pl = (player_t *)malloc(sizeof(player_t));
    pl->addr = client;
    pl->sock = client_sock;
    pl->data = &s_data;
    if (!add_gameserver_player(&s_data, pl)) {
      free(pl);
      return 0;
    }
    
    if( pthread_create( &thread_id , NULL ,  gs_gameserver_client_handler , (void*)pl) < 0) {
      gs_error("GAMESERVER%d - Could not create thread", s_data.game_tcp_port);
      sqlite3_close(s_data.db);
      return 0;
    }
    pthread_detach(thread_id);
  }
  
  if (client_sock < 0) {
    gs_error("GAMESERVER%d - Accept failed", s_data.game_tcp_port);
    sqlite3_close(s_data.db);
    return 0;
  }
  
  return 0;
}
