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
 * UDP game server for POD and Monaco Racing 2
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "gs_gameserver.h"
#include "../gs_common/gs_common.h"

void pod_send_udp_player(player_t *player, char *msg, size_t size) {
  sendto(player->server->udp_sock, msg, size, 0,
	 (struct sockaddr*)&player->udp.addr,
	 (socklen_t)sizeof(struct sockaddr_in));
}

static uint16_t create_gameserver_udp_hdr(char* msg, uint8_t msg_id, uint8_t msg_flag, uint16_t msg_size) {

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

/*
 * Function: pod_udp_msg_handler
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
int pod_udp_msg_handler(char *buf, size_t size, server_data_t *server, struct sockaddr_in *client) {
  uint16_t recv_size = 0, pkt_size = 0;
  uint8_t send_flag = 0;
  uint8_t recv_flag = 0;
  char msg[MAX_PKT_SIZE];
  int i = 0;
  
  player_t* pl = NULL;
  pthread_mutex_lock(&server->mutex);
  if ( ( pl = ( get_user_from_addr(server, client))) == NULL )  {
    pthread_mutex_unlock(&server->mutex);
    gs_info("GAMESERVER%d - Invalid user", server->game_tcp_port);
    return 0;
  }

  if (pl->udp.ready == 0) {
    pl->udp.addr = *client;
    pl->udp.ready = 1;
  }			  

  /* Parse header */
  if (size < 16) {
    pthread_mutex_unlock(&server->mutex);
    return 0;
  }

  recv_size = char_to_uint16(&buf[1]);
  send_flag = (uint8_t)buf[4];
  recv_flag = (uint8_t)buf[15];
    
  if(recv_size > size) {
    pthread_mutex_unlock(&server->mutex);
    return 0;
  }
  
  if (send_flag == SENDTOSERVER) {
    switch(recv_flag) {
    case EVENT_UDPCONNECT:
      if (server->max_players == server->current_nr_of_players) {
	pkt_size = create_gameserver_udp_hdr(msg, (uint8_t)EVENT_UDPCONNECT, SENDTOALLPLAYERS, 0);
	pod_send_udp_player(pl, msg, pkt_size);
	
	for(i = 0; i < MAX_PLAYERS; i++) {
	  if (server->players[i] && server->players[i]->player_id != pl->player_id) {
	    memset(msg, 0, MAX_PKT_SIZE);
	    pkt_size = create_event_newplayer(&msg[8], (uint16_t)server->players[i]->player_id, server->players[i]->username);
	    pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_NEWPLAYER, SENDTOALLPLAYERS, pkt_size);
	    write(pl->sock, msg, pkt_size);
	  }
	}

	pkt_size = create_event_newmaster(&msg[8], (uint16_t)server->master_id);
	pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_NEWMASTER, SENDTOALLPLAYERS, pkt_size);
	write(pl->sock, msg, pkt_size);

	pkt_size = create_event_playerinfos(&msg[8], pl->player_id, (uint32_t)pl->points, (uint32_t)pl->trophies);
	pkt_size = create_gameserver_hdr(msg, (uint8_t)EVENT_PLAYERINFOS, SENDTOALLPLAYERS, pkt_size);
	write(pl->sock, msg, pkt_size);
      }
	
      break;
    default:
      gs_info("GAMESERVER%d - Flag not supported %u", server->game_tcp_port, recv_flag);
      print_gs_data(buf, size);
      break;
    }
  } else if (send_flag == SENDTOPLAYER) {
    if (recv_size >= 0x12) {
      send_udp_functions(send_flag, buf, (uint16_t)size, server, ntohs(char_to_uint16(&buf[0x10])));
    }
  } else {
    send_udp_functions(send_flag, buf, (uint16_t)size, server, pl->player_id);
  }
  pthread_mutex_unlock(&server->mutex);

  return 0;
}
