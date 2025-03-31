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
 * UDP game server for Speed Devils Online
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "gs_gameserver.h"
#include "../gs_common/gs_common.h"

#define RUDP_FLAG 0x800000
#define RUDP_MASK 0x7FFFFF

static uint32_t serverSeq = 1;

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

void sdo_send_udp_player(player_t *player, char* msg, size_t pkt_size)
{
  uint32_t last_ack_seq = serverSeq;
  uint32_t last_rel_ack_seq = serverSeq;
  for (int i = 0; i < MAX_PLAYERS; i++) {
      player_t *pl = player->server->players[i];
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

  sendto(player->server->udp_sock, msg, pkt_size, 0,
	 (struct sockaddr*)&player->udp.addr,
	 (socklen_t)sizeof(struct sockaddr_in));
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

  return (uint16_t)(msg_size + 4);
}

/*
 * Function: sdo_udp_msg_handler
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
int sdo_udp_msg_handler(char* buf, size_t buf_len, server_data_t *s, struct sockaddr_in *client) {
  char msg[MAX_PKT_SIZE];

  if (buf_len < 10) {
    gs_info("Small UDP msg ignored (%zd bytes)", buf_len);
    return 0;
  }

  player_t* pl = NULL;
  pthread_mutex_lock(&s->mutex);
  if ((pl = get_user_from_addr(s, client)) == NULL) {
    pthread_mutex_unlock(&s->mutex);
    gs_info("Invalid user");
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
    if (size < 4 || p + size > buf + buf_len) {
	send_to_players = -1;
	gs_info("UDP segment over/underflow from %s: size %d", pl->username, size);
	break;
    }
    uint8_t msg_id = (uint8_t)(p[3] & 0xff);
    int send_flag = p[1] & 0xf;
    p += size;

    if (send_flag == SENDTOSERVER)
    {
	switch(msg_id) {
	  case EVENT_UDPCONNECT:
	    if (new_connection) {
		gs_info("Got UDPCONNECT");
		pl->udp.ready = 1;
		pkt_size = (uint16_t)(pkt_size + create_gameserver_udp_segment(&msg[pkt_size], (uint8_t)EVENT_UDPCONNECT, SENDTOALLPLAYERS, 0));

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
	      pkt_size = (uint16_t)(pkt_size + create_gameserver_udp_segment(&msg[pkt_size], (uint8_t)SDO_DUMMY, SENDTOPLAYER, 0));
	    }
	    break;

	  case SDO_DUMMY:
	    break;

	  default:
	    gs_info("Flag not supported %x", msg_id);
	    print_gs_data(buf, buf_len);
	    break;
	}
    }
    else if (send_to_players != -1)
    {
	if (send_flag != SENDTOOTHERPLAYERS && send_flag != SENDTOALLPLAYERS) {
	  send_to_players = -1;
	  gs_info("Bogus UDP packet ignored from %s: send_flag %x", pl->username, send_flag);
	}
	/* a bit risky
	else if (msg_id != EVENT_ACK && msg_id != EVENT_CHOKE
	    && msg_id != EVENT_RATE && msg_id != EVENT_UDPCONNECT
	    && msg_id != SDO_PLAYER_STATE && msg_id != SDO_GAME_EVENT
	    && msg_id != SDO_DUMMY && msg_id != STILLALIVE) {
	  send_to_players = -1;
	  gs_info("GAMESERVER%d - Bogus UDP packet ignored from %s: msg_id %x", pl->username, msg_id);
	}
	*/
	else {
	  send_to_players = send_flag;
	}
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
  if (send_to_players > 0) {
      uint32_t reliable = (buf[0] & 0x80) << 16;
      uint24_to_char(serverSeq | reliable, &buf[0]);
      serverSeq++;
      uint16_to_char((uint16_t)get_time_ms(), &buf[6]);
      send_udp_functions(send_to_players, buf, (uint16_t)buf_len, s, pl->player_id);
  }
  /* Handle timeouts */
  for (int i = 0; i < MAX_PLAYERS; i++)
  {
    player_t *player = s->players[i];
    if (player && player->udp.last_update != 0 && (now - player->udp.last_update) >= 60000) {
      if (player->player_id != 0) {
	gs_info("User %s (%d) timed out", player->username, player->player_id);
	/* Notify lobby to remove player from session */
	lobby_kick_player(s, player->player_id);
      }
      else {
	gs_info("Socket %d timed out", player->sock);
      }
      /* Close the client connection */
      shutdown(player->sock, SHUT_RDWR);
    }
  }
  pthread_mutex_unlock(&s->mutex);

  return 0;
}
