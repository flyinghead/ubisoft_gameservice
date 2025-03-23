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
#define _GNU_SOURCE	/* for pipe2 */
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "gs_lobby.h"
#include "gs_waitmodule.h"
#include "../gs_common/gs_common.h"
#include "../gs_common/gs_msg.h"
#include "discord.h"

#define GS_PORT_OFFSET 30000
#define SESSION_LOCKED 0x08
#define SESSION_WAITING 0x10
#define PASSWORD_PROTECTED 0x0F

/* returns 1 if the user's current session was deleted because empty */
int player_cleanup(server_data_t *s, player_t *pl);
void send_msg_to_lobby(server_data_t* s, char* msg, uint16_t pkt_size);
void remove_server_session(server_data_t *s, session_t *sess);

int file_exists(char* filename) {
  struct stat buffer;
  return ( stat(filename, &buffer) );
}

uint16_t get_available_gameserver_port(server_data_t *s, session_t *sess) {
  int i;
  char pidfile[32];
  uint16_t port = 0;
  
  for( i = (int)sess->session_id; i < (int)(s->start_session_id + s->max_sessions); i++ ) {
    port = (uint16_t)(GS_PORT_OFFSET + i);
    sprintf(pidfile, "/tmp/gameserver%d.pid", port);
    if (file_exists(pidfile) != 0) {
      /* Make sure we don't have a live session using this port
       * to prevent any race condition on the pid file
       */
      for (int j = 0; j < s->max_sessions; j++)
	if (s->s_l[j] && s->s_l[j]->session_gameport == port && s->s_l[j] != sess) {
	  port = 0;
	  break;
	}
      if (port != 0)
        return port;
    }	    
  }

  return 0;
}

static uint16_t create_sessionnew(char* msg, session_t *sess) {
  int pkt_size = 0;

  //SessionName, GroupId, PGroupID, MaxP, MaxO, NrP, NrO
  pkt_size += sprintf(&msg[pkt_size], "s%s", sess->session_name);
  pkt_size++;
  pkt_size += bin32_to_msg(sess->session_id, &msg[pkt_size]);
  pkt_size += bin32_to_msg(sess->session_groupid, &msg[pkt_size]);
  pkt_size += bin32_to_msg(sess->session_max_players, &msg[pkt_size]);
  pkt_size += bin32_to_msg(sess->session_max_observers, &msg[pkt_size]);
  pkt_size += bin32_to_msg(sess->session_nb_players, &msg[pkt_size]);
  pkt_size += bin32_to_msg((uint32_t)0, &msg[pkt_size]);
  pkt_size += sprintf(&msg[pkt_size], "s%s", sess->session_master);
  pkt_size++;
  pkt_size += bin32_to_msg(sess->session_config, &msg[pkt_size]);
  pkt_size += sprintf(&msg[pkt_size], "s%s", sess->session_gameinfo);
  pkt_size++;
  pkt_size += sprintf(&msg[pkt_size], "s%s", sess->session_game);
  pkt_size++;
  //pkt_size += sprintf(&msg[pkt_size], "s%s", sess->server->allowedbranch);
  //pkt_size++;

  return (uint16_t)pkt_size;
}


void *gameserver_pipe_handler(void *data) {
  session_t *sess = (session_t *)data;
  for (;;)
  {
    char c;
    if (read(sess->gameserver_pipe, &c, 1) <= 0)
      break;
    int update_config = 0;
    switch (c) {
      case 'L':
        if (sess->session_config & SESSION_WAITING) {
    	  sess->session_config = SESSION_LOCKED;
    	  update_config = 1;
        }
        break;
      case 'U':
    	if (sess->session_config == SESSION_LOCKED) {
    	  sess->session_config = SESSION_WAITING;
    	  if (sess->session_password[0] != '\0')
    	    sess->session_config |= PASSWORD_PROTECTED;
    	  update_config = 1;
    	}
    	break;
      case 'S':
        if (read(sess->gameserver_pipe, &c, 1) == 1
            && c <= sizeof(sess->session_gameinfo)) {
          read(sess->gameserver_pipe, sess->session_gameinfo, (size_t)c);
	  sscanf(sess->session_gameinfo, "%*d %*d %*d %*d %*d %*d %d", &sess->session_max_players);
        }
    	break;
      case 'K':
	{
	  char username[MAX_UNAME_LEN];
	  if (read(sess->gameserver_pipe, &c, 1) == 1
		&& c <= sizeof(username)
		&& read(sess->gameserver_pipe, username, (size_t)c) == c)
	  {
	      server_data_t *server = sess->server;
	      pthread_mutex_lock(&server->mutex);
	      for (int i = 0; i < MAX_PLAYERS; i++) {
	        if (sess->players[i] && !strcmp(sess->players[i]->username, username)) {
	          if (player_cleanup(server, sess->players[i])) {
	            /* session has been deleted */
	            pthread_mutex_unlock(&server->mutex);
	            return NULL;
	          }
              break;
	        }
	      }
	      pthread_mutex_unlock(&server->mutex);
	  }
	}
	break;
      default:
    	gs_error("gameserver_pipe_handler: unknown message %d", c);
    	break;
    }
    if (update_config) {
      char msg[64];
      int pkt_size = create_updatesessions(&msg[6], sess->session_id, sess->session_config);
      pkt_size = create_gs_hdr(msg, UPDATESESSIONSTATE, 0x24, (uint16_t)pkt_size);
      send_msg_to_lobby(sess->server, msg, (uint16_t)pkt_size);
    }
  }
  return NULL;
}

static void safe_fork_gameserver(server_data_t* s, session_t *sess) {
  pid_t pid;
  int status;
  int pipefd[2] = { -1, -1 };

  if (s->server_type == SDO_SERVER) {
    if (pipe2(pipefd, O_CLOEXEC))
      perror("pipe2");
  }
  char arg_1[16], arg_2[16], arg_3[32], arg_4[258], arg_5[16], arg_6[32];
  sprintf(arg_1, "-p %d", sess->session_gameport);
  sprintf(arg_2, "-n %d", s->server_type == SDO_SERVER ? sess->session_max_players : sess->session_nb_players);
  sprintf(arg_3, "-m%s", sess->session_master);
  sprintf(arg_4, "-d%s", s->server_db_path);
  sprintf(arg_5, "-t %d", s->server_type);
  arg_6[0] = '\0';
  char *argv[] = { "gs_gameserver", arg_1, arg_2, arg_3, arg_4, arg_5, arg_6, NULL, NULL };
  int argc = 6 + (pipefd[0] != -1);
  if (!strcmp("SDODC", sess->session_game))
    /* dump received data */
    argv[argc++] = "-v";

  if (!(pid = fork())) {
    if (!fork()) {
      /* Duplicate the writing end of the pipe so it's not closed.
       * Both file descriptors in pipefd[] will be closed on exec due to the O_CLOEXEC flag.
       */
      if (pipefd[0] != -1) {
	int wpipefd = dup(pipefd[1]);
	sprintf(arg_6, "-i %d", wpipefd);
      }
      gs_info("Starting GameServer with args %s %s %s %s %s %s %s",
	      arg_1, arg_2, arg_3, arg_4,
	      arg_5, arg_6, argc >= 8 ? argv[7] : "");
      execve("gs_gameserver", argv, NULL);
    } else {
      exit(0);
    }
  } else {
    if (pipefd[1] != -1) {
      /* close the writing end of the pipe */
      close(pipefd[1]);
      /* and keep the reading end */
      sess->gameserver_pipe = pipefd[0];
      /* create the pipe reading thread but don't detach it so we can stop it cleanly */
      if (pthread_create(&sess->pipe_thread, NULL, gameserver_pipe_handler, sess) < 0)
	gs_error("Could not create gs pipe thread");
    }
    waitpid(pid, &status, 0);
  }
}

static uint16_t icmp_cksum(const uint16_t *addr, int len)
{
  int sum = 0;

  while (len > 1)  {
      sum += *addr++;
      len -= 2;
  }
  if (len == 1)
    sum += *(uint8_t *)addr;

  sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
  sum += (sum >> 16);			/* add carry */
  return (uint16_t)~sum;		/* one-complement and truncate to 16 bits */
}

static int icmp_ping(const struct sockaddr_in *addr)
{
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (sock == -1) {
      if (errno == EPERM || errno == EACCES)
	gs_error("Can't create ICMP socket: permission denied. Set net.ipv4.ping_group_range correctly.");
      else
	gs_error("Can't create ICMP socket: errno %d", errno);
      return 1000;
  }
  int flags = fcntl(sock, F_GETFL, IPPROTO_ICMP);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);

#define DATALEN 56
#define MAXIPLEN 60
#define MAXICMPLEN 76
  uint8_t packet[DATALEN + MAXIPLEN + MAXICMPLEN];
  struct icmphdr *icp = (struct icmphdr *)packet;

  /* We are sending a ICMP_ECHO ICMP packet */
  icp->type = ICMP_ECHO;
  icp->code = 0;
  icp->checksum = 0;
  icp->un.echo.sequence = htons(1);
  /* We don't set the echo.id here since IPPROTO_ICMP does it for us
   * it sets it to the source port
   * pfh.icmph.un.echo.id = inet->inet_sport;
   */

  /* compute ICMP checksum here */
  int cc = DATALEN + 8;
  icp->checksum = icmp_cksum((uint16_t *)icp, cc);

  /* send the ICMP packet*/
  time_t t0 = get_time_ms();
  ssize_t i = sendto(sock, icp, (size_t)cc, 0, (struct sockaddr*)addr, sizeof(*addr));
  if (i != cc) {
      perror("ICMP sendto");
      close(sock);
      return 1000;
  }

  /* read the reply */
  int ping = 1000;
  while (1) {
    time_t now = get_time_ms();
    if (now - t0 >= 1000)
      break;
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    struct timeval tv;
    if (now == t0) {
	tv.tv_sec = 1;
	tv.tv_usec = 0;
    }
    else {
	tv.tv_sec = 0;
	tv.tv_usec = (1000 - (now - t0)) * 1000;
    }
    int ret = select(sock + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0)
	/* timeout or error */
	break;

    cc = (int)recv(sock, packet, sizeof(packet), 0);
    if (cc < 0 ){
	perror("ICMP recv");
	break;
    }
    if (cc < ICMP_MINLEN)
      /* too small: ignore */
      continue;
    struct icmphdr *icp_reply = (struct icmphdr *)packet;
    if (icp_reply->type == ICMP_ECHOREPLY) {
	time_t t1 = get_time_ms();
	//printf("Reply of %d bytes received in %ld ms\n", cc, t1 - t0);
	//printf("icmp_seq = %u\n", ntohs(icp_reply->un.echo.sequence));
	ping = (int)(t1 - t0);
	break;
    }
  }
  close(sock);
  return ping > 1000 ? 1000 : ping;
}

void *keepalive_server_handler(void *data)
{
  server_data_t *s = (server_data_t *)data;
  int i=0;
  int ping_count;
  struct sockaddr_in ping_addresses[100];
  int ping_values[100];
    
  while(1) {
    ping_count = 0;
    pthread_mutex_lock(&s->mutex);
    time_t now = time(NULL);
    for(i=0; i < (s->max_players); i++) {
      player_t *player = s->server_p_l[i];
      if (player == NULL)
        continue;
      //Time between keepalive should not be more then 5min (300 sec)
      if (now - player->keepalive > 300) {
          gs_info("[LOBBY] - User %s is not sending keepalive, last was %d s ago",
		  player->username,
		  (int)(now - player->keepalive));
          /* will make the client thread delete the player and exit */
          shutdown(player->sock, SHUT_RDWR);
          continue;
      }
      if (s->server_type == SDO_SERVER
	  && player->in_game == 0
	  && player->in_session_id != 0
	  && (size_t)ping_count < sizeof(ping_values) / sizeof(ping_values[0]))
	memcpy(&ping_addresses[ping_count++], &player->addr, sizeof(struct sockaddr_in));
    }
    pthread_mutex_unlock(&s->mutex);

    for (i = 0; i < ping_count; i++)
      ping_values[i] = icmp_ping(&ping_addresses[i]);

    pthread_mutex_lock(&s->mutex);
    for (i = 0; i < s->max_players; i++) {
      player_t *player = s->server_p_l[i];
      if (player == NULL)
        continue;
      for (int j = 0; j < ping_count; j++) {
	if (!memcmp(&ping_addresses[j], &player->addr, sizeof(struct sockaddr_in))) {
	    player->ping = (uint8_t)(ping_values[j] / 100);
	    char msg[128];
	    uint16_t pkt_size = create_updateplayerping(&msg[6], player->username, player->in_session_id, player->ping);
	    pkt_size = create_gs_hdr(msg, UPDATEPLAYERPING, 0x24, pkt_size);
	    send_msg_to_lobby(s, msg, pkt_size);
	    break;
	}
      }
    }

    for(i=0;i<s->max_sessions;i++) {
      if(s->s_l[i]) {
	/* Don't remove POD chat session */
	if (s->server_type == POD_SERVER && s->s_l[i]->session_id == s->chatgroup_id)
	  continue;

	int duration = (int)(now - s->s_l[i]->session_start);
	/* Remove session that have been active for longer then 60 sec but have 0 members */
	if (duration > 60 && s->s_l[i]->session_nb_players == 0) {
	  gs_info("[LOBBY] - Removed empty session %s after 60 sec", s->s_l[i]->session_name);
	  remove_server_session(s, s->s_l[i]);
	}
	/* Remove Stale Sessions after 8h */
	else if (duration > 28800) {
	  gs_info("[LOBBY] - Removed stale session %s No: [%d]", s->s_l[i]->session_name, s->s_l[i]->session_nb_players);
	  remove_server_session(s, s->s_l[i]);
	}
      }
    }  
    pthread_mutex_unlock(&s->mutex);
    sleep(10);
  }
  
  return 0;
}

int send_msg_to_session(session_t *sess, char* msg, uint16_t pkt_size) {
  if (sess == NULL)
    return 0;
  
  gs_encode_data((uint8_t*)(msg+6), (size_t)(pkt_size-6));
  
  for (int i = 0; i < MAX_PLAYERS; i++) {
    if (sess->players[i])
      write(sess->players[i]->sock, msg, pkt_size);
  }
  
  return 0;
}

void send_other_players_in_lobby(server_data_t *s, player_t* pl, char* msg) {
  for (int i = 0; i < s->max_players; i++) {
    /* Send to other players which is not in a game */
    player_t *player = s->server_p_l[i];
    if (player && player->player_id != pl->player_id) {
      uint16_t pkt_size = create_joinnew(&msg[6], player->username, s->basicgroup_id);
      pkt_size = create_gs_hdr(msg, JOINNEW, 0x24, pkt_size);
      send_gs_msg(pl->sock, msg, pkt_size);
      /* SDO wants both the join group and the join session */
      if (s->server_type == SDO_SERVER && player->in_session_id != 0) {
	pkt_size = create_joinnew(&msg[6], player->username, player->in_session_id);
	pkt_size = create_gs_hdr(msg, JOINNEW, 0x24, pkt_size);
	send_gs_msg(pl->sock, msg, pkt_size);
	pkt_size = create_updateplayerping(&msg[6], player->username, player->in_session_id, player->ping);
	pkt_size = create_gs_hdr(msg, UPDATEPLAYERPING, 0x24, pkt_size);
	send_gs_msg(pl->sock, msg, pkt_size);
      }
    }
  } 
}

void send_other_players_in_session(session_t *sess, player_t* pl, char* msg) {
  if (sess == NULL)
    return;
  
  for (int i = 0; i < MAX_PLAYERS; i++) {
    if (sess->players[i] && sess->players[i]->player_id != pl->player_id) {
      uint16_t pkt_size = create_joinnew(&msg[6], sess->players[i]->username, sess->session_id);
      pkt_size = create_gs_hdr(msg, JOINNEW, 0x24, pkt_size);
      send_gs_msg(pl->sock, msg, pkt_size);
    }
  }
}

void send_other_players_ping_in_session(session_t *sess, player_t* pl, char* msg) {
  if (sess == NULL)
    return;
  
  for (int i = 0; i < MAX_PLAYERS; i++) {
    if (sess->players[i] && sess->players[i]->player_id != pl->player_id) {
      uint16_t pkt_size = create_updateplayerping(&msg[6], sess->players[i]->username, sess->session_id, sess->players[i]->ping);
      pkt_size = create_gs_hdr(msg, UPDATEPLAYERPING, 0x24, pkt_size);
      send_gs_msg(pl->sock, msg, pkt_size);
    }
  }
}

void send_msg_to_others_in_lobby(server_data_t* s, player_t* pl, char* msg, uint16_t pkt_size) {
  if (s == NULL)
    return;
  
  gs_encode_data((uint8_t*)(msg+6), (size_t)(pkt_size-6));
  
  for (int i = 0; i < s->max_players; i++) {
    /* Send to all players which is not in a game */
    if (s->server_p_l[i] &&
	s->server_p_l[i]->in_game == 0 &&
	s->server_p_l[i]->player_id != pl->player_id ) {
      write(s->server_p_l[i]->sock, msg, pkt_size);
    }
  }
}

void send_msg_to_lobby(server_data_t* s, char* msg, uint16_t pkt_size) {
  if (s == NULL)
    return;

  gs_encode_data((uint8_t*)(msg+6), (size_t)(pkt_size-6));
  
  pthread_mutex_lock(&s->mutex);
  for (int i = 0; i < s->max_players; i++) {
    /* Send to all players which is not in a game */
    if (s->server_p_l[i] &&
	s->server_p_l[i]->in_game == 0) {
      write(s->server_p_l[i]->sock, msg, pkt_size);
    }
  }
  pthread_mutex_unlock(&s->mutex);
}

session_t* find_server_session(server_data_t *s, uint32_t session_id) {
  for (int i = 0; i < s->max_sessions; i++) {
    session_t *sess = s->s_l[i];
    if (sess && sess->session_id == session_id) {
      gs_info("Found session %s with groupid %d", sess->session_name, sess->session_id);
      return sess;
    }
  }
  return NULL;
}

int add_server_player(server_data_t *s, player_t *pl) {
  pthread_mutex_lock(&s->mutex);
  for (int i = 0 ; i < s->max_players; i++) {
    if (!(s->server_p_l[i])) {
      s->server_p_l[i] = pl;
      s->group_size = s->group_size + 1;
      pthread_mutex_unlock(&s->mutex);
      gs_info("Added player with id: 0x%02x", pl->player_id);
      return 1;
    }
  }
  pthread_mutex_unlock(&s->mutex);
  
  gs_info("Could not add player with id: 0x%02x", pl->player_id);
  gs_info("Server full");
  return 0;
}

void remove_server_player(player_t *pl) {
  server_data_t *s = pl->server;
  
  pthread_mutex_lock(&s->mutex);
  for (int i = 0; i < s->max_players; i++) {
    if (s->server_p_l[i] && s->server_p_l[i]->player_id == pl->player_id) {
      s->group_size = s->group_size - 1;
      player_cleanup(s, pl);
      gs_info("lobby: removed player %s (%x)", pl->username, pl->player_id);
      close(s->server_p_l[i]->sock);
      s->server_p_l[i] = NULL;
      break;
    }
  }
  pthread_mutex_unlock(&s->mutex);
}

int add_player_to_session(session_t *sess, player_t *pl) {
  server_data_t *s = pl->server;

  /* Sometimes people can break a session creation, this will hopefully remove the stale session */
  if (pl->in_session_id != 0) {
    if (pl->in_session_id == sess->session_id) {
	/* Already in the session. Not sure how this happens but it does */
	gs_info("Player %s is already in session %d", sess->session_id);
	return 1;
    }
    /* Check if session is still active */
    pthread_mutex_lock(&s->mutex);
    if (find_server_session(s, pl->in_session_id) != NULL)  {
      gs_info("Player %s is trying to join a session %d but is still in %d", pl->username, sess->session_id, pl->in_session_id);
      player_cleanup(s, pl);
    }
    pthread_mutex_unlock(&s->mutex);
  }
  
  pthread_mutex_lock(&s->mutex);
  for (int i = 0; i < MAX_PLAYERS; i++) {
     if(!(sess->players[i])) {
       gs_info("Added player %s to %s", pl->username, sess->session_name);
       sess->session_nb_players = sess->session_nb_players + 1;
       sess->players[i] = pl;
       pl->in_session_id = sess->session_id;
       pthread_mutex_unlock(&s->mutex);
       return 1;
     }
  }
  pthread_mutex_unlock(&s->mutex);

  gs_info("Session is full");
  return 0;
}

void remove_player_from_session(session_t *sess, player_t *pl) {
  pthread_mutex_lock(&sess->server->mutex);
  for (int i = 0; i < MAX_PLAYERS; i++) {
    if (sess->players[i] &&
	sess->players[i]->player_id == pl->player_id) {
      
      gs_info("Removed player %s (0x%02x) from %s", pl->username, pl->player_id, sess->session_name);
      sess->session_nb_players = sess->session_nb_players - 1;

      pl->in_session_id = 0;
      sess->players[i] = NULL;
      break;
    }
  }
  pthread_mutex_unlock(&sess->server->mutex);
}

void remove_server_session(server_data_t *s, session_t *sess) {
  uint16_t max_sessions = s->max_sessions;
  int i;
  
  pthread_mutex_lock(&s->mutex);
  for (i = 0; i < max_sessions; i++) {
    if (s->s_l[i] == sess) {
      s->s_l[i] = NULL;
      break;
    }
  }
  pthread_mutex_unlock(&s->mutex);
  if (i == max_sessions)
    return;

  gs_info("Removed session %s", sess->session_name);
  if (sess->gameserver_pipe != -1) {
      close(sess->gameserver_pipe);
      /* Avoid deadlock with pipe thread */
      int lock_count = 0;
      while (pthread_mutex_unlock(&s->mutex) == 0)
	lock_count++;
      pthread_join(sess->pipe_thread, NULL);
      while (lock_count-- > 0)
	pthread_mutex_lock(&s->mutex);
  }
  free(sess);
}

/* Caller *must* lock the server mutex */
int player_cleanup(server_data_t *s, player_t *pl) {
  uint16_t pkt_size = 0;
  session_t* sess = NULL;
  char msg[MAX_PKT_SIZE];
  int hit=0;
  
  if (pl == NULL) {
    gs_info("Player cleanup with a NULL pointer is bad");
    return 0;
  }

  sess = find_server_session(s, pl->in_session_id);
  if (sess != NULL) {

    for (int i = 0; i < MAX_PLAYERS; i++) {
      if (sess->players[i]
		&& sess->players[i]->username[0] != '\0'
		&& strcmp(pl->username, sess->players[i]->username) == 0) {
	  gs_info("Player %s still in session %d, remove...", pl->username, sess->session_id);
	  hit = 1;
	  break;
      }
    }

    if (hit == 0) {
      gs_info("Player struct has in_session_id value but player is not there anymore");
      return 0;
    }
    
    remove_player_from_session(sess, pl);
    
    pkt_size = create_joinleave(&msg[6], pl->username, sess->session_id);
    pkt_size = create_gs_hdr(msg, JOINLEAVE, 0x24, pkt_size);
    send_msg_to_session(sess, msg, pkt_size);

    if (s->server_type == POD_SERVER && sess->session_id == s->chatgroup_id) {
      gs_info("Leaving chat..");
      return 0;
    }
    
    if (sess->session_nb_players == 0) {
      pkt_size = create_sessionremove(&msg[6],sess->session_id);
      pkt_size = create_gs_hdr(msg, SESSIONREMOVE, 0x24, pkt_size);
      send_msg_to_lobby(s, msg, pkt_size);
      /* Sess is freed here */
      remove_server_session(s, sess);
      return 1;
    } else {
      pkt_size = create_updategroupsize(&msg[6],sess->session_id,sess->session_nb_players);
      pkt_size = create_gs_hdr(msg, UPDATEGROUPSIZE, 0x24, pkt_size);
      send_msg_to_lobby(s, msg, pkt_size);
    }
  } else {
    pkt_size = create_joinleave(&msg[6], pl->username, s->basicgroup_id);
    pkt_size = create_gs_hdr(msg, JOINLEAVE, 0x24, pkt_size);
    send_msg_to_lobby(s, msg, pkt_size);
  }
  return 0;
}

int add_server_session(server_data_t *s,
		       session_t *sess,
		       player_t *pl,
		       char* session_name,
		       char* session_game,
		       char* session_gameversion,
		       char* session_gameinfo,
		       char* session_password,
		       uint32_t session_gs_version,
		       uint32_t session_max_players,
		       uint32_t session_max_observers,
		       uint32_t session_groupid,
		       uint32_t session_pgroupid,
		       uint32_t session_unknown_1,
		       uint32_t session_unknown_2) {
  
  if (strlen(session_name) > sizeof(sess->session_name)) {
    gs_info("Session name is larger then buffer");
    return 0;
  }
  if (strlen(session_game) > sizeof(sess->session_game)) {
    gs_info("Session game is larger then buffer");
    return 0;
  }
  if (strlen(session_gameversion) > sizeof(sess->session_gameversion)) {
    gs_info("Session gameversion is larger then buffer");
    return 0;
  }
  if (strlen(session_gameinfo) > sizeof(sess->session_gameinfo)) {
    gs_info("Session gameinfo is larger then buffer");
    return 0;
  }
  if (strlen(session_password) > sizeof(sess->session_password)) {
    gs_info("Session password is larger then buffer");
    return 0;
  }
  /* Session name and session master is the same here*/
  if (pl != NULL && strlen(pl->username) > sizeof(sess->session_master)) {
    gs_info("Session master is larger than buffer");
    return 0;
  }
  
  strlcpy(sess->session_name, session_name, sizeof(sess->session_name));
  strlcpy(sess->session_game, session_game, sizeof(sess->session_game));
  strlcpy(sess->session_gameversion, session_gameversion, sizeof(sess->session_gameversion));
  strlcpy(sess->session_gameinfo, session_gameinfo, sizeof(sess->session_gameinfo));
  strlcpy(sess->session_password, session_password, sizeof(sess->session_password));
  if (pl != NULL)
    strlcpy(sess->session_master, pl->username, sizeof(sess->session_master));
  else
    strlcpy(sess->session_master, session_name, sizeof(sess->session_master));
    
  sess->session_gs_version = session_gs_version;
  sess->session_max_players = session_max_players;
  sess->session_max_observers = session_max_players;
  sess->session_nb_players = 0;
  sess->session_nb_observers = 0;
  sess->session_groupid = session_groupid;
  sess->session_pgroupid = session_pgroupid;

  //Set timestamp
  sess->session_start = time(NULL);

  sess->session_config = 0;
  sess->session_unknown_1 = session_unknown_1;
  sess->session_unknown_2 = session_unknown_2;

  if (sess->session_password[0] != '\0') {
    gs_info("Session got password %s", sess->session_password);
    sess->session_config = PASSWORD_PROTECTED;
  }
  sess->gameserver_pipe = -1;
  sess->server = s;
  
  if (pl != NULL)
    sess->session_master_player_id = pl->player_id;
  else
    sess->session_master_player_id = 0;

  pthread_mutex_lock(&s->mutex);
  for (int i = 0; i < s->max_sessions; i++) {
    if(!(s->s_l[i])) {
      s->s_l[i] = sess;
      sess->session_id = s->start_session_id + (uint32_t)i;
      sess->session_gameport = get_available_gameserver_port(s, sess);
      if (sess->session_gameport == 0) {
	sess->session_gameport = (uint16_t)(GS_PORT_OFFSET + sess->session_id);
	gs_error("Could not find available gameserver port, set to %d and hope for the best", sess->session_gameport);
      }
      pthread_mutex_unlock(&s->mutex);
      gs_info("Added session %s with groupid: %d and port: %d", sess->session_name, sess->session_id, sess->session_gameport);
      return 1;
    }
  }
  pthread_mutex_unlock(&s->mutex);
  gs_info("Could not add session %s", sess->session_name);
  gs_info("No more session available");
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
ssize_t server_msg_handler(int sock, player_t *pl, char *msg, char *buf, int buf_len) {
  server_data_t *s = pl->server;
  uint16_t pkt_size = 0, recv_size = 0;
  uint8_t recv_flag = 0;
  char *tok_array[256] =  { NULL };
  uint32_t byte_array[256] = { 0 };
  int pos = 0, nr_s_parsed = 0, nr_b_parsed = 0;
  uint32_t groupid = 0, binLen = 0;
  session_t *sess = NULL;
  int i;
  
  buf[buf_len] = '\0';
  //Parse header
  if (buf_len < 6) {
    gs_info("[lobby] Length of packet is less then 6 bytes...[SKIP]");
    return 0;
  }

  recv_flag = (uint8_t)buf[4];
  recv_size = char_to_uint16(&buf[1]);
  
  if(recv_size > buf_len) {
    gs_info("[lobby] Packet size %d is greater than buffer size %d", recv_size, buf_len);
    print_gs_data(buf, (long unsigned int)buf_len);
    return 0;
  }

  //Jump the header
  pos = pos + 6;
  while (pos < recv_size) {
    if (nr_s_parsed == 256 || nr_b_parsed == 256) {
      return 0;
    }
    switch (buf[pos]) {
    case 's':
      pos++;
      tok_array[nr_s_parsed] = &buf[pos];
      pos += (int)(strlen(tok_array[nr_s_parsed]));
      nr_s_parsed++;
      break;;
    case 'b':
      pos++;
      if (pos + 4 > buf_len) {
	gs_error("Binary data exceeds buffer %d > %d on nr %d msg_id %x", (pos+4), buf_len, nr_b_parsed, recv_flag);
	print_gs_data(buf, (long unsigned int)buf_len);
	return 0;
      }
      binLen = char_to_uint32(&buf[pos]);
      if ((uint32_t)(pos + 4) + binLen > buf_len) {
	if (s->server_type != SDO_SERVER || recv_flag != LEAVESESSION) {
	  // SDO sends a bogus LEAVESESSION message when quitting a race. Ignore it silently.
	  gs_error("Binary data exceeds buffer %d > %d on nr %d msg_id %x", (uint32_t)(pos + 4) + binLen, buf_len, nr_b_parsed, recv_flag);
	  print_gs_data(buf, (long unsigned int)buf_len);
	}
	return 0;
      }
      memcpy(&byte_array[nr_b_parsed], &buf[pos+4], binLen);
      nr_b_parsed++;
      break;;
    default:
      pos++;
      break;;
    }
  }

  switch(recv_flag) {
  case LOGINARENA:
    if (nr_s_parsed != 1) {
      gs_error("Got %d strings from LOGINARENA packet needs 1", nr_s_parsed);
      return 0;
    }
    {
      pthread_mutex_lock(&s->mutex);
      for(i = 0; i < s->max_players; i++) {
	player_t *player = s->server_p_l[i];
	if (player == NULL || player == pl)
	  continue;
	if (strcmp(player->username, tok_array[0]) == 0) {
	  shutdown(player->sock, SHUT_RDWR);
	  break;
	}
      }
      strlcpy(pl->username, tok_array[0], sizeof(pl->username));
      pthread_mutex_unlock(&s->mutex);
    }
    gs_info("lobby: User %s is joining the %s server", pl->username, s->game);
    
    pkt_size = create_loginarena(&msg[6], s->arena_id);
    pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x24, pkt_size);
    break;;
  case JOINSESSION:
    if (nr_s_parsed != 2) {
      gs_error("Got %d strings from JOINSESSION packet needs 2", nr_s_parsed);
      return 0;
    }
    if (nr_b_parsed != 2) {
      gs_error("Got %d values from JOINSESSION packet needs 2", nr_b_parsed);
      return 0;
    }

    /* calculate our ping now so we don't lock the entire server */
    if (pl->ping == 10)
      pl->ping = (uint8_t)(icmp_ping(&pl->addr) / 100);

    groupid = byte_array[0];
    pthread_mutex_lock(&s->mutex);
    sess = find_server_session(s, groupid);
    gs_info("lobby: %s JOINSESSION %s %s groupid=%d %d session=%p", pl->username, tok_array[0], tok_array[1], byte_array[0], byte_array[1], sess);

    /* Joining a session */
    if (sess != NULL) {
      if ((sess->session_nb_players + 1) > sess->session_max_players) {
	gs_info("Session is full");
	/* 27 Session full */
	pkt_size = create_gsfail(&msg[6], JOINSESSION, 27);
	pkt_size = create_gs_hdr(msg, GSFAIL, 0x24, pkt_size);
	pthread_mutex_unlock(&s->mutex);
	return pkt_size;
      }
      if (sess->session_config == SESSION_LOCKED) {
	gs_info("Session locked");
	/* 30 Session locked  - Not Working */
	pkt_size = create_gsfail(&msg[6], JOINSESSION, 30);
	pkt_size = create_gs_hdr(msg, GSFAIL, 0x24, pkt_size);
	pthread_mutex_unlock(&s->mutex);
	return pkt_size;
      }
      if ((sess->session_config & PASSWORD_PROTECTED) == PASSWORD_PROTECTED) {
	gs_info("Session is password protected");
	if ( (strcmp(tok_array[0], sess->session_password)) != 0 ) {
	  gs_info("Incorrect password");
	  /* 33 Incorrect password */
	  pkt_size = create_gsfail(&msg[6], JOINSESSION, 33);
	  pkt_size = create_gs_hdr(msg, GSFAIL, 0x24, pkt_size);
	  pthread_mutex_unlock(&s->mutex);
	  return pkt_size;
	}
      }
    }
    
    pkt_size = create_joinsession(&msg[6], groupid);
    pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x24, pkt_size);
    send_gs_msg(sock, msg, pkt_size);
    
    /* Add player to session */
    if (sess != NULL) {
      if (!add_player_to_session(sess, pl)) {
	pthread_mutex_unlock(&s->mutex);
	return 0;
      }

      /* Main Chat in POD needs joining player msg then rest of the players */
      if (s->server_type == POD_SERVER && sess->session_id == s->chatgroup_id) {

	pkt_size = create_joinnew(&msg[6], pl->username, groupid);
	pkt_size = create_gs_hdr(msg, JOINNEW, 0x24, pkt_size);
	send_msg_to_session(sess, msg, pkt_size);
	
	send_other_players_in_session(sess, pl, msg);
      } else {
	/*Send other players already in the session*/
	send_other_players_in_session(sess, pl, msg);
	
	pkt_size = create_joinnew(&msg[6], pl->username, groupid);
	pkt_size = create_gs_hdr(msg, JOINNEW, 0x24, pkt_size);
	if (s->server_type == SDO_SERVER)
	  // send to all players in lobby to update session player count
	  send_msg_to_lobby(s, msg, pkt_size);
	else
	  send_msg_to_session(sess, msg, pkt_size);
      }
      
      /* Send your own ping value */
      pkt_size = create_updateplayerping(&msg[6], pl->username, groupid, pl->ping);
      pkt_size = create_gs_hdr(msg, UPDATEPLAYERPING, 0x24, pkt_size);
      if (s->server_type == SDO_SERVER)
        send_msg_to_lobby(s, msg, pkt_size);
      else
        send_msg_to_session(sess, msg, pkt_size);
      
      /* Send other players ping in session */
      send_other_players_ping_in_session(sess, pl, msg);
      
      /* Update group size, displayed in the game list */
      pkt_size = create_updategroupsize(&msg[6], sess->session_id, sess->session_nb_players);
      pkt_size = create_gs_hdr(msg, UPDATEGROUPSIZE, 0x24, pkt_size);
      send_msg_to_lobby(s, msg, pkt_size);

      /* Send out who is the master */
      if (groupid != s->chatgroup_id) {
	pkt_size = create_master_changed(&msg[6], groupid, sess->session_master);
	pkt_size = create_gs_hdr(msg, MASTERCHANGED, 0x24, pkt_size);
	send_gs_msg(sock, msg, pkt_size);
      } 

      if (s->server_type == MONACO_SERVER) {
	/*Joining  a session will make you leave the lobby-chat*/
	pkt_size = create_joinleave(&msg[6], pl->username, s->basicgroup_id);
	pkt_size = create_gs_hdr(msg, JOINLEAVE, 0x24, pkt_size);
	send_msg_to_others_in_lobby(s, pl, msg, pkt_size);
      }
      else if (sess->session_config & SESSION_WAITING) {
	// needed to avoid hang on Connecting to the waiting room...
	pkt_size = create_startgame(&msg[6], groupid, s->server_ip, sess->session_gameport);
	pkt_size = create_gs_hdr(msg, STARTGAME, 0x24, pkt_size);
	send_gs_msg(sock, msg, pkt_size);
      }
            
    } else {
      /* Not a Session */
      pkt_size = create_joinnew(&msg[6], pl->username, groupid);
      pkt_size = create_gs_hdr(msg, JOINNEW, 0x24, pkt_size);
      send_msg_to_lobby(s, msg, pkt_size);
    }
    
    /* Joining the lobby/arena send all players and sessions */
    if (groupid == s->basicgroup_id) {
#ifdef DISCORD
      const char **player_list = (const char **)calloc(s->max_players, sizeof(char *));
      int nplayers = 0;
      for (i = 0; i < s->max_players; i++) {
	player_t *player = s->server_p_l[i];
	if (player && player->player_id != pl->player_id)
	  player_list[nplayers++] = player->username;
      }
      discord_user_joined(pl->username, player_list, nplayers);
      free(player_list);
#endif
      for (i = 0; i < s->max_sessions; i++) {
	if (s->s_l[i]) {
	  pkt_size = create_sessionnew(&msg[6], s->s_l[i]);
	  pkt_size = create_gs_hdr(msg, SESSIONNEW, 0x24, pkt_size);
	  send_gs_msg(sock, msg, pkt_size);
	}
      }
      send_other_players_in_lobby(s, pl, msg);
    }
    pthread_mutex_unlock(&s->mutex);
    pkt_size = 0;
    break;;
  case CREATESESSION:
    if (nr_s_parsed != 5) {
      gs_error("Got %d strings from CREATESESSION packet needs 5", nr_s_parsed);
      return 0;
    }
    if (nr_b_parsed != 7) {
      gs_error("Got %d values from CREATESESSION packet needs 7", nr_b_parsed);
      return 0;
    }
    gs_info("lobby: %s CREATESESSION '%s' '%s' '%s' '%s' '%s' ver %d maxp %d maxo %d gid %d pgid %d unk %d %d",
	    pl->username,
	    tok_array[0], tok_array[1], tok_array[2], tok_array[3], tok_array[4],
	    byte_array[0], byte_array[1], byte_array[2], byte_array[3],
	    byte_array[4], byte_array[5], byte_array[6]);

    sess = (session_t *)calloc(1, sizeof(session_t));
    pthread_mutex_lock(&s->mutex);
    if (!add_server_session(s,
			    sess,
			    pl,
			    s->server_type == SDO_SERVER ? tok_array[0] : pl->username,
			    tok_array[1],
			    tok_array[2],
			    tok_array[3],
			    tok_array[4],
			    byte_array[0],
			    byte_array[1],
			    byte_array[2],
			    byte_array[3],
			    byte_array[4],
			    byte_array[5],
			    byte_array[6])) {
      pthread_mutex_unlock(&s->mutex);
      free(sess);
      return 0;
    }

    pkt_size = create_createsession(&msg[6],
				    sess->session_name,
				    sess->session_id
				    );
    pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x24, pkt_size);
    send_gs_msg(sock, msg, pkt_size);

    pkt_size = create_sessionnew(&msg[6], sess);
    pkt_size = create_gs_hdr(msg, SESSIONNEW, 0x24, pkt_size);
    send_msg_to_lobby(s, msg, pkt_size);
    pthread_mutex_unlock(&s->mutex);
#ifdef DISCORD
    if (s->server_type != SDO_SERVER)
      discord_game_created(pl->username, sess->session_name, sess->session_gameinfo);
#endif

    pkt_size = 0;
    break;;
  case LEAVESESSION:
    if (nr_b_parsed != 1) {
      gs_error("Got %d values from LEAVESESSION packet needs 1", nr_b_parsed);
      return 0;
    }

    /*Just in case wakeup-command breaks*/
    pl->in_game = 0;
    
    groupid = byte_array[0];
    gs_info("lobby: %s LEAVESESSION %d", pl->username, groupid);
    pthread_mutex_lock(&s->mutex);
    sess = find_server_session(s, groupid);
   
    if (sess != NULL) {
      pkt_size = create_joinleave(&msg[6], pl->username, groupid);
      pkt_size = create_gs_hdr(msg, JOINLEAVE, 0x24, pkt_size);
      send_msg_to_session(sess, msg, pkt_size);
      remove_player_from_session(sess, pl);
      
      /* If POD Main chat we are done here */
      if (s->server_type == POD_SERVER && sess->session_id == s->chatgroup_id) {
	gs_info("Leaving chat..");
	pthread_mutex_unlock(&s->mutex);
	return 0;
      }
      
      if (sess->session_nb_players == 0) {
	pkt_size = create_sessionremove(&msg[6],sess->session_id);
	pkt_size = create_gs_hdr(msg, SESSIONREMOVE, 0x24, pkt_size);
	send_msg_to_lobby(s, msg, pkt_size);
	/* Sess is freed here */
	remove_server_session(s, sess);
      } else {
	pkt_size = create_updategroupsize(&msg[6],
					  sess->session_id,
					  sess->session_nb_players);
	pkt_size = create_gs_hdr(msg, UPDATEGROUPSIZE, 0x24, pkt_size);
	send_msg_to_lobby(s, msg, pkt_size);
      }

      if (s->server_type == MONACO_SERVER) {
	/*Leaving a session will make you join the lobby-chat*/
	pkt_size = create_joinnew(&msg[6], pl->username, s->basicgroup_id);
	pkt_size = create_gs_hdr(msg, JOINNEW, 0x24, pkt_size);
	send_msg_to_others_in_lobby(s, pl, msg, pkt_size);
      }
      else if (s->server_type == SDO_SERVER) {
	pkt_size = create_joinleave(&msg[6], pl->username, groupid);
	pkt_size = create_gs_hdr(msg, JOINLEAVE, 0x24, pkt_size);
	send_msg_to_lobby(s, msg, pkt_size);
      }
    } else {
      pkt_size = create_joinleave(&msg[6], pl->username, groupid);
      pkt_size = create_gs_hdr(msg, JOINLEAVE, 0x24, pkt_size);
      send_msg_to_lobby(s, msg, pkt_size);
    }
    pthread_mutex_unlock(&s->mutex);

    pkt_size = 0;
    break;
  case BEGINGAME:
    if (nr_b_parsed != 1) {
      gs_error("Got %d values from BEGINGAME packet needs 1", nr_b_parsed);
      return 0;
    }

    groupid = byte_array[0];
    gs_info("lobby: %s BEGINGAME %d", pl->username, groupid);
    
    /*Lock the session*/
    pthread_mutex_lock(&s->mutex);
    sess = find_server_session(s, groupid);
    if (sess != NULL) {
      
      pkt_size = create_begingame(&msg[6], groupid);
      pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x24, pkt_size);
      send_gs_msg(sock, msg, pkt_size);
      sess->session_config = SESSION_LOCKED;
      pkt_size = create_updatesessions(&msg[6], groupid, sess->session_config);
      pkt_size = create_gs_hdr(msg, UPDATESESSIONSTATE, 0x24, pkt_size);
      send_msg_to_lobby(s, msg, pkt_size);
      /* Start game server for this session */
      safe_fork_gameserver(s, sess);
            
      pkt_size = create_startgame(&msg[6], groupid, s->server_ip, sess->session_gameport);
      pkt_size = create_gs_hdr(msg, STARTGAME, 0x24, pkt_size);
      send_msg_to_session(sess, msg, pkt_size);

#ifdef DISCORD
      if (s->server_type == SDO_SERVER && strcmp(sess->session_game, "SDODC_GARAGE") != 0)
	discord_game_created(pl->username, sess->session_name, sess->session_gameinfo);
#endif
    } else {
      gs_error("Trying to lock session that doesn't exist");
    }
    pthread_mutex_unlock(&s->mutex);

    pkt_size = 0 ;
    break;;   
  case STILLALIVE:
    //Set new keepalive stamp
    pl->keepalive = time(NULL);
    pkt_size = create_gs_hdr(msg, STILLALIVE, 0x24, pkt_size);
    send_gs_msg(sock, msg, pkt_size);

    pkt_size = 0;
    break;;
  case SLEEP:
    gs_info("lobby: %s SLEEP", pl->username);
    pkt_size = create_gssuccessful(&msg[6], STATUSCHANGE);
    pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x24, pkt_size);
    pl->in_game = 1;
    break;;
  case WAKEUP:
    gs_info("lobby: %s WAKEUP", pl->username);
    pkt_size = create_gssuccessful(&msg[6], STATUSCHANGE);
    pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x24, pkt_size);
    send_gs_msg(sock, msg, pkt_size);
    pl->in_game = 0;

    pthread_mutex_lock(&s->mutex);
    for (i = 0; i < s->max_sessions; i++) {
      if (s->s_l[i]) {
	pkt_size = create_sessionnew(&msg[6], s->s_l[i]);
	pkt_size = create_gs_hdr(msg, SESSIONNEW, 0x24, pkt_size);
	send_gs_msg(sock, msg, pkt_size);
      }
    }
    /* WAKE UP from Game, send all players in lobby */
    send_other_players_in_lobby(s, pl, msg);
    pthread_mutex_unlock(&s->mutex);

    pkt_size = 0;
    break;;
  case DISCONNECTSESSION:
    gs_info("lobby: %s disconnected from session", pl->username);
    break;;
  case FINDSUITABLEGROUP:
    // string SDODC_GARAGE
    // [ binary:00 00 00 04, 01 00 00]
    {
      pkt_size = (uint16_t)sprintf(&msg[6], "s%s", tok_array[0]);
      pkt_size++;
      pkt_size = create_gs_hdr(msg, FINDSUITABLEGROUP, 0x24, pkt_size);
    }
    break;
  default:
    gs_info("lobby: Flag not supported %x", recv_flag);
    print_gs_data(buf, (long unsigned int)buf_len);
    return 0;
  }
  
  return pkt_size;
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
void *gs_server_client_handler(void *data) {
  player_t *pl = (player_t *)data;
  int sock = pl->sock; 
  ssize_t read_size;
  char c_msg[MAX_PKT_SIZE], s_msg[MAX_PKT_SIZE];
  memset(c_msg, 0, sizeof(c_msg));
  memset(s_msg, 0, sizeof(s_msg));

  struct timeval tv;
  tv.tv_sec = 1800;       /* Timeout in seconds */
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,(char *)&tv,sizeof(struct timeval));
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(char *)&tv,sizeof(struct timeval));
  
  //Receive a message from client
  while ((read_size = recv(sock, c_msg, sizeof(c_msg) - 1, 0)) > 0) {
    ssize_t write_size = -1;
    if (read_size >= 6) {
	gs_decode_data((uint8_t *)(c_msg + 6), (size_t)(read_size - 6));
	memset(s_msg, 0, sizeof(s_msg));
	write_size = server_msg_handler(sock, pl, s_msg, c_msg, (int)read_size);
	if (write_size > 0)
	  send_gs_msg(sock, s_msg, (uint16_t)write_size);
    }
    if (write_size < 0) {
      gs_error("Client with socket %d is not following protocol - Disconnecting", sock);
      break;
    }
  }
  remove_server_player(pl);
  free(pl);

  return NULL;
}

void *gs_server_handler(void* data) {
  server_data_t *s_data = (server_data_t *)data;
  int socket_desc , client_sock , c, optval;
  struct sockaddr_in server = { 0 }, client = { 0 };

  socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_desc == -1) {
    gs_info("Could not create socket");
    return 0;
  }

  optval = 1;
  setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));
  
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons( s_data->server_port );
  
  if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0) {
    gs_error("Bind failed. Error");
    return 0;
  }
  gs_info("Server TCP listener on port: %d", ntohs(server.sin_port));
  
  listen(socket_desc , 3);
  
  pthread_t thread_id_keepalive;
  if( pthread_create( &thread_id_keepalive , NULL ,  keepalive_server_handler , (void*)s_data) < 0) {
    perror("Could not create keepalive thread");
    return 0;
  }
  pthread_detach(thread_id_keepalive);
  
  pthread_t thread_id;
  c = sizeof(struct sockaddr_in);

  /* If POD add chat-session */
  if (s_data->server_type == POD_SERVER) {
    session_t *sess = (session_t *)calloc(1, sizeof(session_t));
    if (!add_server_session(s_data,
			    sess,
			    NULL,
			    "##Chat",
			    s_data->game,
			    "1.0",
			    "",
			    "",
			    0,
			    s_data->max_players,
			    s_data->max_players,
			    s_data->chatgroup_id,
			    s_data->arena_id,
			    0,
			    0)) {
      free(sess);
      gs_error("Could not create POD Chat session");
      return 0;
    }
  }
  
  while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) ) {
    //Store player data
    player_t *pl = (player_t *)calloc(1, sizeof(player_t));
    pl->addr = client;
    pl->sock = client_sock;
    pl->server = s_data;
    pl->player_id = (uint32_t)(client_sock + 0x0100);
    pl->keepalive = time(NULL);
    pl->ping = 10;
    if (!add_server_player(s_data, pl)) {
        free(pl);
        return 0;
    }
    
    if( pthread_create( &thread_id , NULL ,  gs_server_client_handler , (void*)pl) < 0) {
      gs_error("Could not create thread");
      return 0;
    }
    pthread_detach(thread_id);
  }
  
  if (client_sock < 0) {
    gs_error("Accept failed");
    return 0;
  }
  
  return 0;
}
