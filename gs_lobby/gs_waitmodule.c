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
#include <signal.h>
#include "gs_lobby.h"
#include "gs_waitmodule.h"
#include "gs_sql.h"
#include "../gs_common/gs_common.h"
#include "../gs_common/gs_msg.h"
#include "discord.h"

#define USER_DOESNT_EXIST 1
#define PASSWORD_INCORRECT 2
#define USER_ALREADY_LOGGED_IN 3
#define LOGIN_FAILED 4

player_t* find_user(server_data_t *s, const char* username, int prefix) {
  for (int i = 0; i < s->max_players; i++) {
      if (s->waitmodule_p_l[i] == NULL)
	continue;
      int cmp;
      if (prefix)
	cmp = strncmp(s->waitmodule_p_l[i]->username, username, strlen(username));
      else
	cmp = strcmp(s->waitmodule_p_l[i]->username, username);
      if (cmp == 0)
	return s->waitmodule_p_l[i];
  }
  return NULL;
}

/*
 * Function: get_server_config
 * --------------------
 * parses the <server>.cfg file into server data struct
 * 
 *  server_data_t *s: pointer to server data struct
 *  fn: filename to read from
 *  buf: pointer to received buffer
 *
 *  returns: 1 => OK
 *           0 => FAIL
 *
 */

int get_server_config(server_data_t *s, char *fn) {
  gs_info("Reading config...");
  FILE *file = fopen(fn,"r");
  int server_port = 0, waitmodule_port = 0, server_type = 0;
  int arena_id = 0, basicgroup_id = 0, start_session_id = 0;
  int max_sessions = 0, max_players = 0;
  char server_ip[16], server_db_path[256], buf[1024], server_name[32];
  char discord_url[128];
  
  memset(buf, 0, sizeof(buf));
  memset(server_ip, 0, sizeof(server_ip));
  memset(server_db_path, 0, sizeof(server_db_path));
  server_name[0] = '\0';
  discord_url[0] = '\0';
  
  if (file != NULL) {
    while (fgets(buf, sizeof(buf), file) != NULL) {
      sscanf(buf, "SERVER_IP=%15s", server_ip);
      sscanf(buf, "SERVER_PORT=%d", &server_port);
      sscanf(buf, "SERVER_WAITMODULE_PORT=%d", &waitmodule_port);
      sscanf(buf, "SERVER_TYPE=%d", &server_type);
      sscanf(buf, "SERVER_ARENA_ID=%d", &arena_id);
      sscanf(buf, "SERVER_BASICGROUP_ID=%d", &basicgroup_id);
      sscanf(buf, "SERVER_START_SESSION_ID=%d", &start_session_id);
      sscanf(buf, "SERVER_MAX_PLAYERS=%d", &max_players);
      sscanf(buf, "SERVER_MAX_SESSIONS=%d", &max_sessions);    
      sscanf(buf, "SERVER_DB_PATH=%s", server_db_path);
      sscanf(buf, "SERVER_NAME=%31s", server_name);
      sscanf(buf, "DISCORD_URL=%s", discord_url);
    }
    fclose(file);
  } else {
    gs_info("Config file %s is missing", fn);
    return 0;
  }

  if (server_ip[0] == '\0') {
    gs_info("Missing SERVER_IP");
    return 0;
  } 
  if (server_db_path[0] == '\0') {
    gs_info("Missing GS_DB_PATH");
    return 0;
  }
  if (server_port == 0) {
    gs_info("Missing SERVER_PORT");
    return 0;
  }
  if (waitmodule_port == 0) {
    gs_info("Missing SERVER_WAITMODULE_PORT");
    return 0;
  }
  if (server_type == 0) {
    gs_info("Missing SERVER_TYPE");
    return 0;
  }
  if (server_type > 3) {
    gs_info("SERVER_TYPE only supports: 1 (POD), 2 (MONACO), 3 (SDO)");
    return 0;
  }
  if (arena_id < 100 || arena_id > 1000 ) {
    gs_info("SERVER_ARENA_ID is either missing or not in the correct range (100<ARENA_ID<1000)");
    return 0;
  }
  if (basicgroup_id < 100 || basicgroup_id > 1000 ) {
    gs_info("SERVER_BASICGROUP_ID is either missing or not in the correct range (100<BASICGROUP_ID<1000)");
    return 0;
  }
  if (start_session_id < 100 || start_session_id > 1000 ) {
    gs_info("SERVER_START_SESSION_ID is either missing or not in the correct range (100<START_SESSION_ID<1000)");
    return 0;
  }
  if (max_players == 0) {
    gs_info("Missing SERVER_MAX_PLAYERS");
    return 0;
  }
  if (max_sessions == 0) {
    gs_info("Missing SERVER_MAX_SESSIONS");
    return 0;
  }

  strncpy(s->server_ip, server_ip, sizeof(s->server_ip) - 1);
  strncpy(s->server_db_path, server_db_path, sizeof(s->server_db_path) - 1);
  strncpy(s->name, server_name, sizeof(s->name) - 1);

  s->waitmodule_port = (uint16_t)waitmodule_port;
  s->server_port = (uint16_t)server_port;
  s->server_type = (uint8_t)server_type;
  s->arena_id = (uint32_t)arena_id;
  s->basicgroup_id = (uint32_t)basicgroup_id;
  s->chatgroup_id = (uint32_t)start_session_id;
  s->start_session_id = (uint32_t)start_session_id;
  s->max_players = (uint16_t)max_players;
  s->max_sessions = (uint16_t)max_sessions;
  
  if (s->server_type == POD_SERVER) {
    strcpy(s->game, "POD2DC");
    strcpy(s->allowedbranch, "POD2DC,POD2DCT");
  } else if (s->server_type == MONACO_SERVER) {
    strcpy(s->game, "MONACODC");
    strcpy(s->allowedbranch, "MONACODC");
  } else if (s->server_type == SDO_SERVER) {
    strcpy(s->game, "SDODC");
    strcpy(s->allowedbranch, "SDODC_GARAGE");
  } else {
    gs_info("Server type is wrong %d", s->server_type);
    return 0;
  }
#ifdef DISCORD
  if (discord_url[0] != '\0')
    set_discord_params(s->server_type, discord_url);
#endif
  
  gs_info("Loaded Config:");
  gs_info("\tSERVER_IP: %s", s->server_ip);
  gs_info("\tSERVER_PORT: %d", s->server_port);
  gs_info("\tSERVER_WAITMODULE_PORT: %d", s->waitmodule_port);
  gs_info("\tSERVER_TYPE: %d (%s)", s->server_type, s->game);
  gs_info("\tSERVER_ARENA_ID: %d", s->arena_id);
  gs_info("\tSERVER_BASICGROUP_ID: %d", s->basicgroup_id);
  gs_info("\tSERVER_CHATGROUP_ID: %d", s->chatgroup_id);
  gs_info("\tSERVER_START_SESSION_ID: %d", s->start_session_id);
  gs_info("\tSERVER_MAX_PLAYERS: %d", s->max_players);
  gs_info("\tSERVER_MAX_SESSIONS: %d", s->max_sessions);
  gs_info("\tSERVER_DB_PATH: %s", s->server_db_path);
  if (s->name[0] != '\0')
    gs_info("\tSERVER_NAME: %s", s->name);

  return 1;
}

void init_server(int argc, char *argv[], server_data_t *s) {
  int opt;
  char* config_path = NULL;
    
  while ((opt = getopt (argc, argv, "c:")) != -1) {
    switch (opt) {
    case 'c':
      config_path = optarg;
      break;
    }
  }

  if (config_path == NULL) {
    gs_info("Missing -c <path to config>");
    exit(-1);
  }

  if (get_server_config(s, config_path) != 1) {
    exit(-1);
  }

  s->group_size = 0;
  
  s->s_l = calloc(s->max_sessions, sizeof(session_t *));
  s->waitmodule_p_l = calloc(s->max_players, sizeof(player_t *));
  s->server_p_l = calloc(s->max_players, sizeof(player_t *));

  pthread_mutexattr_t mutexattr;
  pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&s->mutex, &mutexattr);
  pthread_mutex_init(&s->wm_mutex, &mutexattr);
}

int add_waitmodule_player(server_data_t *s, player_t *pl) {
  int i;
  uint16_t max_players = s->max_players;

  pthread_mutex_lock(&s->wm_mutex);
  for(i=0;i<max_players;i++) {
    if(!(s->waitmodule_p_l[i])) {
      s->waitmodule_p_l[i] = pl;
      pthread_mutex_unlock(&s->wm_mutex);
      gs_info("Added player with id: 0x%02x", pl->player_id);
      return 1;
    }
  }
  pthread_mutex_unlock(&s->wm_mutex);
  gs_info("Could not add player with id: 0x%02x", pl->player_id);
  gs_info("Server full");
  return 0;
 
}

void remove_waitmodule_player(player_t *pl) {
  server_data_t *s = pl->server;
  int max_players = s->max_players;
  int i=0;
  
  pthread_mutex_lock(&s->wm_mutex);
  for(i=0;i<max_players;i++) {
    if (s->waitmodule_p_l[i] != NULL) {
      if(s->waitmodule_p_l[i]->player_id == pl->player_id) {
	gs_info("waitmod: removed player %s (%x)", pl->username, pl->player_id);
	s->waitmodule_p_l[i] = NULL;
      }
    }
  }
  pthread_mutex_unlock(&s->wm_mutex);
}

const char *get_player_ip(player_t *player) {
  static char str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &player->addr.sin_addr, str, sizeof(str));
  return str;
}

static char *trim(char *s) {
  while (*s == ' ')
    s++;
  char *p = s + strlen(s) - 1;
  while (p >= s && *p == ' ')
    *p-- = '\0';
  return s;
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
ssize_t waitmodule_msg_handler(int sock, player_t *pl, char *msg, char *buf, int buf_len) {
  server_data_t *s = pl->server;
  uint16_t pkt_size = 0, recv_size = 0;
  uint8_t recv_flag = 0;
  char *tok_array[256] =  { NULL };
  char ip[INET_ADDRSTRLEN];
  int pos = 0, nr_parsed = 0, rc = 0;
  char *username = NULL;
  char *game = NULL;
    
  buf[buf_len] = '\0';
  //Parse header
  if (buf_len < 6) {
    gs_info("[%s] waitmod: Protocol error: small packet", get_player_ip(pl));
    return -1;
  }

  recv_flag = (uint8_t)buf[4];
  recv_size = char_to_uint16(&buf[1]);
  if (recv_size > buf_len) {
    gs_info("[%s] waitmod: Protocol error: packet size %d > recv size %d", get_player_ip(pl), recv_size, buf_len);
    return -1;
  }

  while (pos < recv_size) {
    if (nr_parsed == 256) {
      return -1;
    }
    switch (buf[pos]) {
    case 's':
      tok_array[nr_parsed] = &buf[++pos];
      pos += (int)(strlen(tok_array[nr_parsed]));
      nr_parsed++;
      break;;
    default:
      pos++;
      break;;
    }
  }
  
  switch(recv_flag) {
  case LOGINWAITMODULE:
    if (nr_parsed != 1) {
      gs_error("Got %d strings from LOGINWAITMODULE packet needs 1", nr_parsed);
      return 0;
    }

    if (tok_array[0][0] == '\0')
      return 0;

    {
      /* Trim white spaces. No idea why this happens sometimes */
      char *username = trim(tok_array[0]);
      if (username[0] == '\0')
	return 0;
      /* Eject existing user with the same name if any */
      player_t *other = find_user(s, username, 0);
      if (other != NULL)
	shutdown(other->sock, SHUT_RDWR);

      strlcpy(pl->username, username, sizeof(pl->username));
      gs_info("User %s is joining the waitmodule [%s]", pl->username, get_player_ip(pl));
      print_gs_data(buf, (unsigned)buf_len);

      /* Load player record, create if not exists */
      sqlite3 *db = open_gs_db(s->server_db_path);
      if (db == NULL) {
	gs_error("Could not connect to database");
	exit(-1);
      }
      rc = load_player_record(db, pl->username, &pl->points, &pl->trophies);
      if (rc == 2)
	rc = create_player_record(db, pl->username, s->server_type == SDO_SERVER);
      sqlite3_close(db);
    }

    if (rc != 1) {
      pkt_size = create_gsfail(&msg[6], LOGINWAITMODULE, LOGIN_FAILED);
      pkt_size = create_gs_hdr(msg, GSFAIL, 0x14, pkt_size);
    }
    else {
      pkt_size = create_gssuccessful(&msg[6], LOGINWAITMODULE);
      pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x14, pkt_size);
    }
    break;

  case PLAYERINFO:
    if (nr_parsed != 1) {
      gs_error("Got %d strings from PLAYERINFO packet needs 1", nr_parsed);
      return 0;
    }
    
    if (tok_array[0] == NULL)
      return 0;

    username = trim(tok_array[0]);

    if (strcmp(pl->username, username) == 0 ) {

      if( (inet_ntop(AF_INET, &(pl->addr.sin_addr), ip, INET_ADDRSTRLEN)) == NULL ) {
	gs_info("Could not convert to IPv4 string on user %s", pl->username);
	return 0;
      }
      
      pkt_size = create_playerinfo(&msg[6], pl->username, ip, s->server_type == SDO_SERVER);
      pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x14, pkt_size);      
      send_gs_msg(sock, msg, pkt_size);
      
      pkt_size = create_new_arena(&msg[6], s->arena_id, s->basicgroup_id, s->server_ip);
      pkt_size = create_gs_hdr(msg, ARENANEW, 0x14, pkt_size);
      send_gs_msg(sock, msg, pkt_size);

      if (s->server_type == SDO_SERVER)
      {
        pkt_size = create_new_basic_group(&msg[6], s->name, s->arena_id, s->basicgroup_id, s->game, s->game);
        pkt_size = create_gs_hdr(msg, NEWBASICGROUP, 0x14, pkt_size);
        send_gs_msg(sock, msg, pkt_size);

        pkt_size = create_new_basic_group(&msg[6], s->name, s->arena_id, s->basicgroup_id + 1, s->game, s->allowedbranch);
        pkt_size = create_gs_hdr(msg, NEWBASICGROUP, 0x14, pkt_size);
        send_gs_msg(sock, msg, pkt_size);
      }
      else
      {
        pkt_size = create_new_basic_group(&msg[6], s->name, s->arena_id, s->basicgroup_id, s->game, s->allowedbranch);
        pkt_size = create_gs_hdr(msg, NEWBASICGROUP, 0x14, pkt_size);
        send_gs_msg(sock, msg, pkt_size);
      }

      pkt_size = create_updategroupsize(&msg[6], s->basicgroup_id, s->group_size);
      pkt_size = create_gs_hdr(msg, UPDATEGROUPSIZE, 0x14, pkt_size);
      send_gs_msg(sock, msg, pkt_size);
      
     
    } else {
      /* Fix for playerinfo lookup from POD chat */
      pthread_mutex_lock(&s->wm_mutex);
      player_t *pl_lookup = find_user(s, username, 1);
      if (pl_lookup != NULL) {
	if( (inet_ntop(AF_INET, &(pl_lookup->addr.sin_addr), ip, INET_ADDRSTRLEN)) == NULL ) {
	  pthread_mutex_unlock(&s->wm_mutex);
	  gs_info("Could not convert to IPv4 string on user %s", pl_lookup->username);
	  return 0;
	}
	/* OK */
	pkt_size = create_playerinfo(&msg[6], pl_lookup->username, ip, s->server_type == SDO_SERVER);
	pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x14, pkt_size);
	send_gs_msg(sock, msg, pkt_size);
      } else {
	/* Send player doesn't exist */
	pkt_size = create_gsfail(&msg[6], PLAYERINFO, USER_DOESNT_EXIST);
	pkt_size = create_gs_hdr(msg, GSFAIL, 0x14, pkt_size);
	send_gs_msg(sock, msg, pkt_size);
      }
      pthread_mutex_unlock(&s->wm_mutex);
    }
      
    pkt_size = 0;
    break;;
  case STILLALIVE:
    pkt_size = 0;
    pkt_size = create_gs_hdr(msg, STILLALIVE, 0x14, pkt_size);
    break;;
  case UPDATEGROUPSIZE:
    pkt_size = create_updategroupsize(&msg[6], s->basicgroup_id, s->group_size);
    pkt_size = create_gs_hdr(msg, UPDATEGROUPSIZE, 0x14, pkt_size);
    break;;
  case JOINARENA: 
    pkt_size = create_joinarena(&msg[6], s->arena_id, s->server_port);
    pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x14, pkt_size);
    break;;
  case LOGINSESSION:
    pkt_size = create_gssuccessful(&msg[6], LOGINSESSION);
    pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x14, pkt_size);
    break;;
  case GETSESSION:
    if (nr_parsed != 1) {
      gs_error("Got %d strings from GETSESSION packet needs 1", nr_parsed);
      return 0;
    }
    
    if (tok_array[0] == NULL)
      return 0;

    gs_info("Is people searching for other players?");    
    
    break;
  case SCORECARD:
    if (nr_parsed != 2) {
      gs_error("Got %d strings from SCORECARD packet needs 2", nr_parsed);
      return 0;
    }

    if (tok_array[0] == NULL)
      return 0;
    if (tok_array[1] == NULL)
      return 0;

    username = tok_array[0];
    game = tok_array[1];

    /* User stat lookup for each user */
    pthread_mutex_lock(&s->wm_mutex);
    {
      char scorecard[64];

      player_t *pl_lookup = find_user(s, username, 0);
      if (pl_lookup != NULL) {
	  if (s->server_type == SDO_SERVER) {
	    sqlite3 *db = open_gs_db(s->server_db_path);
	    if (db == NULL) {
	      gs_error("Could not connect to database");
	      exit(-1);
	    }
	    uint32_t class, points, cash;
	    load_player_scorecard(db, username, &class, &points, &cash);
	    sqlite3_close(db);
	    sprintf(scorecard, "Class,%d|Points,%d|Money,%d", class, points, cash);
	  }
	  else {
	    sprintf(scorecard, "Points,%d|Trophies,%d", pl_lookup->points, pl_lookup->trophies);
	  }
      } else {
	  scorecard[0] = '\0';
      }
      pkt_size = create_playerpoints(&msg[6], username, game, scorecard);
      pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x14, pkt_size);
      send_gs_msg(sock, msg, pkt_size);
    }
    pthread_mutex_unlock(&s->wm_mutex);
    
    pkt_size = 0;
    break;
  case DISCONNECTSESSION:
    gs_info("waitmod: %s disconnected from session", pl->username);
    break;
  default:
    gs_info("[%s] waitmod: Protocol error: unknown message %02x", get_player_ip(pl), recv_flag);
    return -1;
  }
 
  return pkt_size;
}

/*
 * Function: gs_waitmodule_client_handler
 * --------------------
 *
 * Function that handles the Server TCP clients
 * 
 *  *data: ptr to player struct
 *
 *  returns: void
 *
 */
void *gs_waitmodule_client_handler(void *data) {
  player_t *pl = (player_t *)data;
  int sock = pl->sock; 
  ssize_t read_size;
  char c_msg[MAX_PKT_SIZE], s_msg[MAX_PKT_SIZE];

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
	write_size = waitmodule_msg_handler(sock, pl, s_msg, c_msg, (int)read_size);
	if (write_size > 0)
	  send_gs_msg(sock, s_msg, (uint16_t)write_size);
    }
    if (write_size < 0)
      break;
  }
  close(sock);
  remove_waitmodule_player(pl);
  free(pl);

  return NULL;
}

/*
 * Function: gs_waitmodule_handler
 * --------------------
 *
 * Function that handles the gs server
 * 
 *  *data:        ptr to server data struct
 *
 *  returns: void
 *           
 */
int main(int argc, char *argv[]) {
  server_data_t s_data;
  int socket_desc , client_sock , c, optval;
  struct sockaddr_in server = { 0 }, client = { 0 };

  signal(SIGPIPE, SIG_IGN);
  init_server(argc, argv, &s_data);
  
  pthread_t thread_id_server;
  if( pthread_create( &thread_id_server , NULL ,  gs_server_handler , (void*)&s_data) < 0) {
    gs_info("Could not create thread");
    return 1;
  }
  pthread_detach(thread_id_server);
 
  socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_desc == -1) {
    gs_info("Could not create socket");
    return 1;
  }

  optval = 1;
  setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));
  
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons( s_data.waitmodule_port );
  
  if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0) {
    gs_error("Bind failed. Error");
    return 1;
  }
  gs_info("Waitmodule TCP listener on port: %d", ntohs(server.sin_port));
  
  listen(socket_desc , 3);

  pthread_t thread_id;
  c = sizeof(struct sockaddr_in);
  
  while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) ) {
    //Store player data
    player_t *pl = (player_t *)calloc(1, sizeof(player_t));
    pl->addr = client;
    pl->sock = client_sock;
    pl->server = &s_data;
    pl->player_id = (uint32_t)(client_sock + 0x0100);
    pl->keepalive = time(NULL);
    if (!add_waitmodule_player(&s_data, pl)) {
        free(pl);
        close(client_sock);
        continue;
    }
    
    if( pthread_create( &thread_id , NULL ,  gs_waitmodule_client_handler , (void*)pl) < 0) {
      gs_error("Could not create thread");
      return 1;
    }
    pthread_detach(thread_id);
  }
  
  if (client_sock < 0) {
    gs_error("Accept failed");
    return 1;
  }

  gs_info("Exiting waitmodule");
  return 0;
}
