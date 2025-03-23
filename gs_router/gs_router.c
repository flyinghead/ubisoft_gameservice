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
 * Game Service Router functions for Dreamcast
 */

#include <stdlib.h> 
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>   
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h> 
#include <netinet/tcp.h>
#include <sqlite3.h>

#include "gs_router.h"
#include "gs_http.h"
#include "gs_sql.h"
#include "../gs_common/gs_common.h"
#include "../gs_common/gs_msg.h"

#define USER_DOESNT_EXIST 1
#define PASSWORD_INCORRECT 2
#define USER_ALREADY_LOGGED_IN 3
#define LOGIN_FAILED 4

void handler(int s) {
  gs_info("Caught a SIGPIPE");
}

/*
 * Function: get_gs_config
 * --------------------
 * parses the gs.cfg file into server data struct
 * 
 *  server_data_t *s: pointer to server data struct
 *  fn: filename to read from
 *  buf: pointer to received buffer
 *
 *  returns: 1 => OK
 *           0 => FAIL
 *
 */
int get_gs_config(server_data_t *s, char *fn) {
  gs_info("Reading config...");
  FILE *file = fopen(fn,"r");
  int monaco_port=0, sdo_port=0, pod_port=0, http_port = 80;
  char sdo_ip[16], monaco_ip[16], pod_ip[16], buf[1024], db_path[256], config_path[256];

  memset(buf, 0, sizeof(buf));
  memset(sdo_ip, 0, sizeof(sdo_ip));
  memset(pod_ip, 0, sizeof(pod_ip));
  memset(monaco_ip, 0, sizeof(monaco_ip));
  memset(db_path, 0, sizeof(db_path));
  memset(config_path, 0, sizeof(config_path));
  
  if (file != NULL) {
    while (fgets(buf, sizeof(buf), file) != NULL) {
      sscanf(buf, "GS_POD_WAITMODULE_PORT=%d", &pod_port);
      sscanf(buf, "GS_POD_WAITMODULE_IP=%15s", pod_ip);
      sscanf(buf, "GS_MONACO_WAITMODULE_PORT=%d", &monaco_port);
      sscanf(buf, "GS_MONACO_WAITMODULE_IP=%15s", monaco_ip);
      sscanf(buf, "GS_SDO_WAITMODULE_PORT=%d", &sdo_port);
      sscanf(buf, "GS_SDO_WAITMODULE_IP=%15s", sdo_ip);
      sscanf(buf, "GS_DB_PATH=%s", db_path);
      sscanf(buf, "GS_CONFIG_PATH=%s", config_path);
      sscanf(buf, "HTTP_PORT=%d", &http_port);
    }
    fclose(file);
  } else {
    gs_info("Config file gs.cfg is missing in %s", fn);
    return 0;
  }

  if (sdo_ip[0] == '\0') {
    gs_info("Missing GS_SDO_WAITMODULE_IP");
    return 0;
  }
  if (pod_ip[0] == '\0') {
    gs_info("Missing GS_POD_WAITMODULE_IP");
    return 0;
  }
  if (monaco_ip[0] == '\0') {
    gs_info("Missing GS_MONACO_WAITMODULE_IP");
    return 0;
  }
  
  if (db_path[0] == '\0') {
    gs_info("Missing GS_DB_PATH");
    return 0;
  }
  if (config_path[0] == '\0') {
    gs_info("Missing GS_CONFIG_PATH");
    return 0;
  }
  if (sdo_port == 0) {
    gs_info("Missing GS_SDO_WAITMODULE_PORT");
    return 0;
  }
  if (monaco_port == 0) {
    gs_info("Missing GS_MONACO_WAITMODULE_PORT");
    return 0;
  }
  if (pod_port == 0) {
    gs_info("Missing GS_POD_WAITMODULE_PORT");
    return 0;
  }

  strncpy(s->gs_wm_sdo_ip, sdo_ip, sizeof(sdo_ip));
  strncpy(s->gs_wm_pod_ip, pod_ip, sizeof(pod_ip));
  strncpy(s->gs_wm_monaco_ip, monaco_ip, sizeof(monaco_ip));
  
  strncpy(s->gs_db_path, db_path, sizeof(db_path));
  strncpy(s->gs_config_path, config_path, sizeof(config_path));
  
  s->gs_wm_sdo_port = (uint16_t)sdo_port;
  s->gs_wm_monaco_port = (uint16_t)monaco_port;
  s->gs_wm_pod_port = (uint16_t)pod_port;
  s->http_port = (uint16_t)http_port;
    
  gs_info("Loaded Config:");
  gs_info("\tGS_POD_WAITMODULE_PORT: %d", s->gs_wm_pod_port);
  gs_info("\tGS_POD_WAITMODULE_IP: %s", s->gs_wm_pod_ip);
  gs_info("\tGS_SDO_WAITMODULE_PORT: %d", s->gs_wm_sdo_port);
  gs_info("\tGS_SDO_WAITMODULE_IP: %s", s->gs_wm_sdo_ip);
  gs_info("\tGS_MONACO_WAITMODULE_PORT: %d", s->gs_wm_monaco_port);
  gs_info("\tGS_MONACO_WAITMODULE_IP: %s", s->gs_wm_monaco_ip);
  
  gs_info("\tGS_DB_PATH: %s", s->gs_db_path);
  gs_info("\tGS_CONFIG_PATH: %s", s->gs_config_path);
  gs_info("\tHTTP_PORT: %d", s->http_port);
  
  return 1;
}

uint16_t msg_handler(int sock, player_t* pl, char* msg, char* buf, int buf_len) {
  server_data_t *s = (server_data_t *)pl->data;
  uint16_t pkt_size = 0, recv_size = 0;
  uint8_t recv_flag = 0;
  char *tok_array[256];
  int pos = 0, nr_parsed = 0, ret = 0;
  char *game = NULL;
  char *username = NULL;
  char *password = NULL;
  char *firstname = NULL;
  char *lastname = NULL;
  char *email = NULL;
  char *country = NULL;
  sqlite3 *db = NULL;

  buf[buf_len] = '\0';
  //Parse header
  if (buf_len < 6) {
    gs_info("Length of packet is less then 6 bytes...[SKIP]");
    return 0;
  }
  
  recv_flag = (uint8_t)buf[4];
  recv_size = char_to_uint16(&buf[1]);

  if(recv_size > buf_len) {
    gs_info("<- Packet size %d is greater then buffer size %d", recv_size, buf_len);
    return 0;
  }

  while (pos < recv_size) {
    if (nr_parsed == 256) {
      return 0;
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
  case NEWUSERREQUEST:
    if (nr_parsed != 7) {
      gs_error("Got %d strings from NEWUSERREQUEST packet needs 7", nr_parsed);
      return 0;
    }

    game = tok_array[0];
    username = tok_array[1];
    password = tok_array[2];
    firstname = tok_array[3];
    lastname = tok_array[4];
    email = tok_array[5];
    country = tok_array[6];


    //OK - Connect to DB
    db = open_gs_db(s->gs_db_path);
    if (db == NULL) {
      gs_error("Could not connect to database");
      return 0;
    }
    
    ret = is_player_in_gs_db(db, username);

    //Not in db
    if (ret == 2) { 
      ret = write_player_to_gs_db(db,
				  username,
				  password,
				  firstname,
				  lastname,
				  email,
				  country);
      if (ret != 1) {
	/*Create account failed = 1*/
	pkt_size = create_gsfail(&msg[6], NEWUSERREQUEST, 1);
	pkt_size = create_gs_hdr(msg, GSFAIL, 0x14, pkt_size);
	break;
      }
      //In Db
    } else if (ret == 1) { 
      /*Account already exists = 9*/
      pkt_size = create_gsfail(&msg[6], NEWUSERREQUEST, 9);
      pkt_size = create_gs_hdr(msg, GSFAIL, 0x14, pkt_size);
      break;
    } else {
      break;
    }
    
    pkt_size = create_gssuccessful(&msg[6], NEWUSERREQUEST);
    pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x14, pkt_size);
    break;;
  case LOGIN:
    /*Check username and password*/
    if (nr_parsed != 3) {
      gs_error("Got %d strings from LOGIN packet needs 3", nr_parsed);
      return 0;
    }

    username = tok_array[0];
    password = tok_array[1];
    game = tok_array[2];
    
    gs_info("User %s tries to join...", username);

    //OK - Connect to DB
    db = open_gs_db(s->gs_db_path);
    if (db == NULL) {
      gs_error("Could not connect to database");
      return 0;
    }
    
    ret = validate_player_login(db, username, password);
        
    if (ret != 1) {
      gs_error("User not allowed to login %s", password);
      /*GeneralFail = 1, WrongPassword = 2, AlreadyLoggedIn = 3, InvalidUsername = 4*/
      pkt_size = create_gsfail(&msg[6], LOGIN, 2);
      pkt_size = create_gs_hdr(msg, GSFAIL, 0x14, pkt_size);
      break;
    }
    
    if (strncmp(game, "POD2DC1.0", 9) == 0) {
      pl->game = POD_SERVER;
    }
    else if (strncmp(game, "MONDC1.0", 11) == 0) {
      pl->game = MONACO_SERVER;
    } else if (strncmp(game, "SDDC1.0", 7) == 0) {
      pl->game = SDO_SERVER;
    } else {
      gs_error("Game %s is unsupported", game);
      pkt_size = create_gsfail(&msg[6], LOGIN, 1);
      pkt_size = create_gs_hdr(msg, GSFAIL, 0x14, pkt_size);
      break;
    }

    ret = update_player_lastlogin(db, username);
    if (ret != 1) {
      gs_error("Could not update lastlogin for username %s", username);
    }
    
    pkt_size = create_gssuccessful(&msg[6], LOGIN);
    pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x14, pkt_size);
    break;;
  case JOINWAITMODULE:
    if (pl->game == POD_SERVER) {
      pkt_size = create_joinwaitmodule(&msg[6], s->gs_wm_pod_ip, s->gs_wm_pod_port);
    } else if (pl->game == MONACO_SERVER) {
      pkt_size = create_joinwaitmodule(&msg[6], s->gs_wm_monaco_ip, s->gs_wm_monaco_port);
    } else if (pl->game == SDO_SERVER) {
      pkt_size = create_joinwaitmodule(&msg[6], s->gs_wm_sdo_ip, s->gs_wm_sdo_port);
    } else {
      gs_error("Unsupported game");
      break;
    }
    pkt_size = create_gs_hdr(msg, GSSUCCESS, 0x14, pkt_size);
    break;;
  default:
    gs_info("Flag not supported %u", recv_flag);
    return 0;
  }
  if (db != NULL)
    sqlite3_close(db);
  return pkt_size;
}

int main(int argc , char *argv[]) {
  int socket_desc , client_sock , c, optval, opt;
  struct sockaddr_in server , client;
  server_data_t s_data;
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

  signal(SIGPIPE, handler);
  
  //Read cfg file
  if (!get_gs_config(&s_data, config_path))
    return 0;
  
  pthread_t thread_id_http;
  if( pthread_create( &thread_id_http , NULL ,  gs_http_server_handler , (void*)&s_data) < 0) {
    gs_info("Could not create thread");
    return -1;
  }
  pthread_detach(thread_id_http);

  //Create socket
  socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_desc == -1) {
    gs_info("Could not create socket");
    return 0;
  }
  gs_info("Socket created");
  
  optval = 1;
  setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));
  
  //Prepare the sockaddr_in structure
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons( ROUTER_TCP_PORT );
  
  //Bind
  if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0) {
    //print the error message
    gs_info("Bind failed. Error");
    return 0;
  }
  gs_info("Router: TCP listener on port: %d", ROUTER_TCP_PORT);
  
  //Listen
  listen(socket_desc , 3);
  
  c = sizeof(struct sockaddr_in);
  pthread_t thread_id;
  
  while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) ) {
    if (client_sock < 0) {
      gs_info("Accept failed");
      sleep(1);
    } else {
      player_t *pl = (player_t *)malloc(sizeof(player_t));
      pl->addr = client;
      pl->sock = client_sock;
      pl->data = &s_data;
    
      if( pthread_create( &thread_id , NULL ,  gs_router_client_handler , (void*)pl) < 0) {
	gs_info("Could not create thread");
	return 0;
      }
      pthread_detach(thread_id);
    }
  }

  return 0;
}

/*
 * This will handle connection for each router client
*/
void *gs_router_client_handler(void *data)
{
  player_t *pl = (player_t *)data;
  int sock = pl->sock; 
  ssize_t read_size=0;
  size_t write_size=0;
  char c_msg[2048], s_msg[2048], ip[INET_ADDRSTRLEN];
  memset(c_msg, 0, sizeof(c_msg));
  memset(s_msg, 0, sizeof(s_msg));

  struct timeval tv;
  tv.tv_sec = 30;       /* Timeout in seconds */
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,(char *)&tv,sizeof(struct timeval));
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(char *)&tv,sizeof(struct timeval));
  
  //Receive a message from client
  while ((read_size = recv(sock , c_msg , sizeof(c_msg) , 0)) > 0) {
    if (read_size >= 6) {
      gs_decode_data((uint8_t *)(c_msg + 6), (size_t)(read_size - 6));

      //Parse msg
      write_size = msg_handler(sock, pl, s_msg, c_msg, (int)read_size);
      if (write_size > 0)
        send_gs_msg(sock, s_msg, (uint16_t)write_size);
    }
    else {
      write_size = 0;
    }
    if (write_size == 0) {
      gs_error("[ROUTER] - Client with socket %d is not following protocol - Disconnecting", sock);
      break;
    }
    memset(s_msg, 0, sizeof(s_msg));
    memset(c_msg, 0, sizeof(c_msg));
  }

  if ((inet_ntop(AF_INET, &(pl->addr.sin_addr), ip, INET_ADDRSTRLEN)) != NULL)
    gs_info("[ROUTER] - Client with socket %d [%s] disconnected", sock, ip);
  else
    gs_info("[ROUTER] - Could not resolve IP for %d", sock);
  close(sock);
  free(pl);

  return 0;
} 
