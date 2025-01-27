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
 * Game Service HTTP functions for Dreamcast
 */

#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include "gs_router.h"
#include "../gs_common/gs_common.h"

char cfg_path[256];
void http_handler(int s) { gs_info("Caught a SIGPIPE"); }

/*
 * Function: read_config_file
 * --------------------
 *
 * Function that reads the config file
 * from disc.
 * 
 *  *f_name: filename to read
 *  *msg:    outgoing client msg
 *
 *  returns: file size
 *
 */
uint32_t read_config_file(char *f_name, char *msg) {  
  FILE *file;
  uint32_t fileLen;

  file = fopen(f_name, "rb");
  if (!file) {
    gs_error("Unable to open file %s", f_name);
    return 0;
  }
	
  fseek(file, 0, SEEK_END);
  fileLen = (uint32_t)ftell(file);
  fseek(file, 0, SEEK_SET);

  if (fileLen > MAX_PKT_SIZE) {
    gs_error("File size greater then buffer");
    return 0;
  }

  fread(msg, fileLen, 1, file);
  fclose(file);

  return (fileLen-1);
}

/*
 * Function: http_msg_handler
 * --------------------
 *
 * Function that handles the http
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
uint32_t http_msg_handler(char *msg, char *buf, int buf_len) {
  uint32_t pkt_size=0;
  char http_fn[512];
  memset(http_fn,0,sizeof(http_fn));
  
  buf[buf_len] = '\0';
  if (buf_len > 0 && buf[buf_len - 1] == '\n')
    buf[--buf_len] = '\0';

  if (strstr(buf, "SDDC") != NULL) {
    gs_info("Load SDDC config");
    sprintf(http_fn, "%s%s", cfg_path, "sdo.cfg"); 
  } else if (strstr(buf, "POD2DC") != NULL) {
    gs_info("Load POD2 config");
    sprintf(http_fn, "%s%s", cfg_path, "pod.cfg"); 
  } else if (strstr(buf, "MONDC") != NULL) {
    gs_info("Load MONACO config");
    sprintf(http_fn, "%s%s", cfg_path, "monaco.cfg"); 
  } else {
    return 0;
  }
  
  pkt_size = (uint32_t)sprintf(msg, "%s%s%s",
			       "HTTP/1.0 200 OK\r\n",
			       "Content-Type: text/plain\r\n",
			       "Connection: Close\r\n\r\n");

  pkt_size = (uint32_t)(pkt_size + read_config_file(http_fn, &msg[pkt_size]));
  
  return pkt_size;
}

/*
 * Function: gs_http_client_handler
 * --------------------
 *
 * Function that handles the HTTP TCP clients
 * 
 *  *data: ptr to player struct
 *
 *  returns: void
 *
 */
void *gs_http_client_handler(void *data) {
  int sock = *(int*)data; 
  ssize_t read_size=0;
  size_t write_size=0;
  char c_msg[MAX_PKT_SIZE], s_msg[MAX_PKT_SIZE];
  memset(c_msg, 0, sizeof(c_msg));
  memset(s_msg, 0, sizeof(s_msg));

  struct timeval tv;
  tv.tv_sec = 1800;       /* Timeout in seconds */
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,(char *)&tv,sizeof(struct timeval));
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(char *)&tv,sizeof(struct timeval));
  
  //Receive a message from client
  while( (read_size = recv(sock , c_msg , sizeof(c_msg) , 0)) > 0 ) {
    write_size = (ssize_t)http_msg_handler(s_msg, c_msg, (int)read_size);
    if (write_size > 0) {
      write(sock, s_msg, write_size);
      break;
    }
    if (write_size <= 0) {
      break;
    }
    memset(s_msg, 0, sizeof(s_msg));
    memset(c_msg, 0, sizeof(c_msg));
    fflush(stdout);
  }
  
  shutdown(sock, SHUT_RDWR);
  close(sock);
  return 0;
}

/*
 * Function: gs_http_server_handler
 * --------------------
 *
 * Function that handles the http server
 * 
 *  *data:        ptr to server data struct
 *
 *  returns: void
 *           
 */
void *gs_http_server_handler(void *data) {
  server_data_t *s_data = (server_data_t *)data;
  int socket_desc , client_sock , c, optval;
  struct sockaddr_in server = { 0 }, client = { 0 };

  signal(SIGPIPE, http_handler);
  
  socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_desc == -1) {
    gs_info("Could not create socket");
    return 0;
  }

  optval = 1;
  setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));
  
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons( HTTP_PORT );
  
  if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0) {
    gs_error("Bind failed. Error");
    return 0;
  }
  gs_info("HTTP TCP listener on port: %d", ntohs(server.sin_port));
  
  listen(socket_desc , 512);

  pthread_t thread_id;
  c = sizeof(struct sockaddr_in);

  strcpy(cfg_path, s_data->gs_config_path);
 
  while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) ) {
    if (client_sock < 0) {
      gs_info("Accept failed (Socket: %d)");
      sleep(1);
    } else { 
      if( pthread_create( &thread_id , NULL ,  gs_http_client_handler , (void*)&client_sock) < 0) {
	gs_info("Could not create thread");
	return 0;
      }
      pthread_detach(thread_id);
    }
  }
    
  return 0;
}
