#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include <netinet/in.h>

#define ROUTER_TCP_PORT 40000
#define HTTP_PORT 80

typedef struct {
  uint16_t gs_wm_sdo_port;
  uint16_t gs_wm_pod_port;
  uint16_t gs_wm_monaco_port;
 
  char gs_wm_pod_ip[INET_ADDRSTRLEN];
  char gs_wm_sdo_ip[INET_ADDRSTRLEN];
  char gs_wm_monaco_ip[INET_ADDRSTRLEN];
  
  char gs_db_path[256];
  char gs_config_path[256];
  //DB
  sqlite3 *db;
} server_data_t;

typedef struct {
  int sock;
  struct sockaddr_in addr;
  uint8_t game;
  server_data_t *data;
} player_t;

void *gs_router_client_handler(void *data);
