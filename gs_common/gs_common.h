#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include <netinet/in.h>

/* For ARCADE or SIM in Monaco */
#define SIM_LAP_MODE 1
#define ARCADE_LAP_MODE 2

#define MAX_PKT_SIZE 1024
#define MAX_UNAME_LEN 17

#define POD_SERVER 1
#define MONACO_SERVER 2
#define SDO_SERVER 3

#define NEWUSERREQUEST 0x01
#define GROUPINFO 0x11
#define PLAYERINFO 0x13
#define CREATESESSION 0x1A
#define SESSIONNEW 0x1B
#define JOINSESSION 0x1C
#define JOINNEW 0x1F
#define LEAVESESSION 0x20
#define JOINLEAVE 0x21
#define SESSIONREMOVE 0x22
#define GSSUCCESS 0x26
#define GSFAIL 0x27
#define BEGINGAME 0x28
#define UPDATEPLAYERINFO 0x2D
#define MASTERCHANGED 0x30
#define UPDATESESSIONS 0x33
#define STILLALIVE 0x3A
#define PING 0x3B
#define PLAYERKICK 0x3C
#define LOGINWAITMODULE 0x4D
#define STATUSCHANGE 0x51
#define JOINARENA 0x52
#define GETSESSION 0x57
#define PEERMSG 0x5A
#define PEERPLAYER 0x5B
#define JOINWAITMODULE 0x5D
#define LOGINSESSION 0x5E
#define DISCONNECTSESSION 0x5F
#define STARTGAME 0x63
#define LOGIN 0x66
#define LOGINARENA 0x68
#define ARENANEW 0x8D
#define NEWBASICGROUP 0x8F
#define ARENAREMOVED 0x90
#define DELETEBASICGROUP 0x91
#define SESSIONBEGIN 0x92
#define UPDATEPLAYERPING 0xA6
#define UPDATEGROUPSIZE 0xA9
#define SYSTEMPAGE 0xB5
#define UNKNOWN 0xB6
#define WAKEUP 0xB4
#define SLEEP 0xB3
#define CUSTOM_DC_STAT 0x98

void gs_error(const char* format, ... );
void gs_info(const char* format, ... );
void print_gs_data(void* pkt,unsigned long pkt_size);
uint8_t * gs_decode_data(uint8_t * data, size_t size);
uint8_t * gs_encode_data(uint8_t * data, size_t size);
//HELP
uint32_t strlcpy(char *dst, const char *src, size_t size);
uint32_t char_to_uint32(char* data);
uint16_t char_to_uint16(char* data);
int uint32_to_char(uint32_t data, char* msg);
int uint16_to_char(uint16_t data, char* msg);
int bin8_to_msg(uint8_t value, char* msg);
int bin16_to_msg(uint16_t value, char* msg);
int bin32_to_msg(uint32_t value, char* msg);
int str2int(char const* str);
void send_gs_msg(int sock, char* msg, uint16_t pkt_size);
