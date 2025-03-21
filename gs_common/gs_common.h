#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <netinet/in.h>

/* For ARCADE or SIM in Monaco */
#define SIM_LAP_MODE 1
#define ARCADE_LAP_MODE 2

#define MAX_PKT_SIZE 2000
#define MAX_UNAME_LEN 17
#define MAX_PLAYERS 6

#define POD_SERVER 1
#define MONACO_SERVER 2
#define SDO_SERVER 3

#define NEWUSERREQUEST 0x01
#define CONNECTIONREQUEST 0x02
#define PLAYERNEW 0x03
#define DISCONNECTION 0x04
#define PLAYERREMOVED 0x05
#define NEWS 0x07
#define SEARCHPLAYER 0x08
#define REMOVEACCOUNT 0x09
#define SERVERSLIST 0x0B
#define SESSIONLIST 0x0D
#define PLAYERLIST 0x0F
#define GETGROUPINFO 0x10
#define GROUPINFO 0x11
#define GETPLAYERINFO 0x12
#define PLAYERINFO 0x13
#define CHATALL 0x14
#define CHATLIST 0x15
#define CHATSESSION 0x16
#define CHAT 0x18
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
#define UPDATESESSIONSTATE 0x33
#define URGENTMESSAGE 0x34
#define NEWWAITMODULE 0x36
#define KILLMODULE 0x37
#define STILLALIVE 0x3A
#define PING 0x3B
#define PLAYERKICK 0x3C
#define PLAYERMUTE 0x3D
#define ALLOWGAME 0x3E
#define FORBIDGAME 0x3F
#define GAMELIST 0x40
#define UPDATEADVERTISMEMENTS 0x41
#define UPDATENEWS 0x42
#define VERSIONLIST 0x43
#define UPDATEVERSIONS 0x44
#define UPDATEDISTANTROUTERS 0x46
#define STAT_PLAYER 0x48
#define STAT_GAME 0x49
#define UPDATEFRIEND 0x4A
#define ADDFRIEND 0x4B
#define DELFRIEND 0x4C
#define LOGINWAITMODULE 0x4D
#define LOGINFRIENDS 0x4E
#define ADDIGNOREFRIEND 0x4F
#define DELIGNOREFRIEND 0x50
#define STATUSCHANGE 0x51
#define JOINARENA 0x52
#define LEAVEARENA 0x53
#define IGNORELIST 0x54
#define IGNOREFRIEND 0x55
#define GETARENA 0x56
#define GETSESSION 0x57
#define PAGEPLAYER 0x58
#define FRIENDLIST 0x59
#define PEERMSG 0x5A
#define PEERPLAYER 0x5B
#define DISCONNECTFRIENDS 0x5C
#define JOINWAITMODULE 0x5D
#define LOGINSESSION 0x5E
#define DISCONNECTSESSION 0x5F
#define PLAYERDISCONNECT 0x60
#define ADVERTISEMENT 0x61
#define MODIFYUSER 0x62
#define STARTGAME 0x63
#define CHANGEVERSION 0x64
#define PAGER 0x65
#define LOGIN 0x66
#define PHOTO 0x67
#define LOGINARENA 0x68
#define SQLCREATE 0x6A
#define SQLSELECT 0x6B
#define SQLDELETE 0x6C
#define SQLSET 0x6D
#define SQLSTAT 0x6E
#define SQLQUERY 0x6F
#define ROUTEURLIST 0x7f
#define DISTANCEVECTOR 0x83
#define WRAPPEDMESSAGE 0x84
#define CHANGEFRIEND 0x85
#define NEWRELFRIEND 0x86
#define DELRELFRIEND 0x87
#define NEWIGNOREFRIEND 0x88
#define DELETEIGNOREFRIEND 0x89
#define ARENACONNECTION 0x8A
#define ARENADISCONNECTION 0x8B
#define ARENAWAITMODULE 0x8C
#define ARENANEW 0x8D
#define NEWBASICGROUP 0x8F
#define ARENAREMOVED 0x90
#define DELETEBASICGROUP 0x91
#define SESSIONSBEGIN 0x92
#define SETGROUPDATA 0x93
#define GROUPDATA 0x94
#define ARENA_MESSAGE 0x97
#define SCORECARD 0x98
#define ROUTERPLAYERNEW 0x9E
#define UPDATEPLAYERPING 0xA6
#define UPDATEGROUPSIZE 0xA9
#define SLEEP 0xB3
#define WAKEUP 0xB4
#define SYSTEMPAGE 0xB5
#define FINDSUITABLEGROUP 0xB6

void gs_error(const char* format, ... );
void gs_info(const char* format, ... );
void print_gs_data(void* pkt,unsigned long pkt_size);
uint8_t * gs_decode_data(uint8_t * data, size_t size);
uint8_t * gs_encode_data(uint8_t * data, size_t size);
//HELP
#ifndef __APPLE__
uint32_t strlcpy(char *dst, const char *src, size_t size);
#endif
uint32_t char_to_uint32(char* data);
uint32_t char_to_uint24(char* data);
uint16_t char_to_uint16(char* data);
int uint32_to_char(uint32_t data, char* msg);
int uint24_to_char(uint32_t data, char* msg);
int uint16_to_char(uint16_t data, char* msg);
int bin8_to_msg(uint8_t value, char* msg);
int bin16_to_msg(uint16_t value, char* msg);
int bin32_to_msg(uint32_t value, char* msg);
int str2int(char const* str);
void send_gs_msg(int sock, char* msg, uint16_t pkt_size);
time_t get_time_ms();
