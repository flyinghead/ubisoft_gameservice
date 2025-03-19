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

#define SDO_DUMMY 0x01
#define SDO_COMPETITOR_SETTINGS 0x02
#define SDO_START_SYNCHRO 0x03
#define SDO_START_TIME 0x04
#define SDO_PLAYER_READY_REQ 0x05
#define SDO_PLAYER_READY_UPDATE 0x06
#define SDO_START_RACE 0x07
#define SDO_START_RACE_ACK 0x08
#define SDO_GAME_SETTINGS 0x0A
#define SDO_GAME_SETTINGS_ACK 0x0B
#define SDO_PLAYER_STAT 0x0C
#define SDO_GAME_SETTINGS_MENUS 0x0D
#define SDO_IN_WAITROOM 0x0E
#define SDO_NEWMASTER_RESYNC 0x0F
#define SDO_FAMOUSLASTWORD 0x10
#define SDO_PLAYER_STATE 0x32
#define SDO_RESTART_RACE 0x33
#define SDO_GAME_EVENT 0x3C
#define SDO_PRICES_LIST 0x65
#define SDO_DBINFO_PLAYERSTAT 0x66
#define SDO_DBINFO_PLAYERCAR 0x67
#define SDO_DBUPDATE_PLAYERSTAT 0x68
#define SDO_DBUPDATE_PLAYERCAR 0x69
#define SDO_DBINFO_PLAYERALLCARS 0x6A
#define SDO_DBINFO_PLAYERDATA 0x6B
#define SDO_DATABASE_STATUS 0x6C
#define SDO_PLAYER_QUIT_RACE 0x6D
#define SDO_LOCAL_END_OF_RACE 0x6E
#define SDO_GAME_DEFINES 0x6F
#define SDO_LOCK_ROOM 0x70
#define SDO_UNLOCK_ROOM 0x71
#define SDO_DBUPDATE_PLAYERQUEST 0x72
#define SDO_DBINFO_PLAYERQUEST 0x73
#define SDO_PLAYER_KICK 0x74
#define SDO_DBINFO_FULLSTATS 0x75
#define SDO_DBUPDATE_FULLSTATS 0x76
#define SDO_STATS_POINT 0x78
#define SDO_STATS_CASH 0x79
#define SDO_STATS_STANDARDAVG 0x7A
#define SDO_STATS_STANDARDWIN 0x7B
#define SDO_STATS_TRIALAVG 0x7C
#define SDO_STATS_TRIALWIN 0x7D
#define SDO_STATS_VENDETTAAVG 0x7E
#define SDO_STATS_VENDETTAWIN 0x7F
#define SDO_STATS_PLAYERPOINTS 0x80
#define SDO_STATS_PLAYERCASH 0x81
#define SDO_STATS_PLAYERSTANDARDAVG 0x82
#define SDO_STATS_PLAYERSTANDARDWIN 0x83
#define SDO_STATS_PLAYERTRIALAVG 0x84
#define SDO_STATS_PLAYERTRIALWIN 0x85
#define SDO_STATS_PLAYERVENDETTAAVG 0x86
#define SDO_STATS_PLAYERVENDETTAWIN 0x87
#define SDO_DBUPDATE_DESC 0x88
#define SDO_DBUPDATE_STANDARD 0x89
#define SDO_DBUPDATE_TRIAL 0x8A
#define SDO_DBUPDATE_VENDETTA 0x8B
#define SDO_REQUEST_MOTD 0x8C
#define SDO_UPDATE_SESSION_INFO 0x8D
#define SDO_VERSION_CHECK 0x8E
#define SDO_DBERROR 0x8F
#define SDO_GMGENERROR 0x90
#define SDO_GETBESTLAP 0x91
#define SDO_COMMIT 0x92
#define SDO_TRACKRECORDS_UPDATE  0xC7
#define SDO_TRACKRECORDS  0xC8

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
