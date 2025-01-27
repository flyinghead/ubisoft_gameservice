CC = gcc
TARGET = gs_lobby gs_gameserver
CFLAGS = -Wconversion -Wall
LFLAGS = -lpthread -lsqlite3 -lm -lrt
SRC = gs_waitmodule.c gs_lobby.c gs_sql.c ../gs_common/gs_common.c ../gs_common/gs_msg.c
SRC_2 = gs_gameserver.c gs_sql.c ../gs_common/gs_common.c ../gs_common/gs_msg.c
DEP = $(SRC) gs_waitmodule.h gs_lobby.h gs_sql.h ../gs_common/gs_common.h ../gs_common/gs_msg.h
DEP_2 = $(SRC_2) gs_gameserver.h gs_sql.h ../gs_common/gs_common.h ../gs_common/gs_msg.h

all: $(TARGET)

gs_lobby: $(DEP)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LFLAGS)

gs_gameserver: $(DEP_2)
	$(CC) $(CFLAGS) $(SRC_2) -o $@ $(LFLAGS)

clean:
	rm $(TARGET)
