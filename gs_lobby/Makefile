CC = gcc
TARGET = gs_lobby gs_gameserver
CFLAGS = -Wconversion -Wall -g -O3
LFLAGS := -lpthread -lsqlite3 -lm -lrt
DEPS = gs_waitmodule.h gs_lobby.h gs_gameserver.h gs_sql.h ../gs_common/gs_common.h ../gs_common/gs_msg.h Makefile
COMMON_OBJS := gs_sql.o ../gs_common/gs_common.o ../gs_common/gs_msg.o
DISCORD = ON

ifeq ($(DISCORD), ON)
  CFLAGS := $(CFLAGS) -DDISCORD
  COMMON_OBJS := $(COMMON_OBJS) discord.o
  LFLAGS := $(LFLAGS) -lcurl
endif

all: $(TARGET)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

gs_lobby: gs_waitmodule.o gs_lobby.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) gs_waitmodule.o gs_lobby.o $(COMMON_OBJS) -o $@ $(LFLAGS)

gs_gameserver: gs_gameserver.o udp_pod.o udp_sdo.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) gs_gameserver.o udp_pod.o udp_sdo.o $(COMMON_OBJS) -o $@ $(LFLAGS)

clean:
	rm -f *.o $(TARGET)
