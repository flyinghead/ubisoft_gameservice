CC = gcc
TARGET = gs_router
CFLAGS = -Wconversion -Wall
LFLAGS = -lpthread -lsqlite3 -lm
SRC = gs_http.c gs_router.c gs_sql.c ../gs_common/gs_common.c ../gs_common/gs_msg.c

DEP = $(SRC) gs_router.h gs_http.h gs_sql.h ../gs_common/gs_common.h ../gs_common/gs_msg.h

all: $(TARGET)

gs_router: $(DEP)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LFLAGS)

clean:
	rm -f $(TARGET)
