PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE PLAYER_DATA(
ID INTEGER PRIMARY KEY AUTOINCREMENT,
USERNAME CHAR(16) NOT NULL,
TOTALPOINTS INT NOT NULL,
TOTALTROPHIES INT NOT NULL,
PLAYERDATA BLOB,
FULLSTATS BLOB
);
CREATE TABLE PLAYER_CAR(
ID INTEGER PRIMARY KEY AUTOINCREMENT,
PLAYER_ID INTEGER,
CAR_NUM INTEGER NOT NULL,
CARDATA BLOB
);
CREATE TABLE TRACK_DATA(
ID INTEGER PRIMARY KEY AUTOINCREMENT,
TRACKNAME CHAR(16) NOT NULL,
USERNAME CHAR(16) NOT NULL,
TRACKTIME INT NOT NULL
);
CREATE TABLE LAP_DATA(
ID INTEGER PRIMARY KEY AUTOINCREMENT,
TRACKNAME CHAR(16) NOT NULL,
USERNAME CHAR(16) NOT NULL,
LAPTIME INT NOT NULL
);
CREATE TABLE PRICE_LIST(
ID INTEGER PRIMARY KEY AUTOINCREMENT,
ITEM_TYPE INTEGER NOT NULL,
ITEM_ID INTEGER NOT NULL,
PRICE INTEGER NOT NULL
);
-- class D cars
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 0, 17500);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 1, 15000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 2, 15000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 3, 10000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 4, 10000);
-- class C
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 5, 40000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 6, 65000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 7, 55000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 8, 50000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 9, 45000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 10, 60000);
-- class B
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 11, 120000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 12, 180000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 13, 140000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 14, 160000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 15, 220000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 16, 200000);
-- class A
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 17, 450000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 18, 550000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 19, 750000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 20, 650000);
INSERT INTO PRICE_LIST (ITEM_TYPE, ITEM_ID, PRICE) VALUES (1, 21, 850000);

CREATE TABLE GAME_DEFINES(
ID INTEGER PRIMARY KEY AUTOINCREMENT,
DEFNUM INTEGER NOT NULL,
DEFVALUE INTEGER NOT NULL
);
-- Ranking bonuses class D
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (0, 13000);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (1, 7700);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (2, 4000);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (3, 2000);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (4, 1000);
-- Ranking bonuses class C
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (5, 16200);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (6, 9600);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (7, 4800);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (8, 2400);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (9, 1200);
-- Ranking bonuses class B
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (10, 20200);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (11, 12000);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (12, 6000);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (13, 3000);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (14, 1500);
-- Ranking bonuses class A
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (15, 25200);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (16, 15000);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (17, 7500);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (18, 3750);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (19, 1800);
-- unknown
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (20, 0);
-- Paint job price
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (21, 5000);
-- unknown
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (22, 100);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (23, 100);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (24, 0);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (25, 0);
-- class C points
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (26, 160000);
-- class B points
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (27, 800000);
-- class A points
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (28, 4000000);
-- unknown
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (29, 0);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (30, 100);
-- % repair price multiplier
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (31, 100);
-- % cash -> driver points
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (32, 100);
-- race bonus 1 (per class)
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (33, 1500);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (34, 1650);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (35, 1750);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (36, 1900);
-- race bonus 2 (per class)
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (37, 1500);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (38, 1650);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (39, 1750);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (40, 1900);
-- race bonus 3 (per class)
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (41, 1500);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (42, 1650);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (43, 1750);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (44, 1900);
-- radar busted premiums (per class)
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (45, 500);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (46, 1000);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (47, 2000);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (48, 3000);
-- radar busted bonus per mph (per class)
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (49, 5);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (50, 10);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (51, 20);
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (52, 30);
-- New user cash (not a game define)
INSERT INTO GAME_DEFINES (DEFNUM, DEFVALUE) VALUES (-1, 10000);

CREATE TABLE MOTD(
ID INTEGER PRIMARY KEY AUTOINCREMENT,
MOTD VARCHAR(2000)
);
INSERT INTO MOTD (MOTD) VALUES ("Welcome to Speed Devils Online");
COMMIT;
