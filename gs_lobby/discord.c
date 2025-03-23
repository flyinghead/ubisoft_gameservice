/*
 * Discord integration
 * Copyright (c) 2025 Flyinghead
 */
#define _GNU_SOURCE	// asprintf
#include <stdlib.h>
#include <curl/curl.h>
#include <pthread.h>
#include "discord.h"
#include "../gs_common/gs_common.h"

struct Notif
{
  char *content;
  char *embedTitle;
  char *embedText;
};
typedef struct Notif Notif;

static char webhook_url[256];
static int serverType;
static int threadCount;

void set_discord_params(int server_type, const char *url) {
  serverType = server_type;
  strcpy(webhook_url, url);
}

static int writeJsonString(char *json, const char *s)
{
  if (s == NULL)
    return sprintf(json, "null");

  char *j = json;
  *j++ = '"';
  for (; *s != '\0'; s++) {
      switch (*s)
      {
	case '"':
	  *j++ = '\\';
	  *j++ = '"';
	  break;
	case '\n':
	  *j++ = '\\';
	  *j++ = 'n';
	  break;
	default:
	  *j++ = *s;
      }
  }
  *j++ = '"';
  *j++ = '\0';

  return (int)(j - json - 1);
}

static void freeNotif(Notif *notif)
{
  free(notif->content);
  free(notif->embedTitle);
  free(notif->embedText);
  free(notif);
}

static void delThread() {
  __atomic_fetch_sub(&threadCount, 1, __ATOMIC_SEQ_CST);
}
static int addThread() {
  int ret = 1;
  if (__atomic_fetch_add(&threadCount, 1, __ATOMIC_SEQ_CST) >= 5) {
      delThread();
      ret = 0;
  }
  return ret;
}

static void *postWebhookThread(void *arg)
{
  Notif *notif = (Notif *)arg;
  CURL *curl = curl_easy_init();
  if (curl == NULL) {
      gs_error("discord: Can't create curl handle");
      freeNotif(notif);
      delThread();
      return NULL;
  }
  CURLcode res;
  curl_easy_setopt(curl, CURLOPT_URL, webhook_url);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "DCNet-DiscordWebhook");
  struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  char msg[1024];
  int n;
  n = sprintf(msg, "{ \"content\": ");
  n += writeJsonString(msg + n, notif->content);
  msg[n++] = ',';
  msg[n++] = ' ';

  switch (serverType) {
    case POD_SERVER:
      n += sprintf(msg + n, "\"embeds\": [ "
    	       "{ \"author\": { \"name\": \"POD: Speedzone\", "
    	       "\"icon_url\": \"https://dcnet.flyca.st/gamepic/pod.jpg\" }, "
    	       "\"title\": ");
      break;
    case MONACO_SERVER:
      n += sprintf(msg + n, "\"embeds\": [ "
    	       "{ \"author\": { \"name\": \"Monaco Racing Simulation 2\", "
    	       "\"icon_url\": \"https://dcnet.flyca.st/gamepic/monaco2.jpg\" }, "
    	       "\"title\": ");
      break;
    case SDO_SERVER:
      n += sprintf(msg + n, "\"embeds\": [ "
    	       "{ \"author\": { \"name\": \"Speed Devils Online\", "
    	       "\"icon_url\": \"https://dcnet.flyca.st/gamepic/sdo.jpg\" }, "
    	       "\"title\": ");
      break;
    default:
      gs_error("Unknown server type: %d", serverType);
      return NULL;
  }
  n += writeJsonString(msg + n, notif->embedTitle);
  n += sprintf(msg + n, ", \"description\": ");
  n += writeJsonString(msg + n, notif->embedText);
  n += sprintf(msg + n, ", \"color\": 9118205 } ] }");
  //printf("%s\n", msg);

  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, msg);

  res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
      gs_error("discord: curl error: %d", res);
  }
  else {
      long code;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
      if (code < 200 || code >= 300)
	gs_error("discord: Discord error: %d", code);
  }
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  freeNotif(notif);
  delThread();
  return NULL;
}

static void postWebhook(Notif *notif)
{
  if (webhook_url[0] == '\0') {
      freeNotif(notif);
      return;
  }
  if (!addThread()) {
      freeNotif(notif);
      gs_error("discord: Max thread count reached");
      return;
  }

  pthread_attr_t threadAttr;
  pthread_t thread;
  if (pthread_attr_init(&threadAttr)
      || pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_DETACHED)
      || pthread_create(&thread, &threadAttr, postWebhookThread, notif))
  {
      gs_error("discord: can't create thread");
      delThread();
      freeNotif(notif);
  }
}

void discord_user_joined(const char *player, const char **lobby_players, int count)
{
  /* Not thread safe but the worst that can happen is 2 notifications at the same time */
  static time_t last_notif;
  time_t now = get_time_ms();
  if (last_notif != 0 && now - last_notif < 5 * 60 * 1000)
    /* No more than one notification every 5 min */
    return;
  last_notif = now;
  Notif *notif = (Notif *)calloc(1, sizeof(Notif));
  asprintf(&notif->content, "Player **%s** joined the race lobby", player);
  notif->embedTitle = strdup("Lobby Players");
  size_t textSize = 1;
  for (int i = 0; i < count; i++)
    textSize += strlen(lobby_players[i]) + 1;
  char *embedText = (char *)malloc(textSize);
  embedText[0] = '\0';
  char *p = embedText;
  for (int i = 0; i < count; i++)
    p += sprintf(p, "%s\n", lobby_players[i]);
  notif->embedText = embedText;
  postWebhook(notif);
}

static void pod_game_created(const char *player, const char *game, const char *game_info)
{
  // game info:
  // b0: weapons
  // b1: power ups
  // b2: collisions
  // b4,5: 1 single race, 2 championship, 3 thriller race
  // 1f for Classification
  uint8_t type = (uint8_t)game_info[0];
  if (type == 0x1f)
    // Classification
    return;
  Notif *notif = (Notif *)calloc(1, sizeof(Notif));
  asprintf(&notif->content, "Player **%s** created a game", player);

  const char *raceType;
  switch (type >> 4)
  {
    case 1:
    default:
      raceType = "Single Race";
      break;
    case 2:
      raceType = "Championship";
      break;
    case 3:
      raceType = "Thriller Race";
      break;
  }
  notif->embedTitle = strdup(raceType);
  asprintf(&notif->embedText, "collisions: %s\npower-ups: %s\nweapons: %s",
		  type & 4 ? "Yes" : "No",
		  type & 2 ? "Yes" : "No",
		  type & 1 ? "Yes" : "No");
  postWebhook(notif);
}

static void monaco_game_created(const char *player, const char *game, const char *game_info)
{
  static const char *track_names[] = {
      "Australia",
      "Brazil",
      "Argentina",
      "San Marino",
      "Monaco",
      "Spain",
      "Canada",
      "France",
      "Great Britain",
      "Germany",
      "Hungary",
      "Belgium",
      "Italy",
      "Austria",
      "Luxembourg",
      "Japan",
      "Andalucia,"
  };
  if (!strcmp(game_info, "D"))
    // Classification
    return;
  // game info:
  // single race: "SASUC00"
  // [1] game type (Arcade, Simulation)
  // [2] laps (Short, Long)
  // [4] collisions ('C': collisions, 'W': no collisions)
  // [5,6] track#
  // championship:
  //   "CAC" Championship Arcade
  //   "CSC" Championship Simulation
  Notif *notif = (Notif *)calloc(1, sizeof(Notif));
  asprintf(&notif->content, "Player **%s** created a game", player);

  if (game_info[0] == 'C') {
      // Championship
      if (game_info[1] == 'A')
	notif->embedTitle = strdup("Championship Arcade");
      else
	notif->embedTitle = strdup("Championship Simulation");
      notif->embedText = strdup("");
  }
  else
  {
      // Single race
      int track_num = (game_info[5] - '0') * 10 + (game_info[6] - '0');
      const char *track_name;
      if (track_num < 0 || track_num >= sizeof(track_names) / sizeof(track_names[0]))
        track_name = "?";
      else
        track_name = track_names[track_num];

      notif->embedTitle = strdup(game_info[1] == 'A' ? "Arcade Race" : "Simulation Race");
      asprintf(&notif->embedText, "track: %s\ncollisions: %s\nlaps: %s",
    		  track_name, game_info[4] == 'C' ? "Yes" : "No",
    		  game_info[2] == 'S' ? "Short" : "Long");
  }
  postWebhook(notif);
}

static void sdo_game_created(const char *player, const char *game, const char *game_info)
{
  static const char *track_names[] = {
      "Aspen Winter",
      "Aspen Summer",
      "Louisiana",
      "Louisiana Tornado",
      "Canada Autumn",
      "Canada Winter",
      "Canada Heavy Winter",
      "Hollywood",
      "Hollywood Disaster",
      "Mexico",
      "Montreal Summer",
      "Montreal Winter",
      "Montreal Ice Storm",
      "Nevada",
      "New York Summer",
      "New York Winter"
  };
  static const char *weather_names[] = {
      "Clear",
      "Cloudy",
      "Rain",
      "Random"
  };
  static const char *time_names[] = {
      "Day",
      "Dusk",
      "Night",
      "Random"
  };
  // track# weather    time   reverse   mode     mirror max     laps  max   max    nitro  wager
  int track_num, weather, time, reverse, mode, mirror, laps, wager;
  sscanf(game_info, "%d %d %d %d %d %d %*d %d %*d %*d %*d %d", &track_num, &weather, &time, &reverse, &mode, &mirror, &laps, &wager);
  const char *track_name;
  if (track_num < 0 || track_num >= sizeof(track_names) / sizeof(track_names[0]))
    track_name = "?";
  else
    track_name = track_names[track_num];
  const char *weather_name;
  if (weather < 0 || weather >= sizeof(weather_names) / sizeof(weather_names[0]))
    weather_name = "?";
  else
    weather_name = weather_names[weather];
  const char *time_name;
  if (time < 0 || time >= sizeof(time_names) / sizeof(time_names[0]))
    time_name = "?";
  else
    time_name = time_names[time];

  Notif *notif = (Notif *)calloc(1, sizeof(Notif));
  asprintf(&notif->content, "Player **%s** created game **%s**", player, game);

  const char *raceMode;
  switch (mode) {
    case 4: raceMode = "Trials Race"; break;
    case 5: raceMode = "Vendetta Race"; break;
    default: raceMode = "Standard Race"; break;
  }
  notif->embedTitle = strdup(raceMode);
  asprintf(&notif->embedText, "Track: %s\nWeather: %s\nTime: %s\nLaps: %d%s%s",
		  track_name, weather_name, time_name, laps,
		  reverse ? "\nReverse" : "", mirror ? "\nMirror" : "");
  postWebhook(notif);
}


void discord_game_created(const char *player, const char *game, const char *game_info)
{
  switch (serverType)
  {
    case POD_SERVER:
      pod_game_created(player, game, game_info);
      break;
    case MONACO_SERVER:
      monaco_game_created(player, game, game_info);
      break;
    case SDO_SERVER:
      sdo_game_created(player, game, game_info);
      break;
  }
}
