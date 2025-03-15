/*
 * Discord integration
 * Copyright (c) 2025 Flyinghead
 */
#pragma once
void set_discord_params(int server_type, const char *url);
void discord_user_joined(const char *player, const char **lobby_players, int count);
void discord_game_created(const char *player, const char *game, const char *game_info);
