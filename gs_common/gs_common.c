/*
  Game Service Common functions
  Auth Shuouma
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <math.h>
#include "gs_common.h"

#ifndef __APPLE__

uint32_t strlcpy(char *dst, const char *src, size_t size) {
  char *d = dst;
  const char *s = src;
  size_t n = size;

  /* Copy as many bytes as will fit */
  if (n != 0 && --n != 0) {
    do {
      if ((*d++ = *s++) == 0)
	break;
    } while (--n != 0);
  }

  /* Not enough room in dst, add NUL and traverse rest of src */
  if (n == 0) {
    if (size != 0)
      *d = '\0';		/* NUL-terminate dst */
    while (*s++);
  }
  
  return (uint32_t)(s - src - 1); 
}

#endif

void gs_error(const char* format, ... ) {
  va_list args;
  time_t t = time(NULL);
  struct tm tm = *localtime(&t);
  char td_str[64];
  const char* s_str;
  
  memset(td_str, 0, sizeof(td_str));
  snprintf(td_str, sizeof(td_str), "[%04d/%02d/%02d %02d:%02d:%02d]", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  fprintf(stderr,"%s",td_str);
  
  s_str = "[ERROR] ";
  
  fprintf(stderr,"%s",s_str);
  va_start(args,format);
  vfprintf(stderr,format,args);
  va_end(args);
  fprintf(stderr,"\n");
}

void gs_info(const char* format, ... ) {
  va_list args;
  time_t t = time(NULL);
  struct tm tm = *localtime(&t);
  char td_str[64];
  const char* s_str;

  memset(td_str, 0, sizeof(td_str));
  snprintf(td_str, sizeof(td_str), "[%04d/%02d/%02d %02d:%02d:%02d]", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  fprintf(stdout,"%s",td_str);

  s_str = "[INFO] ";

  fprintf(stdout,"%s",s_str);
  va_start(args,format);
  vfprintf(stdout,format,args);
  va_end(args);
  fprintf(stdout,"\n");
  fflush(stdout);
}

void print_gs_data(void* pkt,unsigned long pkt_size) {
  unsigned char* pkt_content = (unsigned char*)pkt;
  unsigned long i,j,off;
  char buffer[17];
  buffer[16] = 0;
  off = 0;
  printf("--------------------\n");
  printf("0000 | ");
  for (i = 0; i < pkt_size; i++) {
    if (off == 16) {
      memcpy(buffer,&pkt_content[i - 16],16);
      for (j = 0; j < 16; j++) if (buffer[j] < 0x20) buffer[j] = '.';
      printf("| %s\n%04X | ",buffer,(unsigned int)i);
      off = 0;
    }
    printf("%02X ",pkt_content[i]);
    off++;
  }
  buffer[off] = 0;
  memcpy(buffer,&pkt_content[i - off],off);
  for (j = 0; j < off; j++) if (buffer[j] < 0x20) buffer[j] = '.';
  for (j = 0; j < 16 - off; j++) printf("   ");
  printf("| %s\n",buffer);
}

uint8_t * gs_decode_data(uint8_t * data, size_t size) {
  uint8_t * m;
  if (data && (size > 0) && (m = (uint8_t *)malloc(size), m)) {
    size_t y;
    size_t r = 0;
    uint8_t * p = (uint8_t *)memcpy(m, data, size);
    size_t d = (size_t)sqrt((double)size);
    if ((d * d) < size)
      ++d;
    for (y = 1; y <= d; ++y) {
      size_t x;
      size_t c = y;
      size_t i = r;
      for (x = d; x; --x ) {
	data[i] = (uint8_t)(*(p++) ^ ((uint8_t)i - 0x77));
	if (x > y)
	  ++c;
	else if (x < y)
	  --c;
	i += c;
	if (i >= size)
	  break;
      }
      r += y;
    }
    free(m);
    return data;
  }
  return 0;
}

uint8_t * gs_encode_data(uint8_t * data, size_t size) {
  uint8_t * m;
  if (data && (size > 0) && (m = (uint8_t *)malloc(size), m)) {
    size_t y;
    size_t r = 0;
    uint8_t * p = m;
    size_t d = (size_t)sqrt((double)size);
    if ((d * d) < size)
      ++d;
    for (y = 1; y <= d; ++y) {
      size_t x;
      size_t c = y;
      size_t i = r;
      for (x = d; x; --x ) {
	*(p++) = (uint8_t)(data[i] ^ ((uint8_t)i - 0x77));
	if (x > y)
	  ++c;
	else if (x < y)
	  --c;
	i += c;
	if (i >= size)
	  break;
      }
      r += y;
    }
    memcpy(data, m, size);
    free(m);
    return data;
  }
  return 0;
}

void send_gs_msg(int sock, char* msg, uint16_t pkt_size) {
  gs_encode_data((uint8_t*)(msg+6), (size_t)(pkt_size-6));
  write(sock, msg, pkt_size);
}

//Help functions
uint32_t char_to_uint32(char* data) {
  uint32_t val = (uint32_t)((uint8_t)data[0] << 24 | (uint8_t)data[1] << 16 | (uint8_t)data[2] << 8  | (uint8_t)data[3]);
  return val;
}

uint32_t char_to_uint24(char* data) {
  return (uint32_t)((uint8_t)data[0] << 16 | (uint8_t)data[1] << 8 | (uint8_t)data[2]);
}

uint16_t char_to_uint16(char* data) {
  uint16_t val = (uint16_t)((uint8_t)data[0] << 8 | (uint8_t)data[1]);
  return val;
}

int uint32_to_char(uint32_t data, char* msg) {
  msg[0] = (char)(data >> 24);
  msg[1] = (char)(data >> 16);
  msg[2] = (char)(data >> 8);
  msg[3] = (char)data;
  return 4;
}

int uint24_to_char(uint32_t data, char* msg) {
  msg[0] = (char)(data >> 16);
  msg[1] = (char)(data >> 8);
  msg[2] = (char)data;
  return 3;
}

int uint16_to_char(uint16_t data, char* msg) {
  msg[0] = (char)(data >> 8);
  msg[1] = (char)data;
  return 2;
}

int bin8_to_msg(uint8_t value, char* msg) {
  int pkt_size = 0;
  msg[pkt_size++] = '\x62';
  pkt_size += uint32_to_char(sizeof(uint8_t), &msg[pkt_size]);
  msg[pkt_size] = (char)value;
  return pkt_size;
}

int bin16_to_msg(uint16_t value, char* msg) {
  int pkt_size = 0;
  msg[pkt_size++] = '\x62';
  pkt_size += uint32_to_char(sizeof(uint16_t), &msg[pkt_size]);
  pkt_size += uint16_to_char(htons(value), &msg[pkt_size]);
  return pkt_size;
}

int bin32_to_msg(uint32_t value, char* msg) {
  int pkt_size = 0;
  msg[pkt_size++] = '\x62';
  pkt_size += uint32_to_char(sizeof(uint32_t), &msg[pkt_size]);
  pkt_size += uint32_to_char(htonl(value), &msg[pkt_size]);
  return pkt_size;
}

int str2int(char const* str) {
  char *endptr;
  errno = 0;
  long int ret = strtol(str, &endptr, 10);

  if (endptr == str) {
    gs_error("Not a valid int");
    return 0;
  }
  if (errno == ERANGE) {
    gs_error("Error parsing in str2int");
    return 0;
  }

  return (int)ret;
}

time_t get_time_ms() {
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  return now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
