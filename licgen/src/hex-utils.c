#define _CRT_SECURE_NO_WARNINGS
#include "hex-utils.h"
#include <stdio.h>
#include <string.h>

int getHexStringFromBytes(unsigned char *bytes, int bytes_count, char *str, int str_max_len){
  char hex_elem_str[3];

  if(!bytes || !str)
    return 0;

  if(bytes_count * 2 + 1 > str_max_len)
    return 0;

  for(int i = 0; i < bytes_count; i++){
    sprintf(hex_elem_str, "%.2x", bytes[i]);
    strcat(str, hex_elem_str);
  }
  return 1;
}

int getBytesFromHexString(char *hex_str, unsigned char *bytes, int bytes_count){
  unsigned char byte;
  int hex_str_len;
  int hex_entities_count;
  char *pos = hex_str;

  if(!hex_str || !bytes)
    return 0;

  hex_str_len = (int) strlen(hex_str);
  hex_entities_count = hex_str_len / 2;

  if(hex_str_len % 2 == 1 || hex_entities_count > bytes_count)
    return 0;

  for(int i = 0; i < hex_entities_count; i++){
    if(sscanf(pos, "%2hhx", &byte) != 1)
      return 0;
    bytes[i] = byte;
    pos += 2;
  }
  return hex_entities_count;
}
