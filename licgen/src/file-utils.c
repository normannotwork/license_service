#define _CRT_SECURE_NO_WARNINGS
#include "file-utils.h"
#include <stdio.h>
#include <string.h>

int writeStringToFile(char *str, char *file_path){
  FILE *file;
  if(!str || !file_path)
    return 0;
  file= fopen(file_path, "w");
  if(!file)
    return 0;
  fprintf(file, "%s", str);
  fclose(file);
  return 1;
}

int readStringFromFile(char *file_path, char *str, int str_max_len){
  char *res;
  FILE *file;
  if(!str || !file_path)
    return 0;
  file = fopen(file_path, "r");
  if(!file)
    return 0;
  res = fgets(str, str_max_len, file);
  fclose(file);
  unsigned long last_sym = (unsigned long) strlen(str) -1;
  if(str[last_sym] == '\n') str[last_sym] = '\0';
  if(!res)
    return 0;
  return 1;
}
