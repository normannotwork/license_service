#define _CRT_SECURE_NO_WARNINGS
#include "time-utils.h"
#include <stdio.h>
#include <string.h>

int getTimeFromStr(char *date, time_t *time_ptr){
  struct tm tm_time;
  time_t time_value;

  if(!date || !time_ptr)
    return 0;

  memset(&tm_time, 0, sizeof(tm_time));
  if((sscanf(date, "%d.%d.%d", &tm_time.tm_mday, &tm_time.tm_mon, &tm_time.tm_year)) != 3){
    return 0;
  }

  if(tm_time.tm_mday < 1 || tm_time.tm_mday > 31)
    return 0;

  tm_time.tm_mon--;
  if(tm_time.tm_mon < 0 || tm_time.tm_mon > 11)
    return 0;

  tm_time.tm_year -= 1900;
  if(tm_time.tm_year < 0)
    return 0;

  time_value = mktime(&tm_time);
  *time_ptr = time_value;
  return 1;
}
