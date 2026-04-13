#ifndef LICGEN_TIME_UTILS_H
#define LICGEN_TIME_UTILS_H

#include <time.h>

/**
 * Распарсить строку со временем в time_t
 * @param date - строка в формате ДД.ММ.ГГГГ
 * @param time_ptr - указатель, куда будет записано получившееся время
 * @return 1 - успешно, 0 - ошибка
 */
int getTimeFromStr(char *date, time_t *time_ptr);

#endif //LICGEN_TIME_UTILS_H
