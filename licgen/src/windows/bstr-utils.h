#ifndef LICGEN_BSTR_UTILS_H
#define LICGEN_BSTR_UTILS_H

#include <windows.h>

/**
 * Конвертировать строку в строку BSTR
 * @param str - строка
 * @return строка BSTR, NULL - в случае ошибки
 * @details при получении строки BSTR происходит выделение памяти. Необходимо вызвать freeBSTR() для освобождения памяти
 */
BSTR getBSTR(char *str);

/**
 * Освободить память, выделенную для строки BSTR
 * @param bstr - строка BSTR
 */
void freeBSTR(BSTR bstr);

#endif //LICGEN_BSTR_UTILS_H
