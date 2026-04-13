#ifndef LICGEN_HEX_UTILS_H
#define LICGEN_HEX_UTILS_H

/**
 * Получить hex-строку, соответствующую байтовому массиву
 * @param bytes - байтовый массив
 * @param bytes_count - длина байтового массива
 * @param str - буфер, куда  будет записана hex-строка
 * @param str_max_len - максимальная вместимость str
 * @return 1 - успешно, 0 - ошибка
 */
int getHexStringFromBytes(unsigned char *bytes, int bytes_count, char *str, int str_max_len);

/**
 * Получить байтовый массив, соответствующий hex-строке
 * @param hex_str - hex-строка
 * @param bytes - байтовый массив
 * @param bytes_count - максимальная вместимость байтового массива
 * @return Число байтов, записанных в bytes, 0 в случае ошибки
 */
int getBytesFromHexString(char *hex_str, unsigned char *bytes, int bytes_count);

#endif //LICGEN_HEX_UTILS_H
