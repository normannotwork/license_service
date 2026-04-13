#ifndef LICGEN_FILE_UTILS_H
#define LICGEN_FILE_UTILS_H

/**
 * Записать строку в файл
 * @param str - строка, которую нужно записать
 * @param file_path - путь к файлу для записи
 * @return 1 - успешно, 0 - ошибка
 * @details Файл открывается на запись в режиме "w"
 */
int writeStringToFile(char *str, char *file_path);

/**
 * Прочитать строку из файла
 * @param file_path - путь к файлу для чтения
 * @param str - буфер, куда будет записана считанная строка
 * @param str_max_len - максимальная вместимость str
 * @return 1 - успешно, 0 - ошибка
 */
int readStringFromFile(char *file_path, char *str, int str_max_len);

#endif //LICGEN_FILE_UTILS_H
