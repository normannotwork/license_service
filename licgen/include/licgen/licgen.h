#ifndef TIUS_LICGEN_LICGEN_H
#define TIUS_LICGEN_LICGEN_H

#include <time.h>

/// описание возникшей ошибки
typedef struct {
    int err_location;     /// место (функция), где возникла ошибка
    int err_type;         /// тип возникшей ошибки
}t_licgen_err;

/// результат проверки лицензии
typedef enum {
    LICGEN_LICENSE_OK,        /// действительная лицензия
    LICGEN_LICENSE_EXPIRED,   /// истекшая лицензия
    LICGEN_WRONG_LICENSE,     /// неправильная лицензия
    LICGEN_INTERNAL_ERROR     /// произошла внутренняя ошибка
}t_licgen_verify_res;

/**
 * Вызывается приложением-клиентом, чтобы создать серийник по оборудованию и секрету
 * @param serial - буфер, куда будет записан серийник
 * @param serial_len - максимальная вместимость serial
 * @return Длина получившегося серийника или 0 в случае ошибки
 * @details Считает хеш по секрету приложения и оборудованию, присоединяет текущее время к хешу и шифрует их
 * @example Секрет можно сгенерить так: openssl rand -hex 32
 */
int licgen_generate_serial_key(unsigned char *serial, int serial_len);

/**
 * Вызывается приложением-генератором ключа
 * @param serial - серийник
 * @param serial_len - размер серийника
 * @param license_key - буфер, куда будет записана лицензия
 * @param license_key_len - максимальная вместимость license_key
 * @param expire_time - время истечения лицензии
 * @return Длина получившейся лицензии или 0 в случае ошибки
 * @details Расшифровывает серийник, генерит ключ лицензии, добавляет к нему время
 * действия, перекладывает время создания серийника и шифрует обратно
 */
int licgen_generate_license_key(unsigned char *serial, int serial_len, unsigned char *license_key,
                                int license_key_len, time_t expire_time);

/**
 * Вызывается приложением-клиентом, чтобы проверить, совпадает ли ключ с серийником и действительна ли лицензия
 * @param license - ключ лицензии
 * @param license_len - длина лицензии
 * @return Результат проверки ключа лицензии
 * @details Повторно собирает серийник, сравнивает его с расшифрованным ключом лицензии, и
 * получает из ключа лицензии время действия
 */
t_licgen_verify_res licgen_verify_license_key(unsigned char *license, int license_len);

/**
 * Сгенерировать серийник и сохранить его в файл
 * @param serial_file_path - путь к файлу, куда сохранить серийник
 * @return 1 - успешно, 0 - ошибка
 */
int licgen_generate_and_save_serial_key(char *serial_file_path);

/**
 * Сгенерировать ключ лицензии на основе серийника из файла и сохранить лицензию в файл (время истечения - time_t)
 * @param serial_file_path - путь к файлу с серийником
 * @param expire_time - время истечения лицензии
 * @param license_file_path - путь к файлу, куда сохранить лицензию
 * @return 1 - успешно, 0 - ошибка
 */
int licgen_generate_and_save_license_key_with_time_t(char *serial_file_path, time_t expire_time,
                                                     char *license_file_path);

/**
 * Сгенерировать ключ лицензии на основе серийника из файла и сохранить лицензию в файл (время истечения - строчка)
 * @param serial_file_path - путь к файлу с серийником
 * @param expire_date - время истечения лицензии (ДД.ММ.ГГГГ)
 * @param license_file_path - путь к файлу, куда сохранить лицензию
 * @return 1 - успешно, 0 - ошибка
 */
int licgen_generate_and_save_license_key_with_date_str(char *serial_file_path, char *expire_date,
                                                       char *license_file_path);

/**
 * Считать ключ лицензии из файла и проверить, действительна ли лицензия
 * @param license_file_path - путь к файлу с лицензией
 * @return 1 - успешно, 0 - ошибка
 */
t_licgen_verify_res licgen_read_and_verify_license_key(char *license_file_path);

/**
 * Определить, запущена ли программа в виртуальной машине
 * @return 1 - запущена в вм, 0 - запущена на настоящем компьютере
 */
int licgen_detect_vm();

/**
 * Получить описание последней ошибки
 * @return описание последней ошибки
 */
t_licgen_err licgen_get_last_error();
#endif //TIUS_LICGEN_LICGEN_H
