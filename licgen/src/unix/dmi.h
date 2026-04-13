#ifndef LICGEN_DMI_H
#define LICGEN_DMI_H

/**
 * Прочитать информацию об оборудовании из распарсенной таблицы DMI
 * @param file_name - имя свойства (название файла распарсенной таблицы DMI)
 * @param buffer - буфер, куда будет записано считанное свойство
 * @param buffer_len - максимальная вместимость buffer
 * @return 1 - успешно, 0 - ошибка
 * @details Ошибка может возникнуть из-за отсутствия файла DMI или если не удалось считать строку из DMI
 * @details Распарсенная таблица DMI находится в "/sys/class/dmi/id"
*/
int getDMIString(char *file_name, char *buffer, int buffer_len);

#endif //LICGEN_DMI_H
