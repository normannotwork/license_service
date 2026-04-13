#ifndef LICGEN_OBFUSCATION_H
#define LICGEN_OBFUSCATION_H

/**
 * Получить настоящий секрет
 * @param in - запутанный (обфусцированный) секрет
 * @param in_len - длина in
 * @param out - буфер, куда будет записан настоящий секрет
 * @param out_len - длина out
 * @return 1 - успешно, 0 - ошибка
 * @note длины in_len и out_len должны совпадать
 */
int getRealSecret(const unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int out_len);

/**
 * Получить запутанный (обфусцированный) секрет
 * @param in - настоящий секрет
 * @param in_len - длина in
 * @param out - буфер, куда будет записан запутанный (обфусцированный) секрет
 * @param out_len - длина out
 * @return 1 - успешно, 0 - ошибка
 * @note длины in_len и out_len должны совпадать
 */
int getObfuscatedSecret(const unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int out_len);

#endif //LICGEN_OBFUSCATION_H
