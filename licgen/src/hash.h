#ifndef LICGEN_HASH_H
#define LICGEN_HASH_H

/// длина хеша в байтах
#define HASH_LEN 64

/**
 * Получить хеш
 * @param in - данные, для которых нужно вычислить хеш
 * @param in_len - длина данных в in
 * @return указатель на хеш, NULL в случае ошибки
 */
unsigned char *getHash(unsigned char *in, int in_len);

#endif //LICGEN_HASH_H
