#define _CRT_SECURE_NO_WARNINGS
#include "licgen/licgen.h"
#include "hwinfo.h"
#include "hash.h"
#include "obfuscation.h"
#include "crypt.h"
#include "file-utils.h"
#include "hex-utils.h"
#include "time-utils.h"
#include <stdio.h>
#include <string.h>
#include "detect-vm.h"

#define TIME_T_MAX_SIZE 8         /// максимальный поддерживаемый размер типа time_t
#define SHORT_SIZE sizeof(short)  /// размер типа short
#define STR_MAX_LEN 2048          /// максимальная длина строки с информацией об оборудовании
#define BUFFER_MAX_LEN 2048       /// максимальный размер буффера, где хранятся склеенные время создания, секрет
                                  /// и информация об оборудовании

/// ФОРМАТ ЧИСТОГО СЕРИЙНИКА
/// - длина чистого серийника - 2 байта - (с учетом поля длины)
/// - время создания серийника - 8 байт
/// - хеш (время создания + информация об оборудовании + секрет) - 64 байта
/// ИТОГО: 74 байта
/// размер серийника: 80 байтов

/// ФОРМАТ ЧИСТОЙ ЛИЦЕНЗИИ
/// - длина чистой лицензии - 2 байта - (с учетом поля длины)
/// - время истечения лицензии - 8 байт
/// - чистый серийник (полностью, со всеми полями) - 74 байта
/// ИТОГО: 84 байта
/// размер лицензии: 96 байтов

/// (от начала буффера-массива)
#define TIME_OFFSET  SHORT_SIZE     /// отступ метки времени в чистом серийнике/лицензии
#define DATA_OFFSET  (SHORT_SIZE + TIME_T_MAX_SIZE)  /// отступ хеша в чистом серийнике
                                                     /// И отступ чистого серийника в чистой лицензии

/// общая длина чистого серийника
#define PURE_SERIAL_LEN  (DATA_OFFSET + HASH_LEN)

/// длина секрета
#define SECRET_LEN 32

/// типы ошибок
typedef enum{
    NO_ERROR = 0,                 /// нет ошибки

    IN_PARAMETER_IS_NULL = 1,     /// один из входных параметров - нулевой указатель
    OUT_PARAMETER_IS_NULL = 2,    /// выходной параметр - нулевой указатель
    OUT_BUFFER_OVERFLOW = 3,      /// недостаточная длина выходного буфера

    CANT_ENCRYPT = 10,            /// не удалось зашифровать
    CANT_DECRYPT = 11,            /// не удалось расшифровать
    CANT_GET_HEX_STRING = 12,     /// не удалось получить шестнадцатеричную строку
    CANT_PARSE_HEX_STRING = 13,   /// не удалось распарсить шестнадцатеричную строку
    CANT_WRITE_TO_FILE = 14,      /// не удалось записать в файл
    CANT_READ_FROM_FILE = 15,     /// не удалось прочитать из файла
    CANT_PARSE_TIME = 16,         /// не удалось распарсить строчку с датой
    PLATFORM_NOT_SUPPORTED = 17,  /// не поддерживается платформа, где тип time_t имеет размер более 8 байтов

    INIT_HWINFO_FAILED = 20,      /// не удалось инициализировать модуль hwInfo
    CANT_GET_HWINFO_ENTITY = 21,  /// не удалось получить информацию о сущности в hwInfo
    CANT_GET_HASH = 22,           /// не удалось вычислить хеш
    CANT_GET_REAL_SECRET = 23,    /// не удалось получить "чистый" секрет
    RUNNING_ON_VM = 24,           /// программа запущена на виртуальной машине
}t_licgen_err_type;

/// места возникновения ошибок
typedef enum{
    NO_LOCATION = 0,                      /// нет ошибки

    GENERATE_SERIAL = 1,                  /// ошибка возникла в функции генерации серийника
    GENERATE_LICENSE = 2,                 /// ошибка возникла в функции генерации лицензии
    VERIFY_LICENSE = 3,                   /// ошибка возникла в функции проверки лицензии
    GENERATE_AND_SAVE_SERIAL = 4,         /// ошибка возникла в функции генерации и записи серийника
    GENERATE_AND_SAVE_LICENSE_TIME_T = 5, /// ошибка возникла в функции генерации и записи лицензии (со временем time_t)
    GENERATE_AND_SAVE_LICENSE_STR = 6,    /// ошибка возникла в функции генерации и записи лицензии (со временем char*)
    READ_AND_VERIFY_LICENSE = 7,          /// ошибка возникла в функции чтения и проверки лицензии

    APPEND_TO_STR = 10,                   /// ошибка возникла в функции добавления к строке
    GET_HWINFO = 11,                      /// ошибка возникла в функции получения информации об оборудовании
    CONCAT_TIME_HWINFO_SECRET = 12,       /// ошибка возникла в функции соединения времени, секрета и инф. об оборуд.
    GET_PURE_SERIAL = 13,                 /// ошибка возникла в функции получения чистого серийника
    GET_PURE_LICENSE = 14                 /// ошибка возникла в функции чистой лицензии
}t_licgen_err_location;

t_licgen_err licgen_err;

void set_licgen_err(int err_type, int err_location){
  licgen_err.err_type = err_type;
  licgen_err.err_location = err_location;
}

int append_to_str(char *dest_str, char *src_str){
  if(strlen(dest_str) + strlen(src_str) + 1 <= STR_MAX_LEN){
    strcat(dest_str, src_str);
    return 1;
  }
  set_licgen_err(OUT_BUFFER_OVERFLOW, APPEND_TO_STR);
  return 0;
}

char *get_hwinfo_string(){
  static char buffer[STR_MAX_LEN];
  char *entity;
  int ram;

  memset(buffer, 0, sizeof(buffer));

#if defined(RAM)
  ram = getRAM();
  if(ram == -1){
    set_licgen_err(CANT_GET_HWINFO_ENTITY, GET_HWINFO);
    return NULL;
  }
  sprintf(buffer,"%d", ram);
#endif

#if defined(CPU_VENDORS)
  entity = getCPUVendors();
  if(!entity){
    set_licgen_err(CANT_GET_HWINFO_ENTITY, GET_HWINFO);
    return NULL;
  }
  if(!append_to_str(buffer, entity))
    return NULL;
#endif

#if defined(BOARD_VENDOR)
  entity = getBoardVendor();
  if(!entity){
    set_licgen_err(CANT_GET_HWINFO_ENTITY, GET_HWINFO);
    return NULL;
  }
  if(!append_to_str(buffer, entity))
    return NULL;
#endif

#if defined(BOARD_NAME)
  entity = getBoardName();
  if(!entity){
    set_licgen_err(CANT_GET_HWINFO_ENTITY, GET_HWINFO);
    return NULL;
  }
  if(!append_to_str(buffer, entity))
    return NULL;
#endif

#if defined(CHASSIS_VENDOR)
  entity = getChassisVendor();
  if(!entity){
    set_licgen_err(CANT_GET_HWINFO_ENTITY, GET_HWINFO);
    return NULL;
  }
  if(!append_to_str(buffer, entity))
    return NULL;
#endif

#if defined(DISK_SERIAL)
  entity = getDiskSerial();
  if(!entity){
    set_licgen_err(CANT_GET_HWINFO_ENTITY, GET_HWINFO);
    return NULL;
  }
  if(!append_to_str(buffer, entity))
    return NULL;
#endif

  return buffer;
}

int concat_time_hwinfo_secret(time_t time, char *hwinfo, unsigned char *secret, int secret_len, char *out, int out_len){
  int current_out_len = 0;
  int hwinfo_len;
  memset(out, 0, out_len);

  memcpy(out, &time, sizeof(time));
  current_out_len += TIME_T_MAX_SIZE;

  hwinfo_len = (int) strlen(hwinfo);
  if(current_out_len + hwinfo_len > out_len){
    set_licgen_err(OUT_BUFFER_OVERFLOW, CONCAT_TIME_HWINFO_SECRET);
    return 0;
  }
  memcpy(&out[current_out_len], hwinfo, hwinfo_len);
  current_out_len += hwinfo_len;

  if(current_out_len + secret_len > out_len){
    set_licgen_err(OUT_BUFFER_OVERFLOW, CONCAT_TIME_HWINFO_SECRET);
    return 0;
  }
  memcpy(&out[current_out_len], secret, secret_len);
  current_out_len += secret_len;

  return current_out_len;
}

int get_pure_serial(unsigned char *secret, int secret_len, time_t time_value, unsigned char *serial, int serial_len){
  char buffer[BUFFER_MAX_LEN];
  unsigned char *hash;
  int buffer_len;
  char *info_str;
  short final_serial_len = PURE_SERIAL_LEN;

  if(serial_len < final_serial_len){
    set_licgen_err(OUT_BUFFER_OVERFLOW, GET_PURE_SERIAL);
    return 0;
  }

  if(!initHwInfo()){
    set_licgen_err(INIT_HWINFO_FAILED, GET_PURE_SERIAL);
    return 0;
  }

  info_str = get_hwinfo_string();

  deinitHwInfo();

  if(!info_str)
    return 0;

  buffer_len = concat_time_hwinfo_secret(time_value, info_str, secret, secret_len, buffer, BUFFER_MAX_LEN);
  if(!buffer_len)
    return 0;

  hash = getHash((unsigned char*) buffer, buffer_len);
  if(!hash){
    set_licgen_err(CANT_GET_HASH, GET_PURE_SERIAL);
    return 0;
  }

  memcpy(serial, &final_serial_len, SHORT_SIZE);
  memcpy(serial + TIME_OFFSET, &time_value, sizeof(time_value));
  memcpy(serial + DATA_OFFSET, hash, HASH_LEN);
  return final_serial_len;
}

int licgen_generate_serial_key(unsigned char *serial, int serial_len) {
  unsigned char parsed_secret[SECRET_LEN], real_secret[SECRET_LEN];
  unsigned char pure_serial[PURE_SERIAL_LEN];
  int pure_serial_len = PURE_SERIAL_LEN, parsed_secret_len;

#ifdef CHECK_VM
  if(licgen_detect_vm()){
      set_licgen_err(RUNNING_ON_VM, GENERATE_SERIAL);
      return 0;
  }
#endif
  if(sizeof(time_t) > TIME_T_MAX_SIZE){
    set_licgen_err(PLATFORM_NOT_SUPPORTED, GENERATE_SERIAL);
    return 0;
  }
  if(!serial){
    set_licgen_err(OUT_PARAMETER_IS_NULL, GENERATE_SERIAL);
    return 0;
  }

  if(!(parsed_secret_len = getBytesFromHexString(APPLICATION_SECRET, parsed_secret, sizeof(parsed_secret)))){
    set_licgen_err(CANT_PARSE_HEX_STRING, GENERATE_SERIAL);
    return 0;
  }
  if(!getRealSecret(parsed_secret, parsed_secret_len, real_secret, SECRET_LEN)){
    set_licgen_err(CANT_GET_REAL_SECRET, GENERATE_SERIAL);
    return 0;
  }

  if(!(pure_serial_len = get_pure_serial(real_secret, SECRET_LEN, time(NULL), pure_serial, pure_serial_len)))
    return 0;
  if(!(serial_len = encryptData(pure_serial, pure_serial_len, real_secret, SECRET_LEN, serial, serial_len))){
    set_licgen_err(CANT_ENCRYPT, GENERATE_SERIAL);
    return 0;
  }

  set_licgen_err(NO_ERROR, NO_LOCATION);
  return serial_len;
}

short get_pure_license(unsigned char *pure_serial, unsigned char *pure_license, short pure_license_len,
                       time_t expire_time){
  short pure_serial_len = *((short *) pure_serial);
  short final_pure_serial_len = (short) (pure_serial_len + DATA_OFFSET);

  if(pure_license_len < final_pure_serial_len){
    set_licgen_err(OUT_BUFFER_OVERFLOW, GET_PURE_LICENSE);
    return 0;
  }
  pure_license_len = final_pure_serial_len;

  memcpy(pure_license, &pure_license_len, SHORT_SIZE);
#if !defined(EXPIRE_TIME)
  expire_time = 0;
#endif
  memcpy(pure_license + TIME_OFFSET, &expire_time, sizeof(expire_time));
  memcpy(pure_license + DATA_OFFSET, pure_serial, pure_serial_len);
  return pure_license_len;
}

int licgen_generate_license_key(unsigned char *serial, int serial_len, unsigned char *license_key,
                                int license_key_len, time_t expire_time) {
  unsigned char parsed_secret[SECRET_LEN], real_secret[SECRET_LEN];
  unsigned char pure_serial[128];
  unsigned char pure_license[128];
  int pure_serial_max_len = sizeof(pure_serial), parsed_secret_len;
  short pure_license_len = sizeof(pure_license);

#ifdef CHECK_VM
    if(licgen_detect_vm()){
        set_licgen_err(RUNNING_ON_VM, GENERATE_LICENSE);
        return 0;
    }
#endif
  if(sizeof(time_t) > TIME_T_MAX_SIZE){
    set_licgen_err(PLATFORM_NOT_SUPPORTED, GENERATE_LICENSE);
    return 0;
  }
  if(!serial){
    set_licgen_err(IN_PARAMETER_IS_NULL, GENERATE_LICENSE);
    return 0;
  }
  if(!license_key){
    set_licgen_err(OUT_PARAMETER_IS_NULL, GENERATE_LICENSE);
    return 0;
  }

  if(!(parsed_secret_len = getBytesFromHexString(APPLICATION_SECRET, parsed_secret, sizeof(parsed_secret)))){
    set_licgen_err(CANT_PARSE_HEX_STRING, GENERATE_LICENSE);
    return 0;
  }
  if(!getRealSecret(parsed_secret, parsed_secret_len, real_secret, SECRET_LEN)){
    set_licgen_err(CANT_GET_REAL_SECRET, GENERATE_LICENSE);
    return 0;
  }

  if(!decryptData(serial, serial_len, real_secret, SECRET_LEN, pure_serial, pure_serial_max_len)){
    set_licgen_err(CANT_DECRYPT, GENERATE_LICENSE);
    return 0;
  }

  if(!(pure_license_len = get_pure_license(pure_serial, pure_license, pure_license_len, expire_time)))
    return 0;

  if(!(license_key_len = encryptData(pure_license, pure_license_len, real_secret, SECRET_LEN,
                                     license_key, license_key_len))){
    set_licgen_err(CANT_ENCRYPT, GENERATE_LICENSE);
    return 0;
  }
  set_licgen_err(NO_ERROR, NO_LOCATION);
  return license_key_len;
}

t_licgen_verify_res licgen_verify_license_key(unsigned char *license, int license_len) {
  unsigned char parsed_secret[SECRET_LEN], real_secret[SECRET_LEN];
  unsigned char pure_serial[PURE_SERIAL_LEN];
  unsigned char pure_license[128];
  short pure_license_len = sizeof(pure_license), pure_serial_len = sizeof(pure_serial), decr_pure_serial_len;
  time_t creation_time, expire_time;
  int parsed_secret_len;

#ifdef CHECK_VM
    if(licgen_detect_vm()){
        set_licgen_err(RUNNING_ON_VM, VERIFY_LICENSE);
        return LICGEN_INTERNAL_ERROR;
    }
#endif
  if(!license){
    set_licgen_err(IN_PARAMETER_IS_NULL, VERIFY_LICENSE);
    return LICGEN_INTERNAL_ERROR;
  }

  if(!(parsed_secret_len = getBytesFromHexString(APPLICATION_SECRET, parsed_secret, sizeof(parsed_secret)))){
    set_licgen_err(CANT_PARSE_HEX_STRING, VERIFY_LICENSE);
    return LICGEN_INTERNAL_ERROR;
  }
  if(!getRealSecret(parsed_secret, parsed_secret_len, real_secret, SECRET_LEN)){
    set_licgen_err(CANT_GET_REAL_SECRET, VERIFY_LICENSE);
    return LICGEN_INTERNAL_ERROR;
  }

  if(!decryptData(license, license_len, real_secret, SECRET_LEN, pure_license, pure_license_len)){
    set_licgen_err(CANT_DECRYPT, VERIFY_LICENSE);
    return LICGEN_INTERNAL_ERROR;
  }

  expire_time = * ((time_t *) (pure_license + TIME_OFFSET));
  creation_time = * ((time_t *) (pure_license + DATA_OFFSET + TIME_OFFSET));

  if(!(pure_serial_len = (short) get_pure_serial(real_secret, SECRET_LEN, creation_time, pure_serial, pure_serial_len)))
    return LICGEN_INTERNAL_ERROR;

  set_licgen_err(NO_ERROR, NO_LOCATION);

  decr_pure_serial_len = * ((short *) (pure_license + DATA_OFFSET));
  if(decr_pure_serial_len != pure_serial_len)
    return LICGEN_WRONG_LICENSE;

  if(memcmp(pure_serial, pure_license + DATA_OFFSET, pure_serial_len) != 0)
    return LICGEN_WRONG_LICENSE;

  if(!difftime(expire_time, 0))
    return LICGEN_LICENSE_OK;

  if(difftime(time(NULL), expire_time) >= 0)
    return LICGEN_LICENSE_EXPIRED;

  return LICGEN_LICENSE_OK;
}

int licgen_generate_and_save_serial_key(char *serial_file_path) {
  unsigned char serial[128];
  int serial_len;
  char serial_hex_str[256];

  if(!(serial_len = licgen_generate_serial_key(serial, sizeof(serial))))
    return 0;

  memset(serial_hex_str, 0, sizeof(serial_hex_str));
  if(!getHexStringFromBytes(serial, serial_len, serial_hex_str, sizeof(serial_hex_str))){
    set_licgen_err(CANT_GET_HEX_STRING, GENERATE_AND_SAVE_SERIAL);
    return 0;
  }

  if(!writeStringToFile(serial_hex_str, serial_file_path)){
    set_licgen_err(CANT_WRITE_TO_FILE, GENERATE_AND_SAVE_SERIAL);
    return 0;
  }

  set_licgen_err(NO_ERROR, NO_LOCATION);
  return 1;
}

int licgen_generate_and_save_license_key_with_time_t(char *serial_file_path, time_t expire_time,
                                                     char *license_file_path){
  char serial_hex_str[256], license_hex_str[256];
  unsigned char serial[128], license[128];
  int serial_len, license_len;

  memset(serial_hex_str, 0 , sizeof(serial_hex_str));
  if(!readStringFromFile(serial_file_path, serial_hex_str, sizeof(serial_hex_str))){
    set_licgen_err(CANT_READ_FROM_FILE, GENERATE_AND_SAVE_LICENSE_TIME_T);
    return 0;
  }

  if(!(serial_len = getBytesFromHexString(serial_hex_str, serial, sizeof(serial)))){
    set_licgen_err(CANT_PARSE_HEX_STRING, GENERATE_AND_SAVE_LICENSE_TIME_T);
    return 0;
  }

  if(!(license_len = licgen_generate_license_key(serial, serial_len, license, sizeof(license), expire_time)))
    return 0;

  memset(license_hex_str, 0 , sizeof(license_hex_str));
  if(!getHexStringFromBytes(license, license_len, license_hex_str, sizeof(license_hex_str))){
    set_licgen_err(CANT_GET_HEX_STRING, GENERATE_AND_SAVE_LICENSE_TIME_T);
    return 0;
  }

  if(!writeStringToFile(license_hex_str, license_file_path)){
    set_licgen_err(CANT_WRITE_TO_FILE, GENERATE_AND_SAVE_LICENSE_TIME_T);
    return 0;
  }

  set_licgen_err(NO_ERROR, NO_LOCATION);
  return 1;
}

int licgen_generate_and_save_license_key_with_date_str(char *serial_file_path, char *expire_date,
                                                       char *license_file_path){
  time_t expire_time;
  if(!getTimeFromStr(expire_date, &expire_time)){
    set_licgen_err(CANT_PARSE_TIME, GENERATE_AND_SAVE_LICENSE_STR);
    return 0;
  }

  return licgen_generate_and_save_license_key_with_time_t(serial_file_path, expire_time, license_file_path);
}

t_licgen_verify_res licgen_read_and_verify_license_key(char *license_file_path){
  char license_hex_str[256];
  int license_len;
  unsigned char license[128];

  memset(license_hex_str, 0 , sizeof(license_hex_str));
  if(!readStringFromFile(license_file_path, license_hex_str, sizeof(license_hex_str))){
    set_licgen_err(CANT_READ_FROM_FILE, READ_AND_VERIFY_LICENSE);
    return LICGEN_INTERNAL_ERROR;
  }

  if(!(license_len = getBytesFromHexString(license_hex_str, license, sizeof(license)))){
    set_licgen_err(CANT_PARSE_HEX_STRING, READ_AND_VERIFY_LICENSE);
    return LICGEN_INTERNAL_ERROR;
  }

  return licgen_verify_license_key(license, license_len);
}

int licgen_detect_vm(){
    return detectVM();
}

t_licgen_err licgen_get_last_error(){
  return licgen_err;
}
