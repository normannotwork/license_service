#include "licgen/licgen.h"
#include "time-utils.h"
#include <stdio.h>

int main(){
  char *expire_date = "30.09.2025";
  time_t expire_time;
  unsigned char serial[128], license[128];
  int serial_len, license_len;
  t_licgen_verify_res verify_res;
  t_licgen_err err_info;

  if(!getTimeFromStr(expire_date, &expire_time)){
    printf("Error: could not parse date %s\n", expire_date);
    return 1;
  }

  if (!(serial_len = licgen_generate_serial_key(serial, sizeof(serial)))) {
    err_info = licgen_get_last_error();
    printf("Error: could not generate serial, error info code: %d:%d\n", err_info.err_type, err_info.err_location);
    return 1;
  }

  if (!(license_len = licgen_generate_license_key(serial, serial_len, license, sizeof(license), expire_time))) {
    err_info = licgen_get_last_error();
    printf("Error: could not generate license, error info code: %d:%d\n", err_info.err_type, err_info.err_location);
    return 1;
  }

  verify_res = licgen_verify_license_key(license, license_len);
  switch (verify_res) {
    case LICGEN_LICENSE_OK:
      printf("Success\n");
      return 0;
    case LICGEN_LICENSE_EXPIRED:
      printf("Error: expired license\n");
      return 1;
    case LICGEN_WRONG_LICENSE:
      printf("Error: wrong license\n");
      return 1;
    case LICGEN_INTERNAL_ERROR:
      err_info = licgen_get_last_error();
      printf("Error: internal error. Info code: %d:%d\n", err_info.err_type, err_info.err_location);
      return 1;
    default:
      printf("Error: got undocumented result %d\n", verify_res);
      return 1;
  }
}
