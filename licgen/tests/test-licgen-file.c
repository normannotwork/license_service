#include "licgen/licgen.h"
#include <stdio.h>

int main(){
  char *expire_date = "30.09.2025";
  char *serial_file_path = "serial.txt";
  char *license_file_path = "license.txt";
  t_licgen_verify_res verify_res;
  t_licgen_err err_info;

  if(!licgen_generate_and_save_serial_key(serial_file_path)){
    err_info = licgen_get_last_error();
    printf("Error: could not generate and save serial key, error info code: %d:%d\n",
           err_info.err_type, err_info.err_location);
    return 1;
  }

  if(!licgen_generate_and_save_license_key_with_date_str(serial_file_path, expire_date, license_file_path)){
    err_info = licgen_get_last_error();
    printf("Error: could not generate and save license key, error info code: %d:%d\n",
           err_info.err_type, err_info.err_location);
    return 1;
  }

  verify_res = licgen_read_and_verify_license_key(license_file_path);
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
