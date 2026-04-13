#include "licgen/licgen.h"
#include <stdio.h>
#include <string.h>

void print_help(){
  printf("Usage:\n");
  printf("licgen-generator SERIAL_PATH LICENSE_PATH EXPIRE_DATE\n");
  printf("licgen-generator --help\n");

  printf("\nArguments:\n");
  printf("SERIAL_PATH    path to the file with serial\n");
  printf("LICENSE_PATH   path to the file to save license to\n");
  printf("EXPIRE_DATE    expire date of license in the format DD.MM.YYYY "
         "(pass \"never\" if you need perpetual license)\n");

  printf("\nCommands\n");
  printf("help           display help and exit\n");
}

int main(int argc, char** argv){
  t_licgen_err err_info;
  char *serial_path, *license_path, *expire_date;
  int res;

  if(argc == 2){
    if(!strcmp(argv[1], "--help")){
      print_help();
      return 0;
    }
    else{
      fprintf(stderr, "Error: wrong command\n");
      print_help();
      return 1;
    }
  }

  if(argc != 4){
    fprintf(stderr, "Error: wrong number of arguments\n");
    print_help();
    return 1;
  }

  serial_path = argv[1];
  license_path = argv[2];
  expire_date = argv[3];

  if(!strcmp(expire_date, "never"))
    res = licgen_generate_and_save_license_key_with_time_t(serial_path, 0, license_path);
  else
    res = licgen_generate_and_save_license_key_with_date_str(serial_path, expire_date, license_path);

  if(!res){
    err_info = licgen_get_last_error();
    printf("Error: could not generate and save license key, error info code: %d:%d\n",
           err_info.err_type, err_info.err_location);
    return 1;
  }

  printf("New license was generated and written to %s\n", license_path);
  return 0;
}
