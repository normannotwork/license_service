#include "dmi.h"
#include <stdio.h>
#include <string.h>

int getDMIString(char *file_name, char *buffer, int buffer_len){
    FILE *info_file;
    char info_path[64];
    int last_symbol;

    sprintf(info_path, "/sys/class/dmi/id/%s", file_name);
    info_file = fopen(info_path, "r");

    if(!info_file)
        return 0;

    if(fgets(buffer, buffer_len, info_file)){
        last_symbol = (int) strlen(buffer) - 1;
        if(buffer[last_symbol] == '\n')
            buffer[last_symbol] = '\0';
        fclose(info_file);
        return 1;
    }

    fclose(info_file);
    return 0;
}
