#include "hwinfo.h"
#include <stdio.h>

void printRAM(){
  int ram = getRAM();
  if(ram != -1)
    printf("RAM = %d\n", ram);
  else
    printf("Could not get RAM\n");
}

void printCPUVendors(){
  char *info = getCPUVendors();
  if(info)
    printf("CPU vendor = %s\n", info);
  else
    printf("Could not get CPU vendors\n");
}

void printBoardVendor(){
  char *info = getBoardVendor();
  if(info)
    printf("MB vendor = %s\n", info);
  else
    printf("Could not get MB vendor\n");
}

void printBoardName(){
  char *info = getBoardName();
  if(info)
    printf("MB name = %s\n", info);
  else
    printf("Could not get MB name\n");
}

void printChassisVendor(){
  char *info = getChassisVendor();
  if(info)
    printf("Chassis vendor = %s\n", info);
  else
    printf("Could not get chassis vendor\n");
}

void printDiskSerial(){
    char *serial = getDiskSerial();
    if(serial)
        printf("Disk serial = %s\n", serial);
    else
        printf("Could not get disk serial\n");
}

int main() {
  if(initHwInfo()){
    printRAM();
    printCPUVendors();
    printBoardVendor();
    printBoardName();
    printChassisVendor();
    printDiskSerial();
    deinitHwInfo();
  }
  else{
    printf("initHwInfo failed\n");
    return 1;
  }
  return 0;
}
