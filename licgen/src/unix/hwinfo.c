#include "hwinfo.h"
#include "dmi.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <libudev.h>
#include <math.h>

int initHwInfo(){
  return 1;
}

int getRAM(){
  char line[256];
  int gb_in_kb = 1024 * 1024;
  int ram_kb;
  FILE *mem_info = fopen("/proc/meminfo", "r");

  if(!mem_info)
    return -1;

  while (fgets(line, sizeof(line), mem_info)){
    if(sscanf(line, "MemTotal: %d kB", &ram_kb) == 1){
      fclose(mem_info);
      return ceil((double) ram_kb / (double) gb_in_kb);
    }
  }

  fclose(mem_info);
  return -1;
}

char *getCPUVendors(){
  static char vendors[2048];
  char vendor[64];
  char line[256];
  FILE *cpu_info = fopen("/proc/cpuinfo", "r");

  if(!cpu_info)
    return NULL;

  memset(vendors, 0, sizeof(vendors));
  while (fgets(line, sizeof(line), cpu_info)){
    if(sscanf(line, "vendor_id : %s", vendor) == 1){
      strcat(vendors,vendor);
    }
  }

  fclose(cpu_info);
  return vendors;
}

char *getBoardVendor(){
  static char vendor[32];
  if(getDMIString("board_vendor", vendor, sizeof(vendor))){
    return vendor;
  }
  return NULL;
}

char *getBoardName(){
  static char name[32];
  if(getDMIString("board_name", name, sizeof(name))){
    return name;
  }
  return NULL;
}

char *getChassisVendor(){
  static char vendor[32];
  if(getDMIString("chassis_vendor", vendor, sizeof(vendor))){
    return vendor;
  }
  return NULL;
}

char *getDiskSerial(){
    static char serial[64];
    char *serial_ptr;
    char *fs_root = "/";
    struct stat s;
    struct udev *context;
    struct udev_device *device;

    if(lstat(fs_root, &s))
        return NULL;
    if(!(context = udev_new()))
        return NULL;
    if(!(device = udev_device_new_from_devnum(context, 'b', s.st_dev))){
        udev_unref(context);
        return NULL;
    }
    if((serial_ptr = (char *) udev_device_get_property_value(device, "ID_SERIAL"))){
        strcpy(serial, serial_ptr);
        udev_device_unref(device);
        udev_unref(context);
        return serial;
    }
    udev_device_unref(device);
    udev_unref(context);
    return NULL;
}

void deinitHwInfo(){}
