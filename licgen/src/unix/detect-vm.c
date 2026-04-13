#include "detect-vm.h"
#include "dmi.h"
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <libudev.h>
#include <dirent.h>
#include <regex.h>

/**
 * @internal
 * Перевести строку в нижний регистр
 * @param str - входная строка
 * @note Входная строка изменяется
 */
void toLowerCase(char *str){
    int len = (int) strlen(str);
    for(int i = 0; i < len; i++)
        str[i] = (char) tolower(str[i]);
}

/**
 * @internal
 * Проверить строки DMI на наличие в них подстрок, характерных для виртуальных машин
 * @param entities - строки DMI
 * @param entitiesCount - число строк DMI
 * @param substrings - подстроки, характерные для виртуальных машин
 * @param substringsCount - число подстрок, характерных для виртуальных машин
 * @return 1 - найден признак вм, 0 - в противном случае
 */
int testDMIStrings(char *entities[], int entitiesCount, char *substrings[], int substringsCount){
    char entityStr[128];
    int isVm = 0;

    for(int i = 0; i < entitiesCount; i++){
        if(getDMIString(entities[i], entityStr, sizeof(entityStr))){
            toLowerCase(entityStr);
            for(int k = 0; k < substringsCount; k++){
                if(strstr(entityStr, substrings[k])){
                    isVm = 1;
                    break;
                }
            }
        }
        if(isVm)
            break;
    }

    return isVm;
}

/// Ищем строки, характерные для вм, в поставщиках оборудования
int testVendors(){
    char *vendorEntities[] = { "bios_vendor", "sys_vendor", "board_vendor", "chassis_vendor" };
    int vendorEntitiesCount = sizeof(vendorEntities) / sizeof(vendorEntities[0]);
    char *vmSubstrings[] = { "kvm", "qemu", "oracle", "innotek gmbh", "vmware", "vmw" };
    int vmSubstringsCount = sizeof(vmSubstrings) / sizeof(vmSubstrings[0]);

    return testDMIStrings(vendorEntities, vendorEntitiesCount, vmSubstrings, vmSubstringsCount);
}

/// Ищем строки, характерные для вм, в названиях моделей оборудования
int testProductNames(){
    char *productEntities[] = { "product_name", "board_name" };
    int productEntitiesCount = sizeof(productEntities) / sizeof(productEntities[0]);
    char *vmSubstrings[] = { "virtualbox", "standard pc", "vmware" };
    int vmSubstringsCount = sizeof(vmSubstrings) / sizeof(vmSubstrings[0]);

    return testDMIStrings(productEntities, productEntitiesCount, vmSubstrings, vmSubstringsCount);
}

#if defined(__i386__) || defined(__x86_64__)

/**
 * @internal
 * Поиск признаков вм в строке, полученной после вызова cpuid
 * @return 1 - найден признак вм, 0 - в противном случае
 */
static int knownSignature (const char *sig){
   return
     strcmp (sig, "bhyve bhyve ") == 0 ||
     memcmp (sig, "KVMKVMKVM\0\0\0", 12) == 0 ||
     strcmp (sig, "LKVMLKVMLKVM") == 0 ||
     strcmp (sig, "Microsoft Hv") == 0 ||
     strcmp (sig, "OpenBSDVMM58") == 0 ||
     strcmp (sig, "TCGTCGTCGTCG") == 0 ||
     strcmp (sig, "VMwareVMware") == 0 ||
     strcmp (sig, "XenVMMXenVMM") == 0 ||
     0;
 }

/**
 * @internal
 * Вызов ассемблерной инструкции cpuid с сохранением результата вызова в регистры
 * @param eax - регистр eax
 * @param ebx - регистр ebx
 * @param ecx - регистр ecx
 * @param edx - регистр edx
 */
static inline void cpuid (uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx){
   asm volatile ("cpuid"
                 : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
                 : "0" (*eax), "2" (*ecx)
                 : "memory");
 }

/**
 * @internal
 * Обертка для вызова cpuid с агрументом в регистре eax
 * @param eax - регистр eax с входным аргументом
 * @param sig - буфер для записи результата cpuid
 * @return содержимое регистра eax после вызова cpuid
 */
static uint32_t cpuidLeaf (uint32_t eax, char *sig) {
   uint32_t *sig32 = (uint32_t *) sig;

   cpuid (&eax, &sig32[0], &sig32[1], &sig32[2]);
   sig[12] = 0;
   return eax;
 }

 /**
  * @internal
  * Цикл проверки возврата команды cpuid при разных входных аргументах
  * @return 1 - найден признак вм, 0 - в противном случае
  */
static int cpuSig () {
   char sig[13];
   const uint32_t base = 0x40000000;
   uint32_t leaf;
   int isVm = 0;

   for (leaf = base + 0xff00; leaf >= base; leaf -= 0x100) {
     memset (sig, 0, sizeof sig);
     cpuidLeaf(leaf, sig);
     if (knownSignature(sig)) {
       isVm = 1;
       break;
     }
   }
    return isVm;
 }

#else /* !i386, !x86_64 */
static int cpuSig ()
   return 0;
}
#endif

/// Поиск признаков вм в строках, возвращаемых cpuid
int testCPUID(){
    return cpuSig();
}

/// Поиск признаков вм в моделях дисков (или в их путях)
int testDiskModel(){
    char *vmSubstrings[] = { "vbox", "virtual", "vmware", "vmw", "qemu", "virtio" };
    int vmSubstringsCount = sizeof(vmSubstrings) / sizeof(vmSubstrings[0]);
    struct udev_enumerate *enumerate;
    struct udev *context;
    struct udev_list_entry *deviceList, *deviceEntry;
    struct udev_device *device;
    char *devicePath, *deviceModel;
    int isVm = 0;

    if(!(context = udev_new()))
        return 0;
    if(!(enumerate = udev_enumerate_new(context))){
        udev_unref(context);
        return 0;
    }
    if(udev_enumerate_add_match_subsystem(enumerate, "block")){
        udev_enumerate_unref(enumerate);
        udev_unref(context);
        return 0;
    }
    if(udev_enumerate_scan_devices(enumerate)){
        udev_enumerate_unref(enumerate);
        udev_unref(context);
        return 0;
    }
    if(!(deviceList = udev_enumerate_get_list_entry(enumerate))){
        udev_enumerate_unref(enumerate);
        udev_unref(context);
        return 0;
    }

    udev_list_entry_foreach(deviceEntry, deviceList){
        if(!(devicePath = (char *) udev_list_entry_get_name(deviceEntry)))
            continue;
        if(!(device = udev_device_new_from_syspath(context, devicePath)))
            continue;
        if((deviceModel = (char *) udev_device_get_property_value(device, "ID_MODEL"))){
            toLowerCase(deviceModel);
            for(int i = 0; i < vmSubstringsCount; i++){
                if(strstr(deviceModel, vmSubstrings[i])){
                    isVm = 1;
                    break;
                }
            }
        }
        else{
            if(strstr(devicePath, "virtio"))
                isVm = 1;
        }
        udev_device_unref(device);

        if(isVm)
            break;
    }

    udev_enumerate_unref(enumerate);
    udev_unref(context);
    return isVm;
}

/**
 * @internal
 * Проверка, является ли файл директорией или символической ссылкой
 * @param d - структура, описывающая файл
 * @return 1 - указанный файл является директорией или символической ссылкой, 0 - в противном случае
 * @note Сущности "." и ".." не являются директориями
 */
int isDirOrSymLink(struct dirent *d){
    switch (d->d_type) {
        case DT_LNK:
            return 1;
        case DT_DIR:
            return (strcmp(d->d_name, ".") != 0 && strcmp(d->d_name, "..") != 0);
        default:
            return 0;
    }
}

/**
 * @internal
 * Проверка наличия файлов, описывающих реальное оборудование, в сущности hwmon
 * @param hwmonPath - путь к сущности hwmon
 * @return 1 - сущность hwmon относится к реальному оборудованию, 0 - в противном случае
 * @details Выполняется проверка наличия файла с именем вида "temp[число]_input" или "fan[число]_input"
 */
int detectRealHwmon(char *hwmonPath){
    regex_t regexTemp, regexFan;
    DIR *hwmonDir;
    struct dirent *hwmonFile;
    int detected = 0;

    if(regcomp(&regexTemp, "temp[[:digit:]]\\{1,\\}_input", 0))
        return 0;
    if(regcomp(&regexFan, "fan[[:digit:]]\\{1,\\}_input" , 0))
        return 0;

    if(!(hwmonDir = opendir(hwmonPath)))
        return 0;
    while((hwmonFile = readdir(hwmonDir))){
        if(hwmonFile->d_type == DT_REG){
            if(!regexec(&regexTemp, hwmonFile->d_name, 0, NULL, 0) ||
               !regexec(&regexFan, hwmonFile->d_name, 0, NULL, 0)){
                detected = 1;
                break;
            }
        }
    }

    closedir(hwmonDir);
    regfree(&regexTemp);
    regfree(&regexFan);
    return detected;
}

/// Проверка интерфейса hwmon, связанного с датчиками температуры и вентиляторами
/// Проверяется наличие файлов, описывающих реальное оборудование
int testHwmon(){
    char *hwmonPath = "/sys/class/hwmon";
    char hwmonEntityPath[512];
    DIR *hwmonRoot;
    struct dirent *hwmon;
    int hwmonCount = 0;
    int detectedReal = 0;
    int isVm = 0;

    if(!(hwmonRoot = opendir(hwmonPath)))
        return 0;
    while((hwmon = readdir(hwmonRoot))){
        if(isDirOrSymLink(hwmon)){
            hwmonCount++;
            sprintf(hwmonEntityPath, "%s/%s", hwmonPath, hwmon->d_name);
            if((detectedReal = detectRealHwmon(hwmonEntityPath)))
                break;
        }
    }
    closedir(hwmonRoot);
    if(!hwmonCount || !detectedReal)
        isVm = 1;

    return isVm;
}

int detectVM(){
    return testVendors() ||
           testProductNames() ||
           testCPUID() ||
           testDiskModel() ||
           testHwmon();
}
