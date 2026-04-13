#define _CRT_SECURE_NO_WARNINGS
#include "detect-vm.h"
#include "wmi.h"
#include <stdio.h>
#include <tchar.h>
#include <SetupAPI.h>
#include <devguid.h>

#pragma comment(lib, "setupapi.lib")

/// Попытка чтения текущего значения температуры (из класса WMI Win32_TemperatureProbe)
/// Если вернулся пустой ответ, то это вм
int testTemperatureProbe(){
    HRESULT hres;
    IEnumWbemClassObject *pEnumerator = NULL;
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    int isVm = 0;

    if(!connectVMI((BSTR) L"ROOT\\CIMV2")){
        return 0;
    }
    if(!execVMIQuery("CurrentReading", "Win32_TemperatureProbe", &pEnumerator)){
        disconnectVMI();
        return 0;
    }

    hres = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if(!FAILED(hres) && uReturn == 0)
        isVm = 1;

    if(pclsObj)
        pclsObj->lpVtbl->Release(pclsObj);
    pEnumerator->lpVtbl->Release(pEnumerator);
    disconnectVMI();

    return isVm;
}

/// Попытка чтения текущего значения температуры (из класса WMI MSAcpi_ThermalZoneTemperature)
/// Если мы получили ошибку "данный класс не существует", то это вм
int testThermalZoneTemperature(){
    HRESULT hres;
    IEnumWbemClassObject *pEnumerator = NULL;
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    int isVm = 0;

    if(!connectVMI((BSTR) L"ROOT\\WMI")){
        return 0;
    }
    if(!execVMIQuery("CurrentTemperature", "MSAcpi_ThermalZoneTemperature", &pEnumerator)){
        disconnectVMI();
        return 0;
    }

    hres = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if(FAILED(hres) && hres == 0x8004100C)
        isVm = 1;

    if(pclsObj)
        pclsObj->lpVtbl->Release(pclsObj);
    pEnumerator->lpVtbl->Release(pEnumerator);
    disconnectVMI();
    return isVm;
}

/// Попытка запроса информации о вентиляторе
/// Если вернулся пустой ответ, то это вм
int testFan(){
    HRESULT hres;
    IEnumWbemClassObject *pEnumerator = NULL;
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    int isVm = 0;

    if(!connectVMI((BSTR) L"ROOT\\CIMV2")){
        return 0;
    }
    if(!execVMIQuery("*", "Win32_Fan", &pEnumerator)){
        disconnectVMI();
        return 0;
    }
    hres = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if(!FAILED(hres) && uReturn == 0)
        isVm = 1;

    if(pclsObj)
        pclsObj->lpVtbl->Release(pclsObj);
    pEnumerator->lpVtbl->Release(pEnumerator);
    disconnectVMI();
    return isVm;
}

/// Поиск признаков вм в серийном номере bios
int testBiosSerialNumber(){
    HRESULT hres;
    VARIANT vtProp;
    IEnumWbemClassObject *pEnumerator = NULL;
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    int isVm = 0;

    if(!connectVMI((BSTR) L"ROOT\\CIMV2")){
        return 0;
    }
    if(!execVMIQuery("SerialNumber", "Win32_Bios", &pEnumerator)){
        disconnectVMI();
        return 0;
    }

    while(pEnumerator){
        hres = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if(FAILED(hres) || uReturn == 0)
            break;
        else{
            hres = pclsObj->lpVtbl->Get(pclsObj, (BSTR) L"SerialNumber", 0, &vtProp, 0, 0);
            if(!FAILED(hres)){
                if(V_VT(&vtProp) == VT_NULL)
                    isVm = 1;
                else{
                    if(_wcslwr(vtProp.bstrVal))
                        if(!wcscmp(vtProp.bstrVal, L"0") || wcsstr(vtProp.bstrVal, L"vmware"))
                            isVm = 1;
                }
                VariantClear(&vtProp);
            }
            pclsObj->lpVtbl->Release(pclsObj);
        }
    }

    pEnumerator->lpVtbl->Release(pEnumerator);
    disconnectVMI();
    return isVm;
}

/// Поиск признаков вм в строках модели и производителя системного блока
int testComputerModelManufacturer(){
    HRESULT hres;
    VARIANT vtProp;
    IEnumWbemClassObject *pEnumerator = NULL;
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    int isVm = 0, tryModel = 0, tryManufacturer = 0;

    if(!connectVMI((BSTR) L"ROOT\\CIMV2")){
        return 0;
    }
    if(!execVMIQuery("Model,Manufacturer", "Win32_ComputerSystem", &pEnumerator)){
        disconnectVMI();
        return 0;
    }

    while(pEnumerator){
        hres = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if(FAILED(hres) || uReturn == 0)
            break;
        else{
            hres = pclsObj->lpVtbl->Get(pclsObj, (BSTR) L"Model", 0, &vtProp, 0, 0);
            if(!FAILED(hres)){
                if(V_VT(&vtProp) != VT_NULL){
                    if(_wcslwr(vtProp.bstrVal))
                        if(wcsstr(vtProp.bstrVal, L"virtualbox") || wcsstr(vtProp.bstrVal, L"vmware"))
                            tryModel = 1;
                }
                VariantClear(&vtProp);
            }

            hres = pclsObj->lpVtbl->Get(pclsObj, (BSTR) L"Manufacturer", 0, &vtProp, 0, 0);
            if(!FAILED(hres)){
                if(V_VT(&vtProp) != VT_NULL){
                    if(_wcslwr(vtProp.bstrVal))
                        if(wcsstr(vtProp.bstrVal, L"vmware") || wcsstr(vtProp.bstrVal, L"qemu"))
                            tryManufacturer = 1;
                }
                VariantClear(&vtProp);
            }

            if(tryModel || tryManufacturer)
                isVm = 1;

            pclsObj->lpVtbl->Release(pclsObj);
        }
    }

    pEnumerator->lpVtbl->Release(pEnumerator);
    disconnectVMI();
    return isVm;
}

/// Поиск признаков вм в устройствах ide и scsi в регистре Windows
int testRegistryDiskEnum(){
    HKEY regKey = NULL;
    DWORD subkeyCount = 0;
    DWORD maxSubkeyLen = 0;
    DWORD subkeyLen, subkeyLenCopy;
    char *subkey;
    LPCSTR  regEntries[] = {
            (LPCSTR) "System\\CurrentControlSet\\Enum\\IDE",
            (LPCSTR) "System\\CurrentControlSet\\Enum\\SCSI"
    };
    TCHAR *vmSubstrings[] = { _T("vbox"), _T("vmware"), _T("qemu"),
                              _T("virtio"), _T("vmw"), _T("virtual")
    };
    int regEntriesCount = sizeof(regEntries) / sizeof(regEntries[0]);
    int vmSubstringsCount = sizeof(vmSubstrings) / sizeof(vmSubstrings[0]);
    int isVm = 0;

    for(int i = 0; i < regEntriesCount; i++){
        if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, regEntries[i], 0, KEY_READ, &regKey) != ERROR_SUCCESS)
            continue;
        if(RegQueryInfoKey(regKey, NULL, NULL, NULL,
                           &subkeyCount, &maxSubkeyLen, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS){
            RegCloseKey(regKey);
            continue;
        }
        subkeyLen = (maxSubkeyLen + 1) * sizeof(TCHAR);
        subkey = (TCHAR *) malloc (subkeyLen);
        if(!subkey){
            RegCloseKey(regKey);
            continue;
        }

        for(DWORD k = 0; k < subkeyCount; k++){
            subkeyLenCopy = subkeyLen;
            if(RegEnumKeyEx(regKey, k, subkey, &subkeyLenCopy, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                continue;
            if(!_tcslwr(subkey))
                continue;
            for(int s = 0; s < vmSubstringsCount; s++){
                if(_tcsstr(subkey, vmSubstrings[s])){
                    isVm = 1;
                    break;
                }
            }
            if(isVm)
                break;
        }
        free(subkey);
        RegCloseKey(regKey);

        if(isVm)
            break;
    }

    return isVm;
}

/// Поиск признаков вм в кодах дисков из setupapi
int testHwDeviceInfo(){
    HDEVINFO hdevinfo;
    SP_DEVINFO_DATA DeviceInfoData;
    DWORD dwPropertyRegDataType;
    LPTSTR buffer = NULL;
    DWORD dwSize = 0;
    int isVm = 0;

    hdevinfo = SetupDiGetClassDevs((LPGUID) &GUID_DEVCLASS_DISKDRIVE, 0, 0, DIGCF_PRESENT);
    if(hdevinfo == INVALID_HANDLE_VALUE)
        return 0;

    DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for(DWORD i = 0; SetupDiEnumDeviceInfo(hdevinfo, i, &DeviceInfoData); i++){
        while(!SetupDiGetDeviceRegistryProperty(hdevinfo, &DeviceInfoData, SPDRP_HARDWAREID, &dwPropertyRegDataType,
                                                (PBYTE) buffer, dwSize, &dwSize)){
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                if (buffer) LocalFree(buffer);
                buffer = (LPTSTR) LocalAlloc(LPTR, dwSize * 2);
                if (buffer == NULL)
                    break;
            }
            else
                break;
        }

        if (buffer) {
            if(!_tcslwr(buffer))
                continue;
            if (_tcsstr(buffer, _T("vbox")) || _tcsstr(buffer, _T("vmware")) ||
                _tcsstr(buffer, _T("qemu")) || _tcsstr(buffer, _T("virtual"))){
                isVm = 1;
                break;
            }
        }
    }

    if(buffer)
        LocalFree(buffer);
    SetupDiDestroyDeviceInfoList(hdevinfo);

    if (GetLastError() != NO_ERROR && GetLastError() != ERROR_NO_MORE_ITEMS)
        return 0;

    return isVm;
}

/**
 * @internal
 * Получить системную таблицу
 * @param signature - сигнатура таблицы
 * @param tableID - id таблицы
 * @param pTableSize - указатель, куда будет записан размер считанной таблицы
 * @return Указатель на считанную системную таблицу, NULL - в противном случае
 * @note После использования необходимо очистить память, выделенную для таблицы, с помощью freeSystemFirmWareTable()
 */
PVOID getSystemFirmWareTable(DWORD signature, DWORD tableID, DWORD *pTableSize){
    PVOID fwTable = NULL;
    DWORD fwTableSize = GetSystemFirmwareTable(signature, tableID, NULL, 0);
    fwTable = (PVOID) malloc(fwTableSize);
    if(!fwTable)
        return NULL;
    fwTableSize = GetSystemFirmwareTable(signature, tableID, fwTable, fwTableSize);
    if(!fwTableSize){
        *pTableSize = 0;
        free(fwTable);
        return NULL;
    }
    *pTableSize = fwTableSize;
    return fwTable;
}

/**
 * @internal
 * Освободить память, выделенную для системной таблицы
 * @param fwTable - указатель на системную таблицу
 */
void freeSystemFirmWareTable(PVOID fwTable){
    free(fwTable);
}

/**
 * @internal
 * Получить перечень id системных таблиц
 * @param signature - сигнатура таблиц
 * @param pEnumSize - указатель, куда будет записан размер считанного перечня
 * @return Указатель на считанный перечень, NULL - в противном случае
 * @note После использования необходимо очистить память, выделенную для перечня, с помощью freeEnumSystemFirmWareTable()
 */
PVOID getEnumSystemFirmWareTable(DWORD signature, DWORD *pEnumSize){
    PVOID fwEnum = NULL;
    DWORD fwEnumSize = (DWORD) EnumSystemFirmwareTables(signature, NULL, 0);
    fwEnum = (PVOID) malloc(fwEnumSize);
    if(!fwEnum)
        return NULL;
    fwEnumSize = (DWORD) EnumSystemFirmwareTables(signature, fwEnum, fwEnumSize);
    if(!fwEnumSize){
        *pEnumSize = 0;
        free(fwEnum);
        return NULL;
    }
    *pEnumSize = fwEnumSize;
    return fwEnum;
}

/**
 * @internal
 * Освободить память, выделенную для перечня системных таблиц
 * @param fwEnum - указатель на перечень id системных таблиц
 */
void freeEnumSystemFirmWareTable(PVOID fwEnum){
    free(fwEnum);
}

/**
 * @internal
 * Поиск последовательность байтов в массиве байтов
 * @param needle - последовательность байтов
 * @param needleLen - размер последовательности байтов
 * @param haystack - массив байтов
 * @param haystackLen - длина массива байтов
 * @return
 */
int findStrInData(PBYTE needle, size_t needleLen, PBYTE haystack, size_t haystackLen)
{
    for (size_t i = 0; i < haystackLen - needleLen; i++)
    {
        if (memcmp(&haystack[i], needle, needleLen) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/// Поиск признаков вм в содержимом таблицы smbios
int testSMBIOSString(){
    PBYTE smbios;
    DWORD smbiosSize = 0;
    int isVm = 0;
    char *vmSubstrings[] = {
            "VirtualBox", "vbox", "VBOX",
            "VMware", "qemu", "QEMU"
    };
    int vmSubstringsCount = sizeof(vmSubstrings) / sizeof(vmSubstrings[0]);

    smbios = (PBYTE) getSystemFirmWareTable('RSMB', 0, &smbiosSize);
    if(!smbios)
        return 0;
    for(int i = 0; i < vmSubstringsCount; i++){
        if(findStrInData((PBYTE) vmSubstrings[i], strlen(vmSubstrings[i]), smbios, smbiosSize)){
            isVm = 1;
            break;
        }
    }
    freeSystemFirmWareTable(smbios);
    return isVm;
}

/// Поиск признаков вм в содержимом таблиц acpi
int testACPIString(){
    int isVm = 0;
    DWORD *acpiEnum;
    DWORD acpiEnumBytesSize = 0, acpiEnumCount;
    DWORD acpiSize;
    PBYTE acpi;
    char *vmSubstrings[] = {
            "VirtualBox", "vbox", "VBOX",
            "VMWARE", "BOCHS", "BXPC"
    };
    int vmSubstringsCount = sizeof(vmSubstrings) / sizeof(vmSubstrings[0]);

    acpiEnum = (DWORD *) getEnumSystemFirmWareTable('ACPI', &acpiEnumBytesSize);
    if(!acpiEnum)
        return 0;
    acpiEnumCount = acpiEnumBytesSize / sizeof(DWORD);
    if(acpiEnumCount < 4 || !acpiEnumCount){
        freeEnumSystemFirmWareTable(acpiEnum);
        return 1;
    }
    for(DWORD i = 0; i < acpiEnumCount; i++){
        acpiSize = 0;
        acpi = getSystemFirmWareTable('ACPI', acpiEnum[i], &acpiSize);
        if(acpi){
            for(int s = 0; s < vmSubstringsCount; s++){
                if(findStrInData((PBYTE) vmSubstrings[s], strlen(vmSubstrings[s]), acpi, acpiSize)){
                    isVm = 1;
                    break;
                }
            }
            freeSystemFirmWareTable(acpi);
        }
        if(isVm)
            break;
    }
    freeEnumSystemFirmWareTable(acpiEnum);
    return isVm;
}

int detectVM(){
    return testTemperatureProbe() ||
           testThermalZoneTemperature() ||
           testFan() ||
           testBiosSerialNumber() ||
           testComputerModelManufacturer() ||
           testRegistryDiskEnum() ||
           testHwDeviceInfo() ||
           testSMBIOSString() ||
           testACPIString();
}
