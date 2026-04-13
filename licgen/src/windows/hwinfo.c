#define _CRT_SECURE_NO_WARNINGS
#include "hwinfo.h"
#include <stdio.h>
#include "wmi.h"
#include "bstr-utils.h"
#include <math.h>

int initHwInfo(){
    return connectVMI((BSTR) L"ROOT\\CIMV2");
}

int getRAM(){
    MEMORYSTATUSEX memorystatusex;
    int gb_in_b = 1024 * 1024 * 1024;
    memorystatusex.dwLength = sizeof(memorystatusex);
    if(GlobalMemoryStatusEx(&memorystatusex))
        return (int) ceil((double) memorystatusex.ullTotalPhys / (double) gb_in_b);
    return -1;
}

int getWMIStrValue(char *wmi_field, char *wmi_class, char *buffer, int buffer_len){
    HRESULT hres;
    VARIANT vtProp;
    IEnumWbemClassObject *pEnumerator = NULL;
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    BSTR wmi_field_b;

    if(!execVMIQuery(wmi_field, wmi_class, &pEnumerator))
        return 0;

    if(!(wmi_field_b = getBSTR(wmi_field)))
        return 0;

    while(pEnumerator){
        hres = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if(FAILED(hres)){
            freeBSTR(wmi_field_b);
            pEnumerator->lpVtbl->Release(pEnumerator);
            return 0;
        }
        if(uReturn == 0)
            break;
        hres = pclsObj->lpVtbl->Get(pclsObj, wmi_field_b, 0, &vtProp, 0, 0);
        if(FAILED(hres)){
            freeBSTR(wmi_field_b);
            pclsObj->lpVtbl->Release(pclsObj);
            pEnumerator->lpVtbl->Release(pEnumerator);
            return 0;
        }
        WideCharToMultiByte(CP_ACP, 0, vtProp.bstrVal, lstrlenW(vtProp.bstrVal), buffer, buffer_len, 0, 0);
        VariantClear(&vtProp);
        pclsObj->lpVtbl->Release(pclsObj);
    }
    freeBSTR(wmi_field_b);
    pEnumerator->lpVtbl->Release(pEnumerator);
    return 1;
}

char *getCPUVendors(){
    static char vendors[2048];
    if(getWMIStrValue("Manufacturer", "Win32_Processor", vendors, sizeof(vendors))){
        return vendors;
    }
    return NULL;
}

char *getBoardVendor(){
    static char vendor[32];
    if(getWMIStrValue("Manufacturer", "Win32_BaseBoard", vendor, sizeof(vendor))){
        return vendor;
    }
    return NULL;
}

char *getBoardName(){
    static char name[32];
    if(getWMIStrValue("Product", "Win32_BaseBoard", name, sizeof(name))){
        return name;
    }
    return NULL;
}

char *getChassisVendor(){
    static char vendor[32];
    if(getWMIStrValue("Manufacturer", "Win32_SystemEnclosure", vendor, sizeof(vendor))){
        return vendor;
    }
    return NULL;
}

char *getDiskSerial(){
    static char serial[128];
    char disk_path[32];
    HANDLE partition, disk;
    DWORD bytes_returned, out_buf_size;
    BYTE *out_buf;
    STORAGE_DEVICE_NUMBER device_number;
    STORAGE_PROPERTY_QUERY property_query;
    STORAGE_DESCRIPTOR_HEADER descriptor_header = { 0 };
    STORAGE_DEVICE_DESCRIPTOR *device_descriptor;
    char *model_str, *serial_num_str;

    partition = CreateFile("\\\\.\\C:", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, NULL);
    if(partition == INVALID_HANDLE_VALUE)
        return NULL;
    if(!DeviceIoControl(partition, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
                        &device_number, sizeof(device_number), &bytes_returned, NULL)){
        CloseHandle(partition);
        return NULL;
    }
    sprintf(disk_path, "\\\\.\\PHYSICALDRIVE%lu", device_number.DeviceNumber);

    disk = CreateFile(disk_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, NULL);
    if(disk == INVALID_HANDLE_VALUE){
        CloseHandle(partition);
        return NULL;
    }

    ZeroMemory(&property_query, sizeof(STORAGE_PROPERTY_QUERY));
    property_query.PropertyId = StorageDeviceProperty;
    property_query.QueryType = PropertyStandardQuery;
    bytes_returned = 0;
    if(!DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY, &property_query, sizeof(STORAGE_PROPERTY_QUERY),
                        &descriptor_header, sizeof(STORAGE_DESCRIPTOR_HEADER), &bytes_returned, NULL)){
        CloseHandle(partition);
        CloseHandle(disk);
        return NULL;
    }

    out_buf_size = descriptor_header.Size * sizeof(BYTE);
    out_buf = (BYTE *) malloc(out_buf_size);
    if(!out_buf){
        CloseHandle(partition);
        CloseHandle(disk);
        return NULL;
    }
    ZeroMemory(out_buf, out_buf_size);
    if(!DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY, &property_query, sizeof(STORAGE_PROPERTY_QUERY),
                        out_buf, out_buf_size, &bytes_returned, NULL)){
        free(out_buf);
        CloseHandle(partition);
        CloseHandle(disk);
        return NULL;
    }
    device_descriptor = (STORAGE_DEVICE_DESCRIPTOR *) out_buf;
    model_str = (char *) (out_buf + device_descriptor->ProductIdOffset);
    serial_num_str = (char *) (out_buf + device_descriptor->SerialNumberOffset);
    sprintf(serial, "%s_%s", model_str, serial_num_str);

    free(out_buf);
    CloseHandle(partition);
    CloseHandle(disk);
    return serial;
}

void deinitHwInfo(){
    disconnectVMI();
}
