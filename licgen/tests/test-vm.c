#include "detect-vm.h"
#include "stdio.h"

int main(){
#ifdef WINDOWS
    printf("temperatureProbe: %d\n", testTemperatureProbe());
    printf("thermalZoneTemperature: %d\n", testThermalZoneTemperature());
    printf("fan: %d\n", testFan());
    printf("biosSerialNumber: %d\n", testBiosSerialNumber());
    printf("computerModelManufacturer: %d\n", testComputerModelManufacturer());
    printf("registryDiskEnum: %d\n", testRegistryDiskEnum());
    printf("hwDeviceInfo: %d\n", testHwDeviceInfo());
    printf("SMBIOS: %d\n", testSMBIOSString());
    printf("ACPI: %d\n", testACPIString());
#else
    printf("vendors: %d\n", testVendors());
    printf("products: %d\n", testProductNames());
    printf("cpuid: %d\n", testCPUID());
    printf("models: %d\n", testDiskModel());
    printf("hwmon: %d\n", testHwmon());
#endif
    printf("%s\n", detectVM() ? "vm detected" : "no vm detected");
    return 0;
}
