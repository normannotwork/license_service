#ifndef LICGEN_DETECT_VM_H
#define LICGEN_DETECT_VM_H

/// Тесты для определения виртуальной машины
/// Все они возвращают 1, если найден признак виртуальной машины, 0 - в противном случае
/// Подробности каждого из тестов описаны в соответсвующих файлах реализации

#ifdef WINDOWS
int testTemperatureProbe();
int testThermalZoneTemperature();
int testFan();
int testBiosSerialNumber();
int testComputerModelManufacturer();
int testRegistryDiskEnum();
int testHwDeviceInfo();
int testSMBIOSString();
int testACPIString();
#else
int testVendors();
int testProductNames();
int testCPUID();
int testDiskModel();
int testHwmon();
#endif

/**
 * Определить, запущена ли программа в виртуальной машине
 * @return 1 - запущена в вм, 0 - запущена на настоящем компьютере
 * @details Выполняет все тесты для определения виртуальной машины и на основе их делает итоговый вывод о наличии вм
 */
int detectVM();

#endif //LICGEN_DETECT_VM_H
