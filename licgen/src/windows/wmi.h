#ifndef LICGEN_WMI_H
#define LICGEN_WMI_H

#include <windows.h>
#include <WbemIdl.h>

#pragma comment(lib, "wbemuuid.lib")

/**
 * Выполнить подключение к пространству имен базы WMI
 * @param namespace - пространство имен WMI
 * @return 1 - успешно, 0 - ошибка
 */
int connectVMI(BSTR namespace);

/**
 * Выполнить запрос к базе WMI (поле-класс)
 * @param wmi_field - запрашиваемое поле
 * @param wmi_class - запрашиваемый класс
 * @param pp_enumerator - указатель, куда будет записан результат запроса
 * @return 1 - успешно, 0 - ошибка
 * @note: чтобы запросить несколько полей класса, нужно передать их в формате "field1,field2,..."
 * @note: чтобы запросить все поля класса, нужно передать в качестве поля "*"
 */
int execVMIQuery(char *wmi_field, char *wmi_class, IEnumWbemClassObject **pp_enumerator);

/**
 * Отключиться от базы WMI
 */
void disconnectVMI();

#endif //LICGEN_WMI_H
