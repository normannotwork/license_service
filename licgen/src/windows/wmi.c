#define _CRT_SECURE_NO_WARNINGS
#include "wmi.h"
#include "bstr-utils.h"
#include <stdio.h>

IWbemLocator *pLoc = NULL;
IWbemServices *pSvc = NULL;

int connectVMI(BSTR namespace){
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if(FAILED(hres)){
        disconnectVMI();
        return 0;
    }

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
                                RPC_C_IMP_LEVEL_IMPERSONATE, NULL,EOAC_NONE, NULL);
    if(FAILED(hres)){
        disconnectVMI();
        return 0;
    }

    hres = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *) &pLoc);
    if(FAILED(hres)){
        disconnectVMI();
        return 0;
    }

    hres = pLoc->lpVtbl->ConnectServer(pLoc, namespace, NULL, NULL, 0, 0, 0, NULL, &pSvc);
    if(FAILED(hres)){
        disconnectVMI();
        return 0;
    }

    hres = CoSetProxyBlanket((IUnknown *) pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL,
                             RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if(FAILED(hres)){
        disconnectVMI();
        return 0;
    }

    return 1;
}

int execVMIQuery(char *wmi_field, char *wmi_class, IEnumWbemClassObject **pp_enumerator){
    char query_ch[128];
    BSTR query_b, wmi_field_b;
    int res;

    sprintf(query_ch, "SELECT %s FROM %s", wmi_field, wmi_class);
    if(!(query_b = getBSTR(query_ch)))
        return 0;

    if(!(wmi_field_b = getBSTR(wmi_field))){
        freeBSTR(query_b);
        return 0;
    }

    HRESULT hres = pSvc->lpVtbl->ExecQuery(pSvc, (BSTR) L"WQL", query_b,
                                           WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, pp_enumerator);
    if(FAILED(hres))
        res = 0;
    else
        res = 1;
    freeBSTR(query_b);
    freeBSTR(wmi_field_b);
    return res;
}

void disconnectVMI(){
    if(pSvc) pSvc->lpVtbl->Release(pSvc);
    if(pLoc) pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();
}
