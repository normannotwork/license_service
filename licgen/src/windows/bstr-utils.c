#include "bstr-utils.h"

BSTR getBSTR(char *str){
    BSTR bstr;
    int bstr_len = MultiByteToWideChar(CP_ACP, 0, str, (int) strlen(str), 0, 0);
    if(bstr_len <= 0)
        return NULL;
    if(!(bstr = SysAllocStringLen(0, bstr_len)))
        return NULL;
    if(MultiByteToWideChar(CP_ACP, 0, str, (int) strlen(str), bstr, bstr_len))
        return bstr;
    SysFreeString(bstr);
    return NULL;
}

void freeBSTR(BSTR bstr){
    SysFreeString(bstr);
}
