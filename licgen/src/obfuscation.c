#include "obfuscation.h"

#define MAX_SECRET_LEN 32

const unsigned char obfuscator[MAX_SECRET_LEN] = {
    0x0b, 0xe5, 0x66, 0xe0, 0x9c, 0x63, 0x3c, 0x71,
    0x36, 0xb1, 0x17, 0x76, 0xde, 0x65, 0x2c, 0x51,
    0xd4, 0x5f, 0x63, 0x97, 0xbc, 0xd5, 0x9c, 0xcc,
    0xb0, 0xc6, 0x28, 0xf0, 0xa1, 0x6a, 0xc3, 0x4b
};

int getRealSecret(const unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int out_len){
  if(in_len > MAX_SECRET_LEN || in_len != out_len)
    return 0;

  for(unsigned int i = 0; i < in_len; i++)
    out[i] = in[i] ^ obfuscator[i];
  return 1;
}

int getObfuscatedSecret(const unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int out_len){
  return getRealSecret(in, in_len, out, out_len);
}
