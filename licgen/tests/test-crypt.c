#include "crypt.h"
#include <stdio.h>
#include <string.h>

int main(){
  unsigned char text[] = "This is a test? This is a test. This is a test!!!";
  unsigned char key[KEY_LENGTH] = {
      0x96, 0x3a, 0x7a, 0xe4, 0x39, 0x5f, 0xef, 0xb2,
      0x96, 0xcc, 0x80, 0x3f, 0x16, 0xd3, 0xb9, 0x60,
      0xe3, 0xc5, 0xdf, 0x15, 0x69, 0x2d, 0x9a, 0x3d,
      0xa0, 0x4d, 0x0d, 0xde, 0x5f, 0xf8, 0x7a, 0x7f
  };
  unsigned char out[100], deout[100];
  int out_len = sizeof(out), deout_len = sizeof(deout);
  int text_len = (int) strlen(text) + 1;
  memset(out, 0, out_len);
  memset(deout, 0, deout_len);

  if((out_len = encryptData(text, text_len, key, KEY_LENGTH, out, out_len)) != 0){
    printf("plain text: %s\nplain text len including null terminator = %d\n\n", text, text_len);
    printf("encrypted text: ");
    for(int i = 0; i < out_len; i++){
      printf("%.2x", out[i]);
    }
    printf("\nencrypted text len = %d\n\n", out_len);

    if((deout_len = decryptData(out, out_len, key, KEY_LENGTH, deout, deout_len)) != 0)
      printf("decrypted text: %s\ntotal decrypted data len = %d", deout, deout_len);
    else{
      printf("Could not decrypt text\n");
      return 1;
    }
  }
  else{
    printf("Could not encrypt text\n");
    return 1;
  }
  return 0;
}
