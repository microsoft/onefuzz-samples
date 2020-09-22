#include <stdint.h>
#include <stdlib.h>

int func1(const uint8_t *data, size_t len) {
  int cnt = 0;

  if (len < 4) {
    return 1;
  }

  if (data[0] == 'x') { cnt++; }
  if (data[1] == 'y') { cnt++; }
  if (data[2] == 'z') { cnt++; }

  if (cnt >= 3) {
    switch (data[3]) {
      case '4': {
        // double-free
        int* p = malloc(sizeof(int)); free(p); free(p);
        break;
      }
      case '5': {
        // heap-use-after-free
        int* p = malloc(sizeof(int)); free(p); *p = 123;
        break;
      }
      case '6': {
        // heap-buffer-overflow
        int* p = malloc(8 * sizeof(int)); for (int i = 0; i < 32; i++) { *(p + i) = 0; }
        break;
      }
      case '7': {
        // fpe
        int x = 0; int y = 123 / x;
        break;
      }
    }
  }

  return 0;
}
