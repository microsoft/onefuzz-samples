// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdint.h>
#include <stdlib.h>


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
  int cnt = 0;

  if (len < 4) {
    return 1;
  }

  if (data[0] == 'x') { cnt++; }
  if (data[1] == 'y') { cnt++; }
  if (data[2] == 'z') { cnt++; }

  if (cnt >= 3) {
    switch (data[3]) {
      case '0': {
        // segv
        int *p = NULL; *p = 123;
        break;
      }
      case '1': {
        // stack-buffer-underflow
        int* p = &cnt - 32; for (int i = 0; i < 32; i++) { *(p + i) = 0; }
        break;
      }
    }
  }

  return 0;
}
