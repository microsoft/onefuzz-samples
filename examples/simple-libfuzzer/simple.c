// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdint.h>
#include <stdlib.h>


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
  int cnt = 0;

  if (len < 4) {
    return 1;
  }

  return 0;
}
