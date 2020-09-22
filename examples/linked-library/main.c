#include <stdint.h>
#include <stdlib.h>

#include "bad1.h"
#include "bad2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
     func1(data, size);
     func2(data, size);
     return 0;
}
