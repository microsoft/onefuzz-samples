#include <stdint.h>
#include <stddef.h>

bool Fuzz(const uint8_t *Data, size_t DataSize) {
    // fills memory
    while(DataSize) {
        int *x = new int;
        DataSize--;
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  Fuzz(Data, Size);
  return 0;
}