#include <stdint.h>
#include <stddef.h>
#include <iostream>
using namespace std;
bool Fuzz(const uint8_t *Data, size_t DataSize) {
    while (DataSize) {
        cout << "CPU";
        DataSize--;
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  Fuzz(Data, Size);
  return 0;
}