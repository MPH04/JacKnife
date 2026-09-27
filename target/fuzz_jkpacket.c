#include <stddef.h>
#include <stdint.h>

#include "jkpacket.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)jkpacket_parse(data, size);
    return 0;
}
