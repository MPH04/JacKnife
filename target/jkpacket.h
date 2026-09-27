#ifndef JACKNIFE_JKPACKET_H
#define JACKNIFE_JKPACKET_H

#include <stddef.h>
#include <stdint.h>

/* Parse one JacKnife packet buffer.
 * Returns 0 on a handled buffer. Sanitizer crashes abort the process.
 * See docs/target.md for the seeded bugs and the byte layout. */
int jkpacket_parse(const uint8_t *data, size_t size);

#endif
