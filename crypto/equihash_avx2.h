// Native Zcash (200,9) verification with automatic AVX2/scalar selection.
#ifndef EQUIHASH_AVX2_H
#define EQUIHASH_AVX2_H
#include <stddef.h>
#include <stdint.h>
// Inputs are borrowed readable buffers. Null pointers and wrong lengths fail.
// A true result checks only Equihash, not share target, freshness or
// duplicates.
// Set EQUIHASH_ENABLE_AVX512=1 before the first call to prefer AVX512 when
// supported. The setting and CPU selection are cached; other values keep the
// AVX2/scalar default. The OS and CPU must still support the selected kernel.
bool VerifyEquihash2009(const uint8_t *header, size_t header_len,
                        const uint8_t *solution, size_t solution_len);
bool Equihash2009HasAvx2();
#endif
