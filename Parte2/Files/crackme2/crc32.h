#ifndef CRC32_H_
#define CRC32_H_

# include <stdio.h>
# include <stdlib.h>

# define CRC_BUFFER_SIZE  8192

int Crc32_ComputeFile(FILE *file, unsigned long *outCrc32);
unsigned long Crc32_ComputeBuf(unsigned long inCrc32, const void *buf, size_t bufLen);

#endif
