/*
This code was taken from the SPHINCS reference implementation and is public domain.
*/

#include <fcntl.h>
#include <unistd.h>

#if 0
/* The original source code opens /dev/urandom to read random byte from. As
   * /dev/urandom/ is not available on the STM32, the call is replaced by a
   * memset with zeroes.
   *
   * The STM32F303RCT7 (NAE-CW308T-STM32F3) does not offer a TRNG, so any
   * randomness provided to the card must be externally feeded to. */

static int fd = -1;

void randombytes(unsigned char *x, unsigned long long xlen)
{

    int i;

    if (fd == -1) {
        for (;;) {
            fd = open("/dev/urandom", O_RDONLY);
            if (fd != -1) {
                break;
            }
            sleep(1);
        }
    }

    while (xlen > 0) {
        if (xlen < 1048576) {
            i = xlen;
        }
        else {
            i = 1048576;
        }

        i = read(fd, x, i);
        if (i < 1) {
            sleep(1);
            continue;
        }

        x += i;
        xlen -= i;
    }
}
#else
#include <string.h>

void randombytes(unsigned char *x, unsigned long long xlen)
{
    memset(x, 0x00, xlen);
}
#endif
