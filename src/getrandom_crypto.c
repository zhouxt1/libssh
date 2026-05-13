/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include "libssh/crypto.h"
#include <openssl/rand.h>

/**
 * @addtogroup libssh_misc
 *
 * @{
 */

/**
 * @brief Get random bytes
 *
 * Make sure to always check the return code of this function!
 *
 * @param[in]  where    The buffer to fill with random bytes
 *
 * @param[in]  len      The size of the buffer to fill.
 *
 * @param[in]  strong   Use a strong or private RNG source.
 *
 * @return 1 on success, 0 on error.
 */
int
ssh_get_random(void *where, int len, int strong)
{
    /* ======================================================================
     *  FUZZING VARIANT: WITHOUT RANDOMNESS  (deterministic xorshift64 PRNG)
     * ======================================================================
     *
     *  AFL-friendly RNG: replace OpenSSL's RAND_bytes/RAND_priv_bytes with
     *  a fixed-seed xorshift64 stream so every run with the same fuzz input
     *  takes the same code path — required for high AFL coverage stability.
     *
     *  Every consumer of randomness in libssh (KEX cookie, x25519/curve25519
     *  ephemerals, ed25519/RSA/DSA nonces, packet padding, channel cookies,
     *  PKI containers, mlkem/sntrup761) routes through ssh_get_random(), so
     *  this single function controls determinism for the whole library.
     *  The static state lives in the AFL forkserver parent and never
     *  advances there, so every forked child starts from the same seed.
     *
     *  To switch back to OpenSSL's RNG, revert this hunk.
     * ====================================================================== */
    static unsigned long long fuzz_prng_state = 0x123456789abcdef0ULL;
    unsigned char *buf = (unsigned char *)where;
    int remaining = len;

    (void)strong;

    if (where == NULL || len <= 0) {
        return 0;
    }

    while (remaining > 0) {
        unsigned long long x = fuzz_prng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        fuzz_prng_state = x;
        int n = (remaining < 8) ? remaining : 8;
        int j;
        for (j = 0; j < n; j++) {
            buf[j] = (unsigned char)(x >> (j * 8));
        }
        buf += n;
        remaining -= n;
    }
    return 1;
}

/**
 * @}
 */
