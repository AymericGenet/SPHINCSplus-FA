/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Build me with
 *    make PLATFORM=CWLITEARM CRYPTO_TARGET=SPHINCSplus
 *    rm -rf .dep/ objdir-CW308_STM32F4/ && make PLATFORM=CW308_STM32F4 CRYPTO_TARGET=SPHINCSplus
 */
/*
 * We attack sphincs-shake256-256s-robust because it's easier to use SHAKE256
 * and it's supposedly the safest version of SPHINCS+.
 *
 * Note however that the attack is agnostic in both parameter sets and hash function.
 *
 * If you want to change this, you need to go in ../crypto/Makefile.sphincsplus and change:
 *   - THASH=robust
 *   - SRC += [...] hash_shake256.c thash_shake256_$(THASH).c
 */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "address.h"
#include "api.h"
#include "context.h"
#include "fors.h"
#include "hash.h"
#include "merkle.h"
#include "params.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"

#define ENABLE_TESTS

#define SPHINCSPLUS_SK_BYTES CRYPTO_SEEDBYTES /* (skseed, skprf, pkseed) 3*SPX_N */
#define SPHINCSPLUS_PK_BYTES SPX_PK_BYTES /* (pkroot, pkseed) 2*SPX_N */
#define SPHINCSPLUS_MSG_BYTES 32

#define EXP_STR_LAYER (6-1) /* i.e., l*-1, as we care about the W-OTS+ at EXP_STR_LAYER+1 */
#define EXP_CACH_LAYER (7-1) /* i.e., l*-1, as we care about the W-OTS+ at EXP_STR_LAYER+1 */

/* ========================================================================== */
/*                                  GLOBALS                                   */
/* ========================================================================== */

uint8_t sk_prf[SPX_N] = {
  0xfd, 0xb9, 0x5f, 0x27, 0xbd, 0xec, 0xcc, 0x57, 
  0x70, 0xc0, 0x77, 0x0c, 0x96, 0x52, 0x03, 0x8f, 
  0xea, 0x65, 0xa0, 0x82, 0xb9, 0x98, 0x84, 0x77, 
  0x12, 0x9e, 0xab, 0xa3, 0x13, 0xa2, 0xad, 0xc8
};
uint8_t pk_root[SPX_N] = {
  0xfc, 0x54, 0x29, 0xb3, 0x64, 0x88, 0x9d, 0x21, 
  0x3a, 0x26, 0xd5, 0xa6, 0x99, 0x86, 0x56, 0x01, 
  0x79, 0xda, 0xc9, 0xc6, 0xe2, 0x0d, 0x55, 0xf4, 
  0x24, 0xce, 0xe9, 0x33, 0x91, 0x79, 0xda, 0xe8
};

// Fixed constants, synchronized with python tools
uint32_t addr[8] = { /* 32 bytes */
    0x44a59bfe, 0xeaefa8a4, 0x32632228, 0x57676ded,
    0x21d9e7fa, 0xc1f4f13d, 0x775f5069, 0xffb93335
};
spx_ctx ctx = {
    { 0x1a, 0x3d, 0x9c, 0xcc, 0x1e, 0x6c, 0xd4, 0xa4, 
      0xbe, 0xbe, 0x2c, 0x60, 0x30, 0x84, 0x04, 0xe4, 
      0xa3, 0x50, 0xa8, 0x7e, 0xf4, 0x47, 0xe4, 0x9a, 
      0xa7, 0xee, 0x50, 0x61, 0x13, 0x1b, 0xab, 0x63 },
    { 0x07, 0xad, 0x58, 0xd9, 0xa7, 0xb1, 0xf8, 0x56, 
      0xa1, 0xc6, 0x64, 0xb8, 0x6f, 0xf2, 0xa7, 0x39, 
      0x05, 0xc4, 0xbe, 0x0a, 0x62, 0x82, 0x1e, 0x8a, 
      0x6a, 0x51, 0xe0, 0x34, 0x12, 0xfa, 0x89, 0x3a }
};

/* WOTS+: 67 * 32 = 2144 */
/* XMSS: 8 * 32 = 256 */
#define EXP_SIG_BYTES 2400
unsigned char sig[EXP_SIG_BYTES]  = { 0x00 };

/* Caching in-depth */
//#define CACHE_SIZE 50
//unsigned char sig[CACHE_SIZE*EXP_SIG_BYTES] = { 0x00 };
//#define CACHE_SIZE 43690
#define CACHE_SIZE 171
uint8_t cache[CACHE_SIZE] = { 0x0000 };
uint8_t cache_idx = 0;

/* ========================================================================== */
/*                             INTERNAL FUNCTIONS                             */
/* ========================================================================== */

#define u8tou64_be(in) ((((uint64_t) in[0]) << 56) | (((uint64_t) in[1]) << 48) | (((uint64_t) in[2]) << 40) | (((uint64_t) in[3]) << 32) | \
                        (((uint64_t) in[4]) << 24) | (((uint64_t) in[5]) << 16) | (((uint64_t) in[6]) << 8)  | (((uint64_t) in[7]) << 0))

/* ========================================================================== */
/*                               TEST FUNCTIONS                               */
/* ========================================================================== */

#ifdef ENABLE_TESTS
uint8_t test_thash(uint8_t* m, uint8_t len)
{ // Sign message with private key

    unsigned char out[SPX_N]  = { 0x00 };

    trigger_high();
    thash(out, m, len/SPX_N, &ctx, addr);
    trigger_low();

    simpleserial_put('r', SPX_N, (uint8_t*) out);

    return 0x00;
}

uint8_t test_wotsplus(uint8_t* m, uint8_t len)
{ // Sign message with private key

    unsigned char pk[SPX_N]  = { 0x00 };

    struct leaf_info_x1 info = { 0 };
    uint32_t steps[SPX_WOTS_LEN] = { 0x00 };

    info.wots_sig = sig;
    chain_lengths(steps, m);
    info.wots_steps = steps;

    set_type(&info.leaf_addr[0], SPX_ADDR_TYPE_WOTS);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], addr);
    copy_subtree_addr(&info.pk_addr[0], addr);

    info.wots_sign_leaf = 0;

    trigger_high();
    wots_gen_leafx1(pk, &ctx, 0, &info); /* Note: leaf_idx = 0 (keypair in adrs) */
    trigger_low();

    /*
    for (i = 0; i < SPX_WOTS_LEN; ++i) {
        putch((steps[i] >> 0) & 0xff);
    }

    for (i = 22*SPX_N; i < 23*SPX_N; ++i)
        putch(sig[i]);
    */

    return 0x00;
}

uint8_t test_merkle(uint8_t* m, uint8_t len)
{
    unsigned char root[SPX_N] = { 0x00 };
    uint32_t wots_addr[8] = { 0x00 };
    uint32_t tree_addr[8] = { 0x00 };
    size_t i = 0;

    //memcpy(tree_addr, addr, 8*4); /* Need to make sure that memcpy copies bytes */
    //memcpy(wots_addr, addr, 8*4);
    memcpy(root, m, len);

    set_layer_addr(tree_addr, 0);
    set_tree_addr(tree_addr, 0);

    copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, 0);

    trigger_high();
    merkle_sign(sig, root, &ctx, wots_addr, tree_addr, 0);
    trigger_low();

    for (i = 0; i < SPX_N; ++i)
        putch(root[i]);

    return 0;
}

uint8_t test_fors(uint8_t* m, uint8_t len)
{
    unsigned char root[SPX_N] = { 0x00 };
    uint32_t fors_addr[8] = { 0x00 };
    size_t i = 0;

    //memcpy(tree_addr, addr, 8*4); /* Need to make sure that memcpy copies bytes */
    //memcpy(wots_addr, addr, 8*4);

    trigger_high();
    fors_sign(sig, root, m, &ctx, fors_addr);
    trigger_low();

    for (i = 0; i < SPX_N; ++i)
        putch(root[i]);

    return 0;
}

uint8_t test_sphincsplus(uint8_t* m, uint8_t len)
{ // Sign message with private key

    unsigned char pk[SPX_PK_BYTES] = { 0x00 };
    unsigned char mhash[SPX_FORS_MSG_BYTES] = { 0x00 };
    unsigned char root[SPX_N] = { 0x00 };
    unsigned char optrand[SPX_N] = { 0x00 };
    unsigned long long i = 0;
    uint64_t tree = 0;
    uint32_t idx_leaf = 0;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    unsigned char* sphincs_sig = sig;

    memcpy(pk, ctx.pub_seed, SPX_N);
    memcpy(pk + SPX_N, pk_root, SPX_N);

    trigger_high();

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    //randombytes(optrand, SPX_N);
    /* Compute the digest randomization value. */
    gen_message_random(sphincs_sig, sk_prf, optrand, m, len, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idx_leaf, sphincs_sig, pk, m, len, &ctx);
    sphincs_sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */

    fors_sign(sphincs_sig, root, mhash, &ctx, wots_addr);
    sphincs_sig += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(sphincs_sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sphincs_sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    trigger_low();

    return 0x00;
}

uint8_t test_trig(uint8_t* x, uint8_t len)
{ // Test trigger
    uint64_t test = 0x0123456789abcdef;

    trigger_high();
    while (x[0]-- != 0);
    trigger_low();

    putch((uint8_t) (test & 0xFF));
    putch((uint8_t) ((test >> 56) & 0xFF));

    return 0x00;
}
#endif /* ENABLE_TESTS */

/* ========================================================================== */
/*                             EXTERNAL FUNCTIONS                             */
/* ========================================================================== */

uint8_t get_sig(uint8_t* m, uint8_t len)
{
    uint32_t idx = (m[1] << 8) | m[0];
    size_t i = 0;

    for (i = idx*SPX_N; i < (idx+1)*SPX_N; ++i)
    {
        putch(sig[i]);
    }

    return 0;
}

uint8_t set_key(uint8_t* k, uint8_t len)
{ // Set private key
    memcpy(ctx.sk_seed, k, SPX_N);
    memcpy(sk_prf, k + SPX_N, SPX_N);
    memcpy(ctx.pub_seed, k + 2*SPX_N, SPX_N);

    merkle_gen_root(pk_root, &ctx);

    initialize_hash_function(&ctx);

    return 0x00;
}

uint8_t get_sk(uint8_t* m, uint8_t len)
{ // Get private key
    size_t i = 0;

    for (i = 0; i < SPX_N; ++i)
    {
        putch(ctx.sk_seed[i]);
    }
    for (i = 0; i < SPX_N; ++i)
    {
        putch(sk_prf[i]);
    }

    return 0;
}

uint8_t get_pk(uint8_t* m, uint8_t len)
{ // Get private key
    size_t i = 0;

    for (i = 0; i < SPX_N; ++i)
    {
        putch(pk_root[i]);
    }
    for (i = 0; i < SPX_N; ++i)
    {
        putch(ctx.pub_seed[i]);
    }

    return 0;
}
#if 0
uint8_t sign_simul(uint8_t* in_addr, uint8_t len)
{ // Sign message with private key

    unsigned char root[SPX_N] = { 0x00 };
    unsigned long long i = 0;
    uint64_t tree = 0;
    uint32_t idx_leaf = 0;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    unsigned char* sphincs_sig = sig;

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Retrieve idx_leaf from tree */
    tree = u8tou64_be(in_addr);
    idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
    tree >>= SPX_TREE_HEIGHT;

    trigger_high();

    /* Re-construct intermediate layers only */
    for (i = 0; i < 2; i++) {
        set_layer_addr(tree_addr, EXP_STR_LAYER+i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(sphincs_sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sphincs_sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    trigger_low();

    return 0x00;
}
#endif
uint8_t sign_straight(uint8_t* in_addr, uint8_t len)
{ // Sign message with private key

    unsigned char root[SPX_N] = { 0x00 };
    uint64_t tree = 0;
    uint32_t idx_leaf = 0;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    unsigned char pk[SPX_N]  = { 0x00 };
    struct leaf_info_x1 info = { 0 };
    uint32_t steps[SPX_WOTS_LEN] = { 0x00 };

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Retrieve idx_leaf from tree */
    tree = u8tou64_be(in_addr);
    idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
    tree >>= SPX_TREE_HEIGHT;

    trigger_high();

    /* Re-construct intermediate layer only */
    set_layer_addr(tree_addr, EXP_STR_LAYER);
    set_tree_addr(tree_addr, tree);
    copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, idx_leaf);

    merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);

    /* Update the indices for the next layer. */
    idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
    tree = tree >> SPX_TREE_HEIGHT;

    set_layer_addr(wots_addr, EXP_STR_LAYER+1);
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    info.wots_sig = sig;
    chain_lengths(steps, root); /* W-OTS+ message */
    info.wots_steps = steps;

    set_type(&info.leaf_addr[0], SPX_ADDR_TYPE_WOTS);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    wots_gen_leafx1(pk, &ctx, idx_leaf, &info); /* Sign and remember signature (pointer in info.wots_sig) */

    trigger_low();

    return 0x00;
}

uint8_t fill_cache(uint8_t* in_addr, uint8_t len)
{
    uint64_t addrs = 0;

    addrs = (u8tou64_be(in_addr) >> 8) & 0xFF;
    cache[cache_idx] = addrs;
    cache_idx = (cache_idx + 1) % CACHE_SIZE;

    return 0x00;
}

uint8_t sign_cached(uint8_t* in_addr, uint8_t len)
{
    unsigned char root[SPX_N] = { 0x00 };
    uint64_t tree = 0, i = 0;
    uint32_t idx_leaf = 0;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint16_t addrs = 0x0000;

    unsigned char pk[SPX_N]  = { 0x00 };
    struct leaf_info_x1 info = { 0 };
    uint32_t steps[SPX_WOTS_LEN] = { 0x00 };

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Retrieve address */
    tree = u8tou64_be(in_addr);

    /* Check if address in cache */
    addrs = (tree >> 8) & 0xFF;
    for (i = 0; i < CACHE_SIZE; ++i)
        if (cache[i] == addrs)
            return 0x01; /* Notify that the address was cached */

    /* Update cache */
    cache[cache_idx] = addrs;
    cache_idx = (cache_idx + 1) % CACHE_SIZE;

    /* Retrieve idx_leaf from tree */
    idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
    tree >>= SPX_TREE_HEIGHT;

    trigger_high();

    /* Re-construct intermediate layer only */
    set_layer_addr(tree_addr, EXP_CACH_LAYER);
    set_tree_addr(tree_addr, tree);
    copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, idx_leaf);

    merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);

    /* Update the indices for the next layer. */
    idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
    tree = tree >> SPX_TREE_HEIGHT;

    set_layer_addr(wots_addr, EXP_CACH_LAYER+1);
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    info.wots_sig = sig;
    chain_lengths(steps, root); /* W-OTS+ message */
    info.wots_steps = steps;

    set_type(&info.leaf_addr[0], SPX_ADDR_TYPE_WOTS);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    wots_gen_leafx1(pk, &ctx, idx_leaf, &info); /* Sign and remember signature (pointer in info.wots_sig) */

    trigger_low();

    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Prints "SPHINCS+" */
    putch('S');
    putch('P');
    putch('H');
    putch('I');
    putch('N');
    putch('C');
    putch('S');
    putch('+');
    putch('\n');

    initialize_hash_function(&ctx);

    simpleserial_init();

    /* Functions programmed to attack SPHINCS+ */

    /* Additional (optional) functions for testing purpose */
    #ifdef ENABLE_TESTS
    simpleserial_addcmd('a', SPX_N, test_thash);
    simpleserial_addcmd('b', SPX_N, test_wotsplus);
    simpleserial_addcmd('c', SPX_N, test_merkle);
    simpleserial_addcmd('d', SPX_FORS_MSG_BYTES, test_fors);
    simpleserial_addcmd('e', SPHINCSPLUS_MSG_BYTES, test_sphincsplus);
    simpleserial_addcmd('t', 1, test_trig);
    #endif

    simpleserial_addcmd('k', SPHINCSPLUS_SK_BYTES, set_key);
    simpleserial_addcmd('p', 0, get_pk);
    simpleserial_addcmd('r', 2, get_sig);
    simpleserial_addcmd('s', 0, get_sk);

    simpleserial_addcmd('x', 8, sign_straight);
    simpleserial_addcmd('q', 8, fill_cache);
    simpleserial_addcmd('z', 8, sign_cached);

    /* Note: letters 'y', 'w', 'v' are already assigned (see simpleserial.c) */

    while(1)
        simpleserial_get();
}
