# SPHINCS+ source code for ChipWhisperer

This folder contains the reference implementation of SPHINCS+ adapted for ARM Cortex-M4 (from [The SPHINCS+ reference code](https://github.com/sphincs/sphincsplus/tree/master/ref)).

## Adaptation

1. [`Makefile.crypto`](Makefile.crypto): add the SPHINCSplus `CRYPTO_TARGET` to call `Makefile.sphincsplus`.
2. [`Makefile.sphincsplus`](Makefile.sphincsplus):
	* Mute `PARAMS`, hardcode it instead in `SPHINCSplus/params.h` (see step 3).
	* Program `THASH` to `robust`.
	* Add the relevant source files from `SPHINCSplus/`, including the portable implementation of SHAKE256 in `thash_shake256_robust.c`.
	* Use ChipWhisperer's Keccak implementation.
3. [`SPHINCSplus/params.h`](SPHINCSplus/params.h): program `params-sphincs-shake256-256s.h`.

The library can be used with `CRYPTO_TARGET=SPHINCSplus` (and no `CRYPTO_OPTIONS`).