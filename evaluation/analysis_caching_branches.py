#!/bin/python

from math import log2, ceil
from util.spx_inst import SPHINCSPLUS_INSTANCES
from util.cmplx_spx import *
from util.combi import recomp_exp

SIGNIFICANT_RATIO = 2/3

if __name__ == '__main__':
	for inst in SPHINCSPLUS_INSTANCES:
		spx = SPHINCSPLUS_INSTANCES[inst]
		print(f"SPHINCS+-{inst}")
		print(f"")
		print(f"Pr(Expl.)")
		for log_b in [spx.hp, 2*spx.hp, 3*spx.hp, 4*spx.hp, spx.h]:
			b = ceil(SIGNIFICANT_RATIO*(2**log_b))

			# SPHINCS+ total count of hashes in the branch-caching signing procedure
			#
			# SPHINCS+ count of vulnerable hashes
			#   The hash function call is vulnerable if and only if the W-OTS+
			#   that signs the public key of the structure being constructed is
			#   uncached.
			#   We suppose the cache independently filled at each layer.
			#
			# FORS case (i.e., l = -1)
			f_total_h = fors_total_hashes(spx.log_t, spx.k)
			s_total_h = 2 + f_total_h
			# Across the 2^h W-OTS+ pk, C/N are cached, so not vulnerable
			N = 2**spx.h
			C = min(N, b)
			s_total_expl_h = f_total_h*(1-C/N)
			for l in range(spx.d):
				# Across the 2^h' W-OTS+ pk, on average, C/N do not need to be computed
				x_total_h = (2**spx.hp)*((1-C/N)*(spx.ell*spx.W+1) + (C/N)*0) + 2**spx.hp - 1
				s_total_h += x_total_h
				N = 2**(spx.h-spx.hp*(l+1))
				C = min(N, b)
				if l != spx.d-1:
					s_total_expl_h += x_total_h*(1-C/N)
			print(f"\tb = ({SIGNIFICANT_RATIO:.2f})2^{log_b}: {s_total_expl_h/s_total_h:.4f} ({s_total_expl_h:.2f}/{s_total_h:.2f})")
		print(f"Memory complexity of caching b branches")
		for log_b in [spx.hp, 2*spx.hp, 3*spx.hp, 4*spx.hp, spx.h]:
			b = ceil(SIGNIFICANT_RATIO*(2**log_b))
			C = sum([min(2**(spx.h-spx.hp*l), b) for l in range(spx.d)])
			total_bytes = C*(spx.n+1)*spx.ell
			print(f"\tb = ({SIGNIFICANT_RATIO:.2f})2^{log_b}: {total_bytes:.2E} bytes")
		print(f"")

	print(f"")
	print(f"E[queries to recomp.]")
	for log_N in [3, 4, 6, 8, 9]:
		print(f"N = {2**log_N}")
		for ratio in [1/2, 2/3, 3/4]:
			C = ceil(ratio*(2**log_N))
			queries_avg = recomp_exp(2**log_N, C)
			print(f"\t\t({ratio:.2f}){2**log_N}:  = {queries_avg:.2f} (2^{log2(queries_avg):.2f})")
		queries_avg = recomp_exp(2**log_N, 2**log_N-1)
		print(f"\t\t{2**log_N}-1: {queries_avg:.2f} (2^{log2(queries_avg):.2f})")