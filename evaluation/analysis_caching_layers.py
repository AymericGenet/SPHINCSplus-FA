#!/bin/python

from math import log2
from util.spx_inst import SPHINCSPLUS_INSTANCES
from util.cmplx_spx import *

if __name__ == '__main__':
	for inst in SPHINCSPLUS_INSTANCES:
		spx = SPHINCSPLUS_INSTANCES[inst]

		# Count the number of hash function calls in SPHINCS+ entirely
		f_total_h = fors_total_hashes(spx.log_t, spx.k)
		x_total_h = xmss_total_hashes(spx.ell, spx.W, spx.hp)

		print(f"SPHINCS+-{inst}")
		print(f"")
		print(f"Pr(Expl.)")
		for c in [1,2,3,4, spx.d-1, spx.d]:
			s_total_expl_h = max(spx.d-c-1, 0)*x_total_h
			if c < spx.d:
				s_total_expl_h += f_total_h
			s_total_h = f_total_h + (spx.d-c)*x_total_h + c*(2**(spx.hp-1)*(spx.ell*(spx.W-1)+2) + (2**spx.hp) - 1)
			print(f"\tc = {c}: {s_total_expl_h/s_total_h:.4f} ({s_total_expl_h}/{s_total_h})")
		print(f"Memory complexity of caching c layers")
		for c in [1,2,3,4, spx.d]:
			C = (2**spx.hp)*(2**(c*spx.hp)-1)//(2**spx.hp-1)
			total_bytes = C*spx.n*spx.ell
			print(f"\tc = {c}: {total_bytes:.2E} bytes")
		print(f"")