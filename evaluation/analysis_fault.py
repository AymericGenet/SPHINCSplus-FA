#!/bin/python

from math import log2
from util.spx_inst import SPHINCSPLUS_INSTANCES
from util.cmplx_spx import *

if __name__ == '__main__':
	for inst in SPHINCSPLUS_INSTANCES:
		spx = SPHINCSPLUS_INSTANCES[inst]

		# Count the number of hash function calls in FORS
		f_verif_h = fors_total_verifiable_hashes(spx.log_t, spx.k)
		f_nonverif_h = fors_total_nonverifiable_hashes(spx.log_t, spx.k)
		f_total_h = fors_total_hashes(spx.log_t, spx.k)
		assert f_verif_h + f_nonverif_h == f_total_h, f"FORS computations inconsistent ({f_verif_h} + {f_nonverif_h} != {f_total_h})"

		# Count the number of hash function calls in XMSS
		x_verif_h = xmss_total_verifiable_hashes(spx.ell, spx.W, spx.hp)
		x_nonverif_h = xmss_total_nonverifiable_hashes(spx.ell, spx.W, spx.hp)
		x_total_h = xmss_total_hashes(spx.ell, spx.W, spx.hp)
		assert x_verif_h + x_nonverif_h == x_total_h, f"XMSS computations inconsistent ({x_verif_h} + {x_nonverif_h} != {x_total_h})"

		# Count the number of hash function calls in SPHINCS+ entirely
		s_total_expl_h = spx_total_exploitable_hashes(spx.log_t, spx.d, spx.k, spx.ell, spx.W, spx.hp)
		s_total_verif_h = spx_total_verifiable_hashes(spx.log_t, spx.d, spx.k, spx.ell, spx.W, spx.hp)
		s_total_nonverif_h = spx_total_nonverifiable_hashes(spx.log_t, spx.d, spx.k, spx.ell, spx.W, spx.hp)
		s_total_h = spx_total_hashes(spx.log_t, spx.d, spx.k, spx.ell, spx.W, spx.hp)
		assert s_total_verif_h + s_total_nonverif_h == s_total_h, f"SPHINCS+ computations inconsistent ({s_total_verif_h} + {s_total_nonverif_h} != {total})"

		print(f"SPHINCS+-{inst}")
		print(f"")
		print(f"FORS")
		print(f"\tVerifiable faulty signatures: {f_verif_h} ({f_verif_h/f_total_h:.4f})")
		print(f"\tNon-verifiable faulty signatures: {f_nonverif_h} ({f_nonverif_h/f_total_h:.4f})")
		print(f"XMSS (1 <= l < d)")
		print(f"\tVerifiable faulty signatures: {x_verif_h} ({x_verif_h/x_total_h:.4f})")
		print(f"\tNon-verifiable faulty signatures: {x_nonverif_h} ({x_nonverif_h/x_total_h:.4f})")
		print(f"Probabilities")
		print(f"\tPr(Faulty signature is exploitable) = {s_total_expl_h/s_total_h:.4f}")
		print(f"\tPr(Faulty signature is verifiable) = {s_total_verif_h/s_total_h:.4f}")
		print(f"\tPr(l*=0) = {f_total_h/s_total_h:.4f} ({f_total_h}/{s_total_h})")
		for l in[1, spx.d-1, spx.d]:
			print(f"\tPr(l*={l}) = {x_total_h/s_total_h:.4f} ({x_total_h}/{s_total_h})")
		print(f"")