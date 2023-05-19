#!/bin/python

from math import log2
from util.spx_inst import SPHINCSPLUS_INSTANCES
from util.cmplx_uf import *

if __name__ == '__main__':
	for inst in SPHINCSPLUS_INSTANCES:
		spx = SPHINCSPLUS_INSTANCES[inst]

		# Count the number of hash function calls
		sig_id_h = sig_identification_withpk_hashes(spx.ell, spx.W)
		nv_sig_id_h = sig_identification_nvonly_hashes(spx.ell, spx.W)

		print(f"SPHINCS+-{inst}")
		print(f"")
		print(f"\tProcessing")
		print(f"\t\tCase 1: {sig_id_h} (2^{log2(sig_id_h):.2f})")
		print(f"\t\tCase 2: {nv_sig_id_h} (2^{log2(nv_sig_id_h):.2f})")
		print(f"\tE[Non-id. chunks]")
		for M in range(2,5):
			unid_chunks = unidentied_chunks_number(spx.ell, spx.W, M)
			print(f"\t\tM = {M}: {unid_chunks:.2f}/{spx.ell}")
		print(f"\tGrafting hashes")
		print(f"\t\tGrafting probability")
		for logM in range(1,6):
			pr_graft = grafting_pr(spx.ell, 2**logM, spx.W)
			print(f"\t\t\tM = {2**logM}: {pr_graft:.4f} (2^{log2(pr_graft):.2f})")
		print(f"\t\tFORS")
		for logM in range(1,6):
			f_graft_h = fors_grafting_hashes(spx.log_t, spx.k, spx.ell, 2**logM, spx.W)
			print(f"\t\t\tM = {2**logM}: {f_graft_h:.4f} (2^{log2(f_graft_h):.2f})")
		print(f"\t\tXMSS")
		for logM in range(1,6):
			x_graft_h = xmss_grafting_hashes(spx.hp, spx.k, spx.ell, 2**logM, 2**spx.log_t, spx.W)
			print(f"\t\t\tM = {2**logM}: {x_graft_h:.4f} (2^{log2(x_graft_h):.2f})")
		print(f"\tPath seeking hashes")
		for layer in [0, 1, spx.d-1]:
			pseek_h = path_seeking_hashes(spx.h, spx.hp, layer)
			print(f"\t\tl* = {layer}: {pseek_h} (2^{int(log2(pseek_h))})")
		print(f"")