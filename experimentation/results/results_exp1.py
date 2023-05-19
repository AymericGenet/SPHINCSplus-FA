#!/bin/python
import sys
sys.path.append('../../')
from SPHINCSplus import SPHINCSplus, ADRS

from utils import *
from datetime import datetime
from math import log2

N = 5
M = 1024

LAYER_STAR = 6

LOG_FILE_IN = "../chipwhisperer/logs/2022-07-29_10-34-56_SPHINCSplus.txt"
RESULTS_FILE_OUT = datetime.now().strftime(f"../chipwhisperer/logs/%Y-%m-%d_%H-%M-%S_SPHINCSplus_results_exp1.txt")

# Pre-generated key pair for SPHINCS-shake-256s-robust
skseed = b"\x07\xad\x58\xd9\xa7\xb1\xf8\x56\xa1\xc6\x64\xb8\x6f\xf2\xa7\x39\x05\xc4\xbe\x0a\x62\x82\x1e\x8a\x6a\x51\xe0\x34\x12\xfa\x89\x3a"
skprf  = b"\xfd\xb9\x5f\x27\xbd\xec\xcc\x57\x70\xc0\x77\x0c\x96\x52\x03\x8f\xea\x65\xa0\x82\xb9\x98\x84\x77\x12\x9e\xab\xa3\x13\xa2\xad\xc8"
pkseed = b"\x1a\x3d\x9c\xcc\x1e\x6c\xd4\xa4\xbe\xbe\x2c\x60\x30\x84\x04\xe4\xa3\x50\xa8\x7e\xf4\x47\xe4\x9a\xa7\xee\x50\x61\x13\x1b\xab\x63"
pkroot = b"\xfc\x54\x29\xb3\x64\x88\x9d\x21\x3a\x26\xd5\xa6\x99\x86\x56\x01\x79\xda\xc9\xc6\xe2\x0d\x55\xf4\x24\xce\xe9\x33\x91\x79\xda\xe8"

spx = SPHINCSplus("256s", robust=True, randomize=False)
spx.keygen(skseed, skprf, pkseed, pkroot)

def results(N, logfile, onscreen=False, logged=True):
	"""Prints Tables 14 and 15 of technical paper.
	"""
	(send_data, recv_data) = parse_logs(logfile)
	assert len(send_data) == len(recv_data), f"Length discrepancy between sent and received data ({len(send_data)} != {(len(recv_data))})"
	batch_size = len(send_data)//N

	f_log = open(RESULTS_FILE_OUT, 'w') if logged else None

	for i in range(N):
		loginfo(f"i={i}\n", f_log=f_log, onscreen=onscreen)

		(sent, rcvd) = (send_data[batch_size*i:batch_size*(i+1)], recv_data[batch_size*i:batch_size*(i+1)])

		# Classify faulty signatures according to their types
		(_, faulty) = check_faulty(spx, sent, rcvd, LAYER_STAR)
		(_, nonverif) = check_verifiable(spx, faulty, LAYER_STAR)
		(correct, _) = check_correctness(spx, nonverif, LAYER_STAR)

		# Derive results
		(maxload, n_compromised, graft_p) = check_compromised(spx, LAYER_STAR, sent, rcvd)

		loginfo(f"# of faulty signatures = {len(faulty['send'])} (vs {batch_size-len(faulty['send'])} valid)", f_log=f_log, onscreen=onscreen)
		loginfo(f"# of faulty non-verifiable signatures = {len(nonverif['send'])} (vs {len(faulty['send'])-len(nonverif['send'])} verifiable)", f_log=f_log, onscreen=onscreen)
		loginfo(f"# of faulty non-verifiable signatures but correct = {len(correct['send'])} (vs {len(nonverif['send'])-len(correct['send'])})", f_log=f_log, onscreen=onscreen)

		loginfo(f"Max load: {maxload}", f_log=f_log, onscreen=onscreen)
		loginfo(f"Number of compromised W-OTS+: {n_compromised}", f_log=f_log, onscreen=onscreen)

		if graft_p:
			(adrs, proba) = max(graft_p, key=lambda p: p[1])
			loginfo(f"Maximum grafting probability at 0x{hex(adrs)[2:].zfill(4)} = {proba} (2^{log2(proba) if proba != 0 else 256:.4f})", f_log=f_log, onscreen=onscreen)

			(adrs, proba) = min(graft_p, key=lambda p: p[1])
			loginfo(f"Minimum grafting probability at 0x{hex(adrs)[2:].zfill(4)} = {proba} (2^{log2(proba) if proba != 0 else 256:.4f})", f_log=f_log, onscreen=onscreen)

		loginfo(f"="*100 + '\n\n', f_log=f_log, onscreen=onscreen)

if __name__ == '__main__':
	results(N, LOG_FILE_IN, onscreen=True, logged=True)
