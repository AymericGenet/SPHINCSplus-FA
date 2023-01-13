#!/bin/python

from math import log2
from util.combi import break_pb, coverage_exp, maxload_exp

N = 2**8

if __name__ == '__main__':
	for log_N in [8]:
		print(f"Pr(W-OTS+ break) where N = {2**log_N}")
		for log_Mv in [0] + list(range(2,7)):
			Mv = 2**log_Mv if log_Mv > 0 else 0
			print(f"\tMv = {Mv}")
			for log_Mf in range(2,7):
				Mf = 2**log_Mf
				print(f"\t\tMf = {Mf}: {1.0-break_pb(2**log_N, Mv, Mf):.4f}")

	print(f"E[Mv] to cover layer")
	for log_N in [3,4,6,8,9,12,16]:
		avg_Mv = coverage_exp(2**log_N)
		print(f"\tN = {2**log_N}: {avg_Mv:.2f} (2^{log2(avg_Mv):.2f})")

	print(f"E[Max. load | Mf]")
	for log_N in [3, 4, 6, 8, 9]:
		print(f"\tN = {2**log_N}")
		for log_Mf in range(6, 11):
			Mf = 2**log_Mf
			max_M = maxload_exp(2**log_N, Mf, 0)
			print(f"\t\tMf = {Mf}: {max_M:.2f} (2^{log2(max_M):.2f})")
	print(f"")