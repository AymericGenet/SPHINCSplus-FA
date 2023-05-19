from .cmplx_spx import xmss_total_hashes, fors_total_hashes

# ------------------------------------------------------------------------------
# 1. Fault collection: see cmplx_spx.py
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# 2. Processing
# ------------------------------------------------------------------------------

def sig_identification_withpk_hashes(ell, W):
	"""Case 1: known W-OTS+ public key.
	"""
	return ell*(W-1)/2

def sig_identification_nvonly_hashes(ell, W):
	"""Case 2: unknown W-OTS+ public key.
	"""
	return ell*(W*(W-1)+1)/2

def unidentied_chunks_number(ell, W, M):
	"""Expected number of unidentified chunks with M non-verifiable signatures.
	"""
	return ell*(1.0/(W**(M-1)))

# ------------------------------------------------------------------------------
# 3. Grafting
# ------------------------------------------------------------------------------

def grafting_pr(ell, M, W):
	return (sum([1 - ((W-1-x)/W)**M for x in range(W)])**ell)/(W**ell)

def fors_grafting_hashes(a, k, ell, M, W):
	f_total_h = fors_total_hashes(a, k)
	graft_h = 1.0/grafting_pr(ell, M, W)

	return f_total_h*graft_h

def xmss_grafting_hashes(hp, k, ell, M, t, W):
	x_hashes = xmss_total_hashes(ell, W, hp)
	graft_h = 1.0/grafting_pr(ell, M, W)

	return x_hashes*graft_h

# ------------------------------------------------------------------------------
# 4. Path seeking
# ------------------------------------------------------------------------------

def path_seeking_hashes(h, hp, layer):
	"""Fix the tree index (tau), fix the leaf index (lambda) in this tree.

	We want both the tree index and the leaf index to pass by the compromised
	key pair. Given the layer l at which the key pair is compromised, we need
	the h-hp*(l+1) first bits of the digest's address to be tau, then the
	subsequent hp bits to be lambda. As a result, this amounts to:

	    2^(h-hp*(layer+1))*2^hp = 2^(h-hp*layer) possible solutions.

	On average, we need to perform this amount of hashes to get it right
	(see: geometric random variable).
	"""
	return 2**(h - hp*layer)