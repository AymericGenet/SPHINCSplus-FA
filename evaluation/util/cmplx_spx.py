# ------------------------------------------------------------------------------
# XMSS count of hash function calls
# ------------------------------------------------------------------------------

def xmss_total_hashes(ell, W, hp):
	return (2**hp)*(ell*W+2) - 1

def xmss_total_nonverifiable_hashes(ell, W, hp):
	return (ell*W) + 1 + hp

def xmss_total_verifiable_hashes(ell, W, hp):
	return (2**hp-1)*(ell*W+1) + (2**hp) - hp -1

# ------------------------------------------------------------------------------
# XMSS count of hash function calls
# ------------------------------------------------------------------------------

def fors_total_hashes(a, k):
	t = 2**a
	return k*(3*t-1) + 1

def fors_total_nonverifiable_hashes(a, k):
	return k*(a+2) + 1

def fors_total_verifiable_hashes(a, k):
	t = 2**a
	return k*(3*t-a-3)

# ------------------------------------------------------------------------------
# SPHINCS+ count of hash function calls
# ------------------------------------------------------------------------------

def spx_total_hashes(a, d, k, ell, W, hp):
	return fors_total_hashes(a, k) + xmss_total_hashes(ell, W, hp)*d + 2

def spx_total_nonverifiable_hashes(a, d, k, ell, W, hp):
	return fors_total_nonverifiable_hashes(a, k) + xmss_total_nonverifiable_hashes(ell, W, hp)*(d-1) + xmss_total_hashes(ell, W, hp) + 1

def spx_total_verifiable_hashes(a, d, k, ell, W, hp):
	return fors_total_verifiable_hashes(a, k) + xmss_total_verifiable_hashes(ell, W, hp)*(d-1) + 1

def spx_total_exploitable_hashes(a, d, k, ell, W, hp):
	return fors_total_hashes(a, k) + xmss_total_hashes(ell, W, hp)*(d-1) + 1