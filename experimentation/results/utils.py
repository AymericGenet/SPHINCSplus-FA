import sys
sys.path.append('../../')

import re
from SPHINCSplus import ADRS
from math import prod

# -----------------------------------------------------------------------------
# Miscellaneous
# -----------------------------------------------------------------------------

def loginfo(info, f_log=None, onscreen=False):
	"""Logs info in provided file handler or on console screen.
	"""
	if onscreen:
		print(info)
	if f_log:
		f_log.write(info + '\n')

# -----------------------------------------------------------------------------
# SPHINCS+
# -----------------------------------------------------------------------------

def derive_pk(spx, layer, tree, leaf):
	"""Derives the W-OTS+ public key (leaf of XMSS) at the specified layer,
	tree, and leaf index.
	"""
	wots_adrs = ADRS()
	wots_adrs.setLayerAddress(layer)
	wots_adrs.setTreeAddress(tree)
	wots_adrs.setKeyPairAddress(leaf)

	(_, pk_w) = spx.wots_plus.keygen(spx.sk_seed, wots_adrs, spx.pk_seed)

	return pk_w

def derive_root(spx, layer, tree):
	"""Derives the XMSS tree root at the specified layer, and tree index.
	"""
	adrs = ADRS()
	adrs.setLayerAddress(layer)
	adrs.setTreeAddress(tree)

	(_, root) = spx.xmss.keygen(spx.sk_seed, adrs, spx.pk_seed)

	return root

def derive_auth_path(spx, layer, tree, leaf):
	"""Derives the authentication path in an XMSS at the specified layer, tree
	index, starting from the leaf index.
	"""
	adrs = ADRS()
	adrs.setLayerAddress(layer)
	adrs.setTreeAddress(tree)

	((_, auth_path), _) = spx.xmss.sign(b"\x00"*32, leaf, spx.sk_seed, adrs, spx.pk_seed)

	return auth_path

def derive_sig(spx, layer, tree):
	"""Derives an intermediate W-OTS+ signature in an XMSS at specified layer,
	and tre index. This corresponds to the signature of the XMSS tree root at
	the previous layer.
	"""
	root = derive_root(spx, layer-1, tree)

	wots_adrs = ADRS()
	wots_adrs.setLayerAddress(layer)
	wots_adrs.setTreeAddress(tree >> 8)
	wots_adrs.setKeyPairAddress(tree & 0xff)
	sig = spx.wots_plus.sign(root, spx.sk_seed, wots_adrs, spx.pk_seed)

	return sig

# -----------------------------------------------------------------------------
# Log parsing functions
# -----------------------------------------------------------------------------

SEND_REGEX = r"^.*Sending  \.\.\. ([0-9a-fA-F]{16}).*$"
RECV_REGEX = r"^.*Received \.\.\. ([ \w]+).*$"

FAULTY_REGEX = r"^([0-9a-fA-F]{16}) -> ([ \w]+): FAULTY SIGNATURE.*$"

def parse_logs(logfile):
	"""Reads and parses log file of experiment with each input/output received
	from/to the target device.
	"""
	send_pat = re.compile(SEND_REGEX)
	recv_pat = re.compile(RECV_REGEX)

	send_data = []
	recv_data = []
	with open(logfile) as f:
		for line in f.readlines():
			send_match = send_pat.match(line)
			recv_match = recv_pat.match(line)
			if send_match:
				send_data += [send_match.group(1)]
			elif recv_match:
				recv_data += [recv_match.group(1)]

	return (send_data, recv_data)

def parse_faulty(faultyfile):
	"""Reads and parses faulty signature file that was generated from parse_logs.
	"""
	faulty_pat = re.compile(FAULTY_REGEX)

	faulty = [{'send':[], 'recv':[]} for _ in range(5)]
	with open(faultyfile) as f:
		l = 0
		i = 0
		for line in f.readlines():
			l += 1
			faulty_match = faulty_pat.match(line)
			if faulty_match:
				if l >= 1024:
					i += 1
					l = 0
				faulty[i]['send'] += [faulty_match.group(1)]
				faulty[i]['recv'] += [faulty_match.group(2)]

	return faulty

CACH_REGEX  = r"^.*CACHE (HIT|MISS) \((?:STATUS=1, )?HIT PREDICTION=(True|False)\)!$"
TRUE_HIT_REGEX = r"^.*CACHE HIT \(STATUS=1, HIT PREDICTION=True\)!$"
TRUE_MISS_REGEX = r"^.*CACHE MISS \(HIT PREDICTION=False\)!$"

def parse_logs_cached(logfile):
	send_pat = re.compile(SEND_REGEX)
	recv_pat = re.compile(RECV_REGEX)
	cach_pat = re.compile(CACH_REGEX)

	send_data = []
	recv_data = []
	cache_data = []
	with open(logfile) as f:
		for line in f.readlines():
			send_match = send_pat.match(line)
			recv_match = recv_pat.match(line)
			cach_match = cach_pat.match(line)
			if send_match:
				send_data += [send_match.group(1)]
			elif recv_match:
				recv_data += [recv_match.group(1)]
			elif cach_match:
				status = cach_match.group(1)
				predic = cach_match.group(2)
				if status == 'HIT' and predic == 'True':
					cache_data += [1]
				elif status == 'MISS' and predic == 'False':
					cache_data += [0]
				else:
					cache_data += [-1]

	return (send_data, recv_data, cache_data)

# -----------------------------------------------------------------------------
# Signatures checks
# -----------------------------------------------------------------------------

def check_faulty(spx, send_data, recv_data, layer):
	"""Checks for faulty W-OTS signatures by comparing the received signatures
	with the expected signatures at their addresses (using the known signing
	key).

	The sent data correspond to addresses (tree | leaf), and received data to 
	the concatenation of the authentication path and W-OTS+ signatures (all in
	hexadecimal string, big endian).
	"""
	valid = {'send': [], 'recv': []}
	faulty = {'send': [], 'recv': []}

	for (s, r) in zip(send_data, recv_data):
		adrs = int(s, 16)
		tree = adrs >> 8
		leaf = adrs & 0xff

		# Derives actual signature + authentication path of the same tree starting from same leaf
		sig = ' '.join([x.hex() for x in derive_sig(spx, layer, tree) + derive_auth_path(spx, layer-1, tree, leaf)])

		if sig == r:
			valid['send'] += [s]
			valid['recv'] += [r]
		else:
			faulty['send'] += [s]
			faulty['recv'] += [r]

	return (valid, faulty)

def check_verifiable(spx, faulty, layer):
	"""Checks that the faulty W-OTS signatures are verifiable by comparing the
	recovered root with the expected root.

	@input faulty The second output of check_faulty (see above).
	"""
	verif = {'send': [], 'recv': []}
	nonverif = {'send': [], 'recv': []}

	for (s, r) in zip(faulty['send'], faulty['recv']):
		if r == "Nothing":
			nonverif['send'] += [s]
			nonverif['recv'] += [r]
		else:
			adrs = int(s, 16)
			tree = adrs >> 8
			leaf = adrs & 0xff

			# Recover previous layer's leaf
			pk_w = derive_pk(spx, layer-1, tree, leaf)

			# Compute previous layer's tree root using authentication path from signature + recovered leaf
			tree_adrs = ADRS()
			tree_adrs.setLayerAddress(layer-1)
			tree_adrs.setTreeAddress(tree)
			tree_adrs.setType(ADRS.Type.XMSS)
			tree_adrs.setKeyPairAddress(0)

			auth_path = [int.to_bytes(int(x, 16), byteorder='big', length=32) for x in r.split()[-8:]]
			root = spx.hash.recomp_root(pk_w, auth_path, leaf, tree_adrs, spx.pk_seed)

			# Compute expected layer's W-OTS+ signature of previous layer's tree root
			wots_adrs = ADRS(tree_adrs)
			wots_adrs.setLayerAddress(layer)
			wots_adrs.setTreeAddress(tree >> 8)
			wots_adrs.setKeyPairAddress(tree & 0xff)
			exp_sig = ' '.join([x.hex() for x in spx.wots_plus.sign(root, spx.sk_seed, wots_adrs, spx.pk_seed)])

			# Check if signatures are the same
			if r[:67*65-1] == exp_sig:
				verif['send'] += [s]
				verif['recv'] += [r]
			else:
				nonverif['send'] += [s]
				nonverif['recv'] += [r]

	return (verif, nonverif)

def check_correctness(spx, nonverif, layer):
	"""Checks that the non-verifiable W-OTS signatures are corect by comparing
	the received elements with all the elements in the signing key of the W-OTS+.

	@input nonverif The second output of check_verifiable (see above).
	"""
	correct = {'send': [], 'recv': []}
	incorrect = {'send': [], 'recv': []}

	for (s, r) in zip(nonverif['send'], nonverif['recv']):
		# Rule out "Nothing" signature
		if r == "Nothing":
			incorrect['send'] += [s]
			incorrect['recv'] += [r]
		else:
			sig = [int.to_bytes(int(x, 16), byteorder='big', length=32) for x in r.split()[:-8]]

			# Address of XMSS at previous layer
			adrs = int(s, 16)
			tree = adrs >> 8
			leaf = adrs & 0xff

			# Address of WOTS at current layer
			wots_adrs = ADRS()
			wots_adrs.setLayerAddress(layer)
			wots_adrs.setTreeAddress(tree >> 8)
			wots_adrs.setKeyPairAddress(tree & 0xff)

			# Derive entire signing key of W-OTS+
			(sk, _) = spx.wots_plus.keygen(spx.sk_seed, wots_adrs, spx.pk_seed)

			mismatch = False
			for i in range(len(sk)):
				wots_adrs.setChainAddress(i)
				# Pass through entire signing key to see if value is there
				for j in range(spx.wots_plus.W):
					if sig[i] == sk[i]:
						break
					wots_adrs.setHashAddress(j)
					sk[i] = spx.hash.F(sk[i], wots_adrs, spx.pk_seed)
				# Passed through entire signing key and still mismatch
				if sig[i] != sk[i]:
					mismatch = True
					break

			# Classification
			if mismatch:
				incorrect['send'] += [s]
				incorrect['recv'] += [r]
			else:
				correct['send'] += [s]
				correct['recv'] += [r]

	return (correct, incorrect)

def compute_graftingproba(spx, sigs, tree, layer):
	"""Computes the theoretical probability that a tree could be grafted given
	the specified W-OTS+ signatures at the specified layer and tree index.

	The function identifies the messages for all signatures and then computes
	the probability as follows:

	    (W-b[0])/W * (W-b[1])/W * (W-b[2])/W * ... * (W-b[l-1])/W

	where b[i] are the lowest chunks of log2(W) bits at position 0 <= i < ell
	in all messages.
	"""
	# Address of WOTS at current layer
	wots_adrs = ADRS()
	wots_adrs.setLayerAddress(layer)
	wots_adrs.setTreeAddress(tree >> 8)
	wots_adrs.setKeyPairAddress(tree & 0xff)

	msgs = []
	for s in sigs:
		# Skips "Nothing"
		if "Nothing" in s:
			continue

		# W-OTS+ signature elements
		s = [int.to_bytes(int(x, 16), byteorder='big', length=32) for x in s.split()]

		(sk, _) = spx.wots_plus.keygen(spx.sk_seed, wots_adrs, spx.pk_seed)

		msg = []
		# Recover message from signature, given signing key and signature
		for i in range(len(sk)):
			wots_adrs.setChainAddress(i)
			# Pass through entire signing key to see if value is there
			for j in range(spx.wots_plus.W):
				if s[i] == sk[i]:
					msg += [j]
					break
				wots_adrs.setHashAddress(j)
				sk[i] = spx.hash.F(sk[i], wots_adrs, spx.pk_seed)
			# Passed through entire signing key and still mismatch
			if s[i] != sk[i]:
				print(f"Incorrect signature at index {i}: {hex(tree)[2:]} -> {s[i].hex()}")
				break

		# Was the message properly identified?
		if len(msg) == spx.wots_plus.len and not msg in msgs:
			msgs += [msg]

	# Given the lowest values recovered, evaluate how hard it would be to graft a tree
	proba = prod([(spx.wots_plus.W - b)/spx.wots_plus.W for b in map(lambda tup: min(tup), zip(*msgs))]) if len(msgs) > 1 else 0

	return (tree, proba)

def derive_results(spx, layer, adrs2sig):
	"""Derives the various results according to number of collisions of
	signatures for a same address.
	"""
	# Get maximum load (i.e., maximum number of unique signatures at a single address)
	max_load = len(max(adrs2sig.values(), key= lambda v: len(v)))

	# Get compromised W-OTS+ (i.e., addresses for which there are at least 2 unique signatures)
	compromised_wots = list(filter(lambda k: len(adrs2sig[k]) > 1, adrs2sig))

	# Compute grafting probabilities
	graft_p = [compute_graftingproba(spx, adrs2sig[adrs], adrs, layer) for adrs in compromised_wots]

	return (max_load, len(compromised_wots), graft_p)

def check_compromised(spx, layer, send_data, recv_data):
	"""Checks the number of compromised W-OTS+ key pairs by arranging all the
	signatures by tree and leaf indexes and returning the number of key pairs
	for which multiple different W-OTS+ signatures were retrieved.

	The sent data correspond to addresses (tree | leaf), and received data to 
	the concatenation of the authentication path and W-OTS+ signatures (all in
	hexadecimal string, big endian).
	"""
	# Arrange signatures by address (tree address of previous layer)
	adrs2sig = {k:set() for k in [int(adrs,16) >> 8 for adrs in send_data]}
	for i in range(len(send_data)):
		if not "Nothing" in recv_data[i]:
			adrs2sig[int(send_data[i], 16) >> 8].add(recv_data[i][:65*67-1])

	return derive_results(spx, layer, adrs2sig)

def check_compromised_cached(spx, layer, send_data, recv_data, cache_data):
	"""Checks the number of compromised W-OTS+ key pairs by arranging all the
	signatures received and the ones pretended to be cached by tree and leaf
	indexes and returning the number of key pairs for which multiple different
	W-OTS+ signatures were retrieved.

	The sent data correspond to addresses (tree | leaf), the received data to 
	the concatenation of the authentication path and W-OTS+ signatures for which
	the cache missed (all in hexadecimal string, big endian), and the cached
	data to the status of the cache returned by each sent address.
	"""
	adrs2sig = {k:set() for k in [int(adrs,16) >> 8 for adrs in send_data]}

	visited = []
	recv_idx = 0
	recomp_queries = float('inf')
	for i in range(len(send_data)):
		address = int(send_data[i], 16)

		tree = address >> 8
		leaf = address & 0xff

		# On (true) cache HIT
		if cache_data[i] == 1:
			if tree in visited:
				# Do nothing, the signature is the same as the one received before
				continue

			# Re-compute address from pretended cache
			sig = ' '.join([x.hex() for x in derive_sig(spx, layer, tree)])
			adrs2sig[int(send_data[i], 16) >> 8].add(sig)
		# On (true) cache MISS
		elif cache_data[i] == 0:
			if not "Nothing" in recv_data[recv_idx]:
				adrs2sig[tree].add(recv_data[recv_idx][:65*67-1])
			recv_idx += 1

		visited += [tree]

		# Condition to compromise
		if len(adrs2sig[tree]) >= 2:
			recomp_queries = min(recomp_queries, i)

	(maxload, n_compromised, graft_p) = derive_results(spx, layer, adrs2sig)

	return (maxload, n_compromised, graft_p, recomp_queries)