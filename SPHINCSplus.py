from collections import namedtuple
from Crypto.Hash import SHAKE256
from enum import IntEnum
from itertools import zip_longest, islice
from math import log2, ceil, floor
import os

# =============================================================================
# HASH FUNCTIONS
# =============================================================================

class Hash:

	def __init__(self, n, m, robust=False):
		self.n = n
		self.m = m
		self.robust = robust
		self.impl = SHAKE256 # for now, the only supported function is SHAKE256. SHA256 and Haraka need special treatment.

	def T_l(self, xs, adrs, pk_seed):
		x = b''.join(xs)
		lN = len(x)
		if self.robust:
			inner_shake = self.impl.new()
			inner_shake.update(pk_seed)
			inner_shake.update(adrs.bytes)
			x = int.to_bytes(
			        int.from_bytes(x, byteorder="little") ^ # XOR
			        int.from_bytes(inner_shake.read(lN), byteorder="little"),
			      byteorder="little", length=lN)
		shake = self.impl.new()
		shake.update(pk_seed)
		shake.update(adrs.bytes)
		shake.update(x)
		return shake.read(self.n)

	def F(self, x, adrs, pk_seed):
		if self.robust:
			inner_shake = self.impl.new()
			inner_shake.update(pk_seed)
			inner_shake.update(adrs.bytes)
			x = int.to_bytes(
			        int.from_bytes(x, byteorder="little") ^ # XOR
			        int.from_bytes(inner_shake.read(len(x)), byteorder="little"),
			      byteorder="little", length=len(x))
		shake = self.impl.new()
		shake.update(pk_seed)
		shake.update(adrs.bytes)
		shake.update(x)
		return shake.read(self.n)

	def H(self, left, right, adrs, pk_seed):
		if self.robust:
			inner_shake = self.impl.new()
			inner_shake.update(pk_seed)
			inner_shake.update(adrs.bytes)
			mask = int.from_bytes(inner_shake.read(self.n), byteorder="little")
			left = int.to_bytes(
			        int.from_bytes(left, byteorder="little") ^ # XOR
			        mask,
			      byteorder="little", length=len(left))
			mask = int.from_bytes(inner_shake.read(self.n), byteorder="little")
			right = int.to_bytes(
			        int.from_bytes(right, byteorder="little") ^ # XOR
			        mask,
			      byteorder="little", length=len(right))
		shake = self.impl.new()
		shake.update(pk_seed)
		shake.update(adrs.bytes)
		shake.update(left)
		shake.update(right)
		return shake.read(self.n)

	def PRF(self, x, adrs):
		shake = self.impl.new()
		shake.update(x)
		shake.update(adrs.bytes)
		return shake.read(self.n)

	def PRF_msg(self, x, opt, sk_prf):
		shake = self.impl.new()
		shake.update(sk_prf)
		shake.update(opt)
		shake.update(x)
		return shake.read(self.n)

	def H_msg(self, x, pk_root, pk_seed, R):
		shake = self.impl.new()
		shake.update(R)
		shake.update(pk_seed)
		shake.update(pk_root)
		shake.update(x)
		return shake.read(self.m)

	def C(self, x, i, s, adrs, pk_seed):
		if s <= 0:
			return x
		link = self.C(x, i, s-1, adrs, pk_seed)
		adrs.setHashAddress(i+s-1)
		link = self.F(link, adrs, pk_seed)
		return link

	def treehash(self, leaves, leaf_idx, adrs, pk_seed, tree_idx_offset=0):
		assert len(leaves) > 0 and (len(leaves) & (len(leaves)-1) == 0), f"There must be a power of two of leaves: {len(leaves)}"
		assert (tree_idx_offset % (len(leaves)//2)) == 0, f"Invalid tree_idx_offset: {tree_idx_offset} ({len(leaves)} leaves)"

		# Treehash algorithm
		nodes = leaves
		tree_height = 1
		auth_path = []
		while len(nodes) > 1:
			# Set new tree height
			adrs.setTreeHeight(tree_height)

			# We have all the nodes at this level, might as well take the one in the path
			auth_path += [nodes[leaf_idx ^ 1]]

			# Group nodes two-by-two
			grouped_nodes = zip_longest(*[iter(nodes)]*2)

			# Hash each two-by-two grouped node
			nodes = []
			tree_index = tree_idx_offset
			for (left, right) in grouped_nodes:
				adrs.setTreeIndex(tree_index)

				nodes += [self.H(left, right, adrs, pk_seed)]
				tree_index += 1

			# Update height (and leaf index accordingly)
			tree_height += 1
			leaf_idx >>= 1
			tree_idx_offset >>= 1
		return (nodes[0], auth_path)

	def recomp_root(self, leaf, auth_path, leaf_idx, adrs, pk_seed, tree_idx_offset=0):
		node = leaf
		for i in range(len(auth_path)):
			adrs.setTreeIndex(tree_idx_offset + (leaf_idx>>1))
			adrs.setTreeHeight(i+1)

			if leaf_idx % 2 == 0:
				node = self.H(node, auth_path[i], adrs, pk_seed)
			else:
				node = self.H(auth_path[i], node, adrs, pk_seed)
			leaf_idx >>= 1
			tree_idx_offset >>= 1
		return node

# =============================================================================
# ADDRESSING SCHEME
# =============================================================================

class ADRS:
	# SPHINCS+ addresses bytes length
	SPX_ADDRESS_BYTES = 32

	# Indices
	SPX_LAYER_IDX = 0
	SPX_TREE_IDX = 1
	SPX_TYPE_IDX = 4
	SPX_KEYPAIR_IDX = 5
	SPX_TREEHEIGHT_IDX = 6
	SPX_CHAINADDRESS_IDX = 6
	SPX_TREEINDEX_IDX = 7
	SPX_HASHADDRESS_IDX = 7

	# SPHINCS+ byte endianness
	ENDIAN = 'big'

	class Type(IntEnum):
		# W-OTS+ hash chain
		# =================
		# [ layer address  ] [                     tree address                     ]
		# [     type=0     ] [key pair address] [ chain address  ] [  hash address  ]
		WOTSCHAIN = 0
		# W-OTS+ public key compression
		# =============================
		# [ layer address  ] [                     tree address                     ]
		# [     type=1     ] [key pair address] [00000000000000000000000000000000000]
		WOTSPK = 1
		# XMSS hash tree
		# ==============
		# [ layer address  ] [                     tree address                     ]
		# [     type=2     ] [0000000000000000] [  tree height   ] [   tree index   ]
		XMSS = 2
		# FORS hash tree
		# ==============
		# [ layer address  ] [                     tree address                     ]
		# [     type=3     ] [key pair address] [  tree height   ] [   tree index   ]
		FORSTREE = 3
		# FORS public key compression
		# ===========================
		# [ layer address  ] [                     tree address                     ]
		# [     type=4     ] [key pair address] [00000000000000000000000000000000000]
		FORSPK = 4

	def __init__(self, adrs=None):
		if type(adrs) is ADRS:
			self.bytes = adrs.bytes
		elif type(adrs) is bytes:
			self.bytes = adrs
		else:
			self.bytes = b'\x00'*self.SPX_ADDRESS_BYTES

	def __str__(self):
		return ' '.join([self.bytes[4*i:4*(i+1)].hex() for i in range(self.SPX_ADDRESS_BYTES//4)])

	def setWords(self, val, idx, length):
		"""Sets val in byte address at specified index.
		"""
		if idx < 0 or 4*(idx+length) > self.SPX_ADDRESS_BYTES:
			raise IndexError(f"{idx}")
		self.bytes = self.bytes[:4*idx] + int.to_bytes(val, byteorder=self.ENDIAN, length=4*length) + self.bytes[4*(idx+length):]

	def setLayerAddress(self, layeraddr):
		self.setWords(layeraddr, self.SPX_LAYER_IDX, 1)

	def setTreeAddress(self, treeaddr):
		self.setWords(treeaddr, self.SPX_TREE_IDX, 3)

	def setType(self, typeaddr):
		self.setWords(typeaddr, self.SPX_TYPE_IDX, 1)

	def setKeyPairAddress(self, keypairaddr):
		self.setWords(keypairaddr, self.SPX_KEYPAIR_IDX, 1)

	def setTreeHeight(self, treeheight):
		self.setWords(treeheight, self.SPX_TREEHEIGHT_IDX, 1)

	def setTreeIndex(self, treeindex):
		self.setWords(treeindex, self.SPX_TREEINDEX_IDX, 1)

	def setChainAddress(self, chainaddr):
		self.setWords(chainaddr, self.SPX_CHAINADDRESS_IDX, 1)

	def setHashAddress(self, hashaddr):
		self.setWords(hashaddr, self.SPX_HASHADDRESS_IDX, 1)

# =============================================================================
# FORS
# =============================================================================

class FORS:

	def __init__(self, a, k, hash):
		self.a = a
		self.t = 2**a
		self.mask = self.t - 1
		self.k = k
		self.hash = hash

	def keygen(self, sk_seed, adrs, pk_seed):
		# Computes FORS trees
		roots = []
		sk = []
		tree_adrs = ADRS(adrs)
		tree_adrs.setType(adrs.Type.FORSTREE)
		for i in range(self.k):
			secrets = []
			leaves = []
			tree_adrs.setTreeHeight(0)
			for j in range(self.t):
				tree_adrs.setTreeIndex(i*self.t + j)
				secrets += [self.hash.PRF(sk_seed, tree_adrs)]
				leaves += [self.hash.F(secrets[-1], tree_adrs, pk_seed)]
			(r, _) = self.hash.treehash(leaves, 0, tree_adrs, pk_seed, tree_idx_offset=(i*self.t >> 1))
			roots += [r]
			sk += [secrets]

		# Computes pk
		pk_adrs = ADRS(adrs)
		pk_adrs.setType(adrs.Type.FORSPK)
		pk = self.hash.T_l(roots, pk_adrs, pk_seed)

		return (sk, pk)

	def to_baseA(self, msg):
		return [(msg >> (i*self.a)) & self.mask for i in range(self.k)] # little-endian order

	def sign(self, msg, sk_seed, adrs, pk_seed):
		# Breaks msg into list of indices
		indices = self.to_baseA(int.from_bytes(msg, byteorder="little"))

		# Derives signature (from k FORS trees of t leaves)
		sig = []
		tree_adrs = ADRS(adrs)
		tree_adrs.setType(ADRS.Type.FORSTREE)
		for i in range(self.k):
			# Computes FORS tree
			leaves = []
			secret = b''
			tree_adrs.setTreeHeight(0)
			for j in range(self.t):
				# Computes secret leaves
				tree_adrs.setTreeIndex(j + i*self.t)
				sk = self.hash.PRF(sk_seed, tree_adrs)
				if j == indices[i]:
					secret = sk
				leaves += [self.hash.F(sk, tree_adrs, pk_seed)]
			# Computes authentication path
			(_, auth_path) = self.hash.treehash(leaves, indices[i], tree_adrs, pk_seed, tree_idx_offset=(i*self.t >> 1))

			# Recalls everything
			sig += [(secret, auth_path)]

		return sig

	def keyextract(self, msg, sig, adrs, pk_seed):
		# Breaks msg into list of indices
		indices = self.to_baseA(int.from_bytes(msg, byteorder="little"))

		# Recomputes roots of all FORS trees
		roots = []
		tree_adrs = ADRS(adrs)
		tree_adrs.setType(ADRS.Type.FORSTREE)
		for i in range(self.k):
			(leaf, auth_path) = sig[i]
			tree_adrs.setTreeIndex(i*self.t + indices[i])
			tree_adrs.setTreeHeight(0)
			leaf = self.hash.F(leaf, tree_adrs, pk_seed)
			roots += [self.hash.recomp_root(leaf, auth_path, indices[i], tree_adrs, pk_seed, tree_idx_offset=(i*self.t >> 1))]

		# Recovers public key from roots
		pk_adrs = ADRS(adrs)
		pk_adrs.setType(ADRS.Type.FORSPK)
		pk = self.hash.T_l(roots, pk_adrs, pk_seed)

		return pk

	def verify(self, msg, sig, pk, adrs, pk_seed):
		return pk == self.keyextract(msg, sig, adrs, pk_seed)

# =============================================================================
# W-OTS+
# =============================================================================

class WOTSplus:

	def __init__(self, w, hash):
		self.w = w
		self.W = 2**w
		self.len1 = ceil(8*hash.n/w)
		self.len2 = floor(log2(self.len1*(self.W-1))/w) + 1
		self.len  = self.len1 + self.len2
		self.mask = self.W - 1
		self.hash = hash

	def keygen(self, sk_seed, adrs, pk_seed):
		chain_adrs = ADRS(adrs)
		chain_adrs.setType(ADRS.Type.WOTSCHAIN)

		# Computes chains
		s = []
		p = []
		for i in range(self.len):
			chain_adrs.setChainAddress(i)
			chain_adrs.setHashAddress(0)
			s += [self.hash.PRF(sk_seed, chain_adrs)]
			p += [self.hash.C(s[i], 0, self.W - 1, chain_adrs, pk_seed)]

		# Computes pk
		pk_adrs = ADRS(adrs)
		pk_adrs.setType(ADRS.Type.WOTSPK)
		pk = self.hash.T_l(p, pk_adrs, pk_seed)

		return (s, pk)

	def to_baseW(self, msg, l):
		return [(msg >> (i*self.w)) & self.mask for i in range(l-1,-1,-1)] # reversed order

	def sign(self, msg, sk_seed, adrs, pk_seed):
		chain_adrs = ADRS(adrs)
		chain_adrs.setType(ADRS.Type.WOTSCHAIN)

		# Splits message + checksum into blocks
		b = self.to_baseW(int.from_bytes(msg, byteorder="big"), self.len1)
		csum = sum(map(lambda x: self.W - 1 - x, b))
		b += self.to_baseW(csum, self.len2)

		# Derives signature
		sig = []
		for i in range(self.len):
			chain_adrs.setChainAddress(i)
			chain_adrs.setHashAddress(0)
			sk = self.hash.PRF(sk_seed, chain_adrs)
			sig += [self.hash.C(sk, 0, b[i], chain_adrs, pk_seed)]

		return sig

	def keyextract(self, msg, sig, adrs, pk_seed):
		chain_adrs = ADRS(adrs)
		chain_adrs.setType(ADRS.Type.WOTSCHAIN)

		# Splits message + checksum into blocks
		b = self.to_baseW(int.from_bytes(msg, byteorder="big"), self.len1)
		csum = sum(map(lambda x: self.W - 1 - x, b))
		b += self.to_baseW(csum, self.len2)

		# Computes chains
		p = []
		chain_adrs.setHashAddress(0)
		for i in range(self.len):
			chain_adrs.setChainAddress(i)
			chain_adrs.setHashAddress(b[i])
			p += [self.hash.C(sig[i], b[i], self.W - 1 - b[i], chain_adrs, pk_seed)]

		# Computes pk
		pk_adrs = ADRS(adrs)
		pk_adrs.setType(ADRS.Type.WOTSPK)
		pk = self.hash.T_l(p, pk_adrs, pk_seed)

		return pk

	def verify(self, msg, sig, pk, adrs, pk_seed):
		return pk == self.keyextract(msg, sig, adrs, pk_seed)

# =============================================================================
# XMSS
# =============================================================================

class XMSS:

	def __init__(self, h_prime, wots_plus, hash):
		self.h_prime = h_prime
		self.wots_plus = wots_plus
		self.hash = hash

	def keygen(self, sk_seed, adrs, pk_seed):
		tree_adrs = ADRS(adrs)

		# Derives leaves from W-OTS+ public keys
		sk = []
		leaves = []
		for i in range(2**self.h_prime):
			tree_adrs.setKeyPairAddress(i)
			(s, pk) = self.wots_plus.keygen(sk_seed, tree_adrs, pk_seed)
			leaves += [pk]
			sk += [s]

		# Computes root with treehash
		tree_adrs.setKeyPairAddress(0)
		tree_adrs.setType(ADRS.Type.XMSS)
		(root, _) = self.hash.treehash(leaves, -1, tree_adrs, pk_seed)

		return (sk, root)

	def sign(self, msg, leaf_idx, sk_seed, adrs, pk_seed):
		tree_adrs = ADRS(adrs)

		# Derives leaves from W-OTS+ public keys
		leaves = []
		for i in range(2**self.h_prime):
			tree_adrs.setKeyPairAddress(i)
			if i == leaf_idx:
				sig = self.wots_plus.sign(msg, sk_seed, tree_adrs, pk_seed)
				pk = self.wots_plus.keyextract(msg, sig, tree_adrs, pk_seed)
			else:
				(_, pk) = self.wots_plus.keygen(sk_seed, tree_adrs, pk_seed)
			leaves += [pk]

		# Computes root with treehash
		tree_adrs.setType(ADRS.Type.XMSS)
		tree_adrs.setKeyPairAddress(0)
		(root, auth_path) = self.hash.treehash(leaves, leaf_idx, tree_adrs, pk_seed)

		return ((sig, auth_path), root)

	def fault_sign(self, msg, leaf_idx, sk_seed, adrs, pk_seed, verifying=True):
		tree_adrs = ADRS(adrs)

		# Derives leaves from W-OTS+ public keys
		leaves = []
		for i in range(2**self.h_prime):
			tree_adrs.setKeyPairAddress(i)
			if i == leaf_idx:
				sig = self.wots_plus.sign(msg, sk_seed, tree_adrs, pk_seed)
				pk = self.wots_plus.keyextract(msg, sig, tree_adrs, pk_seed)
			else:
				(_, pk) = self.wots_plus.keygen(sk_seed, tree_adrs, pk_seed)
			leaves += [pk]

		leaves[leaf_idx ^ 1 if verifying else leaf_idx] = os.urandom(self.hash.n) # random leaf faulted

		# Computes root with treehash
		tree_adrs.setType(ADRS.Type.XMSS)
		tree_adrs.setKeyPairAddress(0)
		(root, auth_path) = self.hash.treehash(leaves, leaf_idx, tree_adrs, pk_seed)

		return ((sig, auth_path), root)

	def keyextract(self, msg, leaf_idx, sig, adrs, pk_seed):
		tree_adrs = ADRS(adrs)

		# Split signature into leaf and authentication path
		(wots_plus_sig, auth_path) = sig
		tree_adrs.setKeyPairAddress(leaf_idx)
		leaf = self.wots_plus.keyextract(msg, wots_plus_sig, tree_adrs, pk_seed)

		# Recomputes root
		tree_adrs.setType(ADRS.Type.XMSS)
		tree_adrs.setKeyPairAddress(0)
		root = self.hash.recomp_root(leaf, auth_path, leaf_idx, tree_adrs, pk_seed)

		return root

	def verify(self, msg, leaf_idx, sig, pk, adrs, pk_seed):
		return pk == self.keyextract(msg, leaf_idx, sig, adrs, pk_seed)

# =============================================================================
# SPHINCS+
# =============================================================================

# SPHINCS+ parameters
spx_inst = namedtuple("spx_inst", "n h d a k w")

# SPHINCS+ according to specifications
# Ref: https://sphincs.org/data/sphincs+-round3-specification.pdf, Table 3, p.38
SPHINCSPLUS_INSTANCES = {
	"128s": spx_inst(n=16, h=64, d=8,  a=15, k=10, w=4), # h' = 8
	"128f": spx_inst(n=16, h=60, d=20, a=9,  k=30, w=4), # h' = 3
	"192s": spx_inst(n=24, h=64, d=8,  a=16, k=14, w=4), # h' = 8
	"192f": spx_inst(n=24, h=66, d=22, a=8,  k=33, w=4), # h' = 3
	"256s": spx_inst(n=32, h=64, d=8,  a=14, k=22, w=4), # h' = 8
	"256f": spx_inst(n=32, h=68, d=17, a=10, k=30, w=4)  # h' = 4
}

class SPHINCSplus:

	def __init__(self, instance, randomize=True, robust=False):
		spx = SPHINCSPLUS_INSTANCES[instance]

		m = (spx.k*spx.a+7)//8 + (spx.h-spx.h//spx.d+7)//8 + (spx.h//spx.d+7)//8
		self.hash = Hash(spx.n, m, robust=robust)
		self.fors = FORS(spx.a, spx.k, self.hash)
		self.wots_plus = WOTSplus(spx.w, self.hash)
		self.xmss = XMSS(spx.h//spx.d, self.wots_plus, self.hash)
		self.d = spx.d
		self.h = spx.h
		self.randomize = randomize

		self.SKSEED_LENGTH = self.hash.n
		self.SKPRF_LENGTH = self.hash.n
		self.PKSEED_LENGTH = self.hash.n
		self.PKROOT_LENGTH = self.hash.n
		self.SIGNATURE_LENGTH = (1+spx.k*(spx.a+1)+spx.h+spx.d*self.wots_plus.len)*self.hash.n

	def keygen(self, sk_seed=None, sk_prf=None, pk_seed=None, pk_root=None):
		if not pk_seed:
			pk_seed = os.urandom(self.PKSEED_LENGTH)
		if not sk_seed:
			sk_seed = os.urandom(self.SKSEED_LENGTH)
		if not sk_prf:
			sk_prf = os.urandom(self.SKPRF_LENGTH)
		if not pk_root:
			tree_adrs = ADRS()
			tree_adrs.setLayerAddress(self.d-1)
			(_, pk_root) = self.xmss.keygen(sk_seed, tree_adrs, pk_seed)

		self.sk_seed = sk_seed
		self.sk_prf = sk_prf
		self.pk_seed = pk_seed
		self.pk_root = pk_root

	def digest(self, msg, R):
		digest = iter(self.hash.H_msg(msg, self.pk_root, self.pk_seed, R))
		tmp_md = bytes(islice(digest, (self.fors.k*self.fors.a+7)//8))
		tmp_tree_idx = bytes(islice(digest, (self.h - self.h//self.d + 7)//8))
		tmp_leaf_idx = bytes(islice(digest, (self.h//self.d + 7)//8))

		md = int.from_bytes(tmp_md, byteorder="big") # & ((2**(self.fors.a*self.fors.k)-1)) that's complicated actually... => remove bits from last byte
		tree_idx = int.from_bytes(tmp_tree_idx, byteorder="big") & (2**(self.h - self.h//self.d)-1)
		leaf_idx = int.from_bytes(tmp_leaf_idx, byteorder="big") & (2**(self.h//self.d)-1)

		md = int.to_bytes(md, byteorder="big", length=(self.fors.a*self.fors.k+7)//8)

		return (md, tree_idx, leaf_idx)

	def sign(self, msg):
		adrs = ADRS()
		opt = os.urandom(self.hash.n) if self.randomize else b'\x00'*self.hash.n
		R = self.hash.PRF_msg(msg, opt, self.sk_prf)
		(md, tree_idx, leaf_idx) = self.digest(msg, R)

		adrs.setLayerAddress(0)
		adrs.setTreeAddress(tree_idx)
		adrs.setKeyPairAddress(leaf_idx)

		sig_fors = self.fors.sign(md, self.sk_seed, adrs, self.pk_seed)
		root = self.fors.keyextract(md, sig_fors, adrs, self.pk_seed)

		sig_ht = []
		for i in range(self.d):
			adrs.setLayerAddress(i)
			adrs.setTreeAddress(tree_idx)

			(sig, root) = self.xmss.sign(root, leaf_idx, self.sk_seed, adrs, self.pk_seed)
			sig_ht += [sig]
			leaf_idx = (tree_idx & (2**self.xmss.h_prime-1))
			tree_idx >>= self.xmss.h_prime

		return (R, sig_fors, sig_ht)

	def fault_sign(self, msg, layer=0, verifying=True):
		adrs = ADRS()
		opt = os.urandom(self.hash.n) if self.randomize else b'\x00'*self.hash.n
		R = self.hash.PRF_msg(msg, opt, self.sk_prf)
		(md, tree_idx, leaf_idx) = self.digest(msg, R)

		adrs.setLayerAddress(0)
		adrs.setTreeAddress(tree_idx)
		adrs.setKeyPairAddress(leaf_idx)

		sig_fors = self.fors.sign(md, self.sk_seed, adrs, self.pk_seed)
		root = self.fors.keyextract(md, sig_fors, adrs, self.pk_seed)

		sig_ht = []
		for i in range(self.d):
			adrs.setLayerAddress(i)
			adrs.setTreeAddress(tree_idx)

			if i == layer:
				(sig, root) =  self.xmss.fault_sign(root, leaf_idx, self.sk_seed, adrs, self.pk_seed, verifying=verifying)
			else:
				(sig, root) =  self.xmss.sign(root, leaf_idx, self.sk_seed, adrs, self.pk_seed)
			sig_ht += [sig]
			leaf_idx = (tree_idx & (2**self.xmss.h_prime-1))
			tree_idx >>= self.xmss.h_prime

		return (R, sig_fors, sig_ht)

	def to_bytes(self, sig):
		sig_bytes = b''

		(R, sig_fors, sig_ht) = sig
		sig_bytes += R

		for i in range(len(sig_fors)):
			(s_fors, a_path_fors) = sig_fors[i]
			sig_bytes += s_fors
			sig_bytes += b''.join(a_path_fors)

		for i in range(len(sig_ht)):
			(s_wots_plus, a_path_xmss) = sig_ht[i]
			sig_bytes += b''.join(s_wots_plus)
			sig_bytes += b''.join(a_path_xmss)

		return sig_bytes

	def from_bytes(self, sig_bytes):
		assert len(sig_bytes) == self.SIGNATURE_LENGTH

		sig_bytes = iter(sig_bytes)
		R = bytes(islice(sig_bytes, self.hash.n))
		sig_fors = []
		for _ in range(self.fors.k):
			secret = bytes(islice(sig_bytes, self.hash.n))
			auth_path = []
			for _ in range(self.fors.a):
				auth_path += [bytes(islice(sig_bytes, self.hash.n))]
			sig_fors += [(secret, auth_path)]

		sig_ht = []
		for _ in range(self.d):
			sig_wots_plus = []
			for _ in range(self.wots_plus.len):
				sig_wots_plus += [bytes(islice(sig_bytes, self.hash.n))]
			auth_path = []
			for _ in range(self.xmss.h_prime):
				auth_path += [bytes(islice(sig_bytes, self.hash.n))]
			sig_ht += [(sig_wots_plus, auth_path)]

		return (R, sig_fors, sig_ht)

	def extract_keys(self, msg, sig):
		adrs = ADRS()
		(R, sig_fors, sig_ht) = sig

		(md, tree_idx, leaf_idx) = self.digest(msg, R)

		adrs.setLayerAddress(0)
		adrs.setTreeAddress(tree_idx)
		adrs.setKeyPairAddress(leaf_idx)

		roots = [self.fors.keyextract(md, sig_fors, adrs, self.pk_seed)]

		for i in range(self.d):
			adrs.setLayerAddress(i)
			adrs.setTreeAddress(tree_idx)
			roots += [self.xmss.keyextract(roots[-1], leaf_idx, sig_ht[i], adrs, self.pk_seed)]
			leaf_idx = (tree_idx & (2**self.xmss.h_prime-1))
			tree_idx >>= self.xmss.h_prime

		return roots

	def verify(self, msg, sig):
		return self.extract_keys(msg, sig)[-1] == self.pk_root

	def write_sig(self, msg, sig, file="data/tmp.txt"):
		with open(file, 'a') as f:
			f.write(f"{msg.hex()} ")
			(R, sig_fors, sig_ht) = sig
			f.write(f"{R.hex().zfill(self.hash.n*2)}")

			for i in range(len(sig_fors)):
				(s_fors, a_path_fors) = sig_fors[i]
				f.write(f"{s_fors.hex().zfill(self.hash.n*2)}")
				for j in range(len(a_path_fors)):
					f.write(f"{a_path_fors[j].hex().zfill(self.hash.n*2)}")

			for i in range(len(sig_ht)):
				(s_wots_plus, a_path_xmss) = sig_ht[i]
				for j in range(len(s_wots_plus)):
					f.write(f"{s_wots_plus[j].hex().zfill(self.hash.n*2)}")
				for j in range(len(a_path_xmss)):
					f.write(f"{a_path_xmss[j].hex().zfill(self.hash.n*2)}")

	def print_sig(self, sig):
		(R, sig_fors, sig_ht) = sig
		print(f"R: {R.hex().zfill(self.hash.n*2)}")

		for i in range(len(sig_fors)):
			(s_fors, a_path_fors) = sig_fors[i]
			print()
			print(f"FORS {i:2}: {s_fors.hex().zfill(self.hash.n*2)}")
			for j in range(len(a_path_fors)):
				print(f"path {j:2}: {a_path_fors[j].hex().zfill(self.hash.n*2)}")

		for i in range(len(sig_ht)):
			(s_wots_plus, a_path_xmss) = sig_ht[i]
			print("="*72)
			for j in range(len(s_wots_plus)):
				print(f"WOTS+{j:2}: {s_wots_plus[j].hex().zfill(self.hash.n*2)}")
			for j in range(len(a_path_xmss)):
				print(f"path {j:2}: {a_path_xmss[j].hex().zfill(self.hash.n*2)}")