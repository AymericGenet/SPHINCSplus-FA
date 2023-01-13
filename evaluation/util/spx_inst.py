from collections import namedtuple

# SPHINCS+ parameters
spx_inst = namedtuple("spx_inst", "n h d log_t k W ell hp")

# SPHINCS+ according to specifications
# Ref: https://sphincs.org/data/sphincs+-round3-specification.pdf, Table 3, p.38
SPHINCSPLUS_INSTANCES = {
	"128s": spx_inst(n=16, h=64, d=8,  log_t=15, k=10, W=16, ell = 35, hp=8),
	"128f": spx_inst(n=16, h=60, d=20, log_t=9,  k=30, W=16, ell = 35, hp=3),
	"192s": spx_inst(n=24, h=64, d=8,  log_t=16, k=14, W=16, ell = 51, hp=8),
	"192f": spx_inst(n=24, h=66, d=22, log_t=8,  k=33, W=16, ell = 51, hp=3),
	"256s": spx_inst(n=32, h=64, d=8,  log_t=14, k=22, W=16, ell = 67, hp=8),
	"256f": spx_inst(n=32, h=68, d=17, log_t=10, k=30, W=16, ell = 67, hp=4)
}