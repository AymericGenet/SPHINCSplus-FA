from math import prod, comb, factorial
import sympy
import numpy as np

# Stirling's number of the second kind
stirl2nd = sympy.functions.combinatorial.numbers.stirling
# Count the number of combinations with repetitions
multiset = lambda m, N: comb(m+N-1, m-1)

def truncexp(N, k):
	return prod(map(lambda i: N-i, range(k)))

def break_pb(N, Mv, Mf):
	if Mf == 1:
		return 1 - (1 - 1/N)**Mv
	elif Mv == 0:
		"""Computes the probability of the birthday problem, that is the probability
		that no bin contains two balls after Mf throws.

		Ref: https://en.wikipedia.org/wiki/Birthday_problem#Calculating_the_probability

		Returns: 1 * (1-1/N) * (1-2/N) * ... * (1-Mf/N)"""
		return prod(map(lambda r: 1.0-r/N, range(1, Mf)))
	else:
		"""Computes the probability of the occupancy problem with two types of
		balls, that is the probability that no bin contains two balls of different
		types after M1 throws of the first type and Mf throws of the second type.

		Ref: https://www.ism.ac.jp/editsec/aism/pdf/040_1_0077.pdf

		Returns: Equation (3.4) of https://www.ism.ac.jp/editsec/aism/pdf/040_1_0077.pdf, p.83 (7)"""
		s = 0
		for t1 in range(min(Mv, N)+1):
			stirl2nd_Mvt1 = stirl2nd(Mv, t1)
			for t2 in range(min(Mf, N)+1):
				s += stirl2nd_Mvt1*stirl2nd(Mf, t2)*truncexp(N, t1+t2)
		return s/(N**(Mv+Mf))

def multinomial_transition_pb(N, m, k, sk, sk_prev):
	"""Returns the multinomial transition probabliity, i.e., the entries of the
	stochastic matrix Q_k.

	Args:
		N (int): The number of bins.
		m (int): The number of thrown balls.
		k (int): The index of the stochastic matrix.
		sk (int): The cumulative number of balls from bins 0 to k.
		sk_prev (int): The cumulative number of balls from bins 0 to k-1.
	"""
	p = 1/(N-k)
	return comb(m-sk_prev, sk-sk_prev)*p**(sk-sk_prev)*(1-p)**(m-sk) if sk >= sk_prev else 0

def max_multinomial_freq_pb(N, m, c):
	"""Returns the probability that the maximum frequency of the multinomial
	distribution with parameters N and m.

	Ref: https://link.springer.com/content/pdf/10.1007/s11222-010-9174-3.pdf

	Args:
		N (int): The number of bins.
		m (int): The number of thrown balls.
	"""
	Q = [np.matrix([multinomial_transition_pb(N, m, 0, i, 0) if i <= c else 0 for i in range(m+1)])]
	for k in range(1,N-1):
		Q += [np.matrix([[multinomial_transition_pb(N, m, k, i, j) if i-j <= c else 0 for i in range(m+1)] for j in range(m+1)])]
	Q += [np.matrix([[1 if m-i <= c else 0] for i in range(m+1)])]

	return prod(Q).min()

def maxload_exp(N, Mf, Mv):
	s = 0
	l = 1.0
	c = 0
	while l > 1E-02:
		l = 1.0-max_multinomial_freq_pb(N, Mf, c)
		s += l
		c += 1
	return s + (1 - ((N-1)/N)**Mv)

def coverage_exp(N):
	"""Computes the expected number of the coupon collector's problem, that is
	the average number of uniform throws required to have at least one ball in
	each bin.

	Ref: https://www.sciencedirect.com/science/article/pii/0166218X9290177C

	Args:
		N (int): The number of bins (N > 0)

	Returns:
		N * (1/N + 1/(N-1) + ... + 1)
	"""
	if N <= 0:
		return 0
	return N*sum(map(lambda x: 1/(N-x), range(N)))

def alpha(i, m):
	return sum(map(lambda k: (-1)**(i-k)*comb(i, k)*k**m, range(1, i+1)))/factorial(i)

def distinct_pb(n, m, d):
	return alpha(min(d,n),m)*truncexp(n, d)/n**m

def occupancy_pb(N, m, i):
	return factorial(N)*alpha(i,m)/(factorial(N-i)*(N**m))

def occupancy_exp(N, m):
	return sum(map(lambda i: i*occupancy_pb(N, m, i), range(1, min(N+1, m+1))))

def recomp_matrix(N, C):
	p = np.zeros((N+2, N+2))
	for i in range(N+2-1): # row
		for j in range(N+2): # column
			if i == j:
				p[i][j] = min(C, i)/N
			if j == i+1:
				p[i][j] = (N-i)/N
		if i > C:
			p[i][-1] = (i-C)/N
	p[-1][-1] = 1

	return p

def recomp_exp(N, C):
	p = recomp_matrix(N, C)

	q = [r[:-1] for r in p[:-1]]

	m = np.identity(N+2-1) - q

	n = np.linalg.inv(m)

	return sum(n[0])