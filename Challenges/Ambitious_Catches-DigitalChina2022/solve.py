import time
from sage.all import *

idx = -1
rand_vec_s = [0]*32

def linear_feed_back(i):
    global rand_vec_s
    return (rand_vec_s[(i+1)&0x1f] + rand_vec_s[(i+29)&0x1f]) % 4294967296 

def srand(seed):
    global rand_vec_s
    global idx
    rand_vec_s[0] = seed
    for i in range(1,31):
        rand_vec_s[i] = (16807 * rand_vec_s[i-1]) % 2147483647
    for i in range(31,34):
        rand_vec_s[i&0x1f] = rand_vec_s[i-31]
    for i in range(34,344):
        rand_vec_s[i&0x1f] = linear_feed_back(i)
    idx = 344 & 0x1f

def rand():
    global rand_vec_s
    global idx
    if idx==-1:
        srand(1)
    rand_vec_s[idx] = linear_feed_back(idx)
    res = rand_vec_s[idx] >> 1
    idx = (idx+1) & 0x1f
    return res


def Num2Blst(x):
  return [int(i) for i in bin(x)[2:]]

def GN(x, G):
  return G(Num2Blst(x)[::-1])

def Lst2Mat(G, r, c, lst):
  return Matrix(G, r, c, [
    GN(i, G) for i in lst
  ])

rand_seed = int(time.mktime(time.strptime("220301 22:13:31", "%y%m%d %H:%M:%S"))) >> 4
srand(rand_seed)
print(hex(rand_seed))

def rand_matrix(G, size):
  elms = []
  for i in range(size):
    for j in range(size):
      elms.append(rand()>>23)
  return Lst2Mat(G, size, size, elms).transpose()



P = PolynomialRing(GF(2), 'a')
a = P.gen()
pmod = a**8 + a**7 + a**4 + a**3 + a**2 + a + 1
sz = 48
G=GF(256,name='a',repr='int',modulus=pmod)

V = rand_matrix(G, sz)
K = rand_matrix(G, sz)
Q = rand_matrix(G, sz)
print("--------")
print(V)
print("---------")
C = Lst2Mat(G, sz, 1, [
  0x60,    0xa9,    0x7a,    0x21,    0xb1,    0xe2,    0xb7,    0x66,
  0x1e,    0xec,    0x5f,    0x26,    0x6e,    0xd1,    0xd0,    0x6e,
  0xb7,    0xe9,    0x35,    0xe0,    0x57,    0x27,    0xae,    0x27,
  0x9d,    0xa0,    0x12,    0x13,    0x8c,    0x43,    0x4a,    0x99,
  0x37,    0xcf,    0x0b,    0x28,    0xe1,    0xdd,    0x2c,    0x03,
  0x7c,    0xa7,    0x4b,    0x55,    0x6d,    0xdd,    0x4b,    0xe9,
])

def mat2str(lst):
  slst = []
  for i in lst:
    for j in i:
      slst.append(int(str(j)))
  return bytes(slst)

print(C.transpose())
aI = (V.inverse()*C).transpose()
# print(aI)
print("---------")
for i in range(1, 256):
  gi = GN(i, G)
  sI = aI*gi
  if sI[0,0] == GN(0x48, G):
    print(mat2str(sI))

