
# Part 1
import os

SRNaryPath = "./distribution/code20160401"
os.chdir(SRNaryPath)
os.system('javac -cp ".;..\\choco\\choco-solver-2.1.5.jar;" SRNary.java SRN.java SR.java SMSRInstance.java')
PuzzlePath = "puzzle.txt"
OutputPath = "output.txt"
os.system(f'java -cp ".;..\choco\choco-solver-2.1.5.jar;" SRNary {PuzzlePath} all > ${OutputPath}')

with open(OutputPath, 'r') as f:
  lines = [eval('['+line.replace(') (', '),(')+']') for line in f.readlines() if line.startswith('(')]


# Part 2
import string 
from base64 import b64decode
from Crypto.Cipher import AES

def decode(ct, selected):
  print(selected)
  b64table = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  keyb64 = bytes([b64table[selected[i^3]-1] for i in range(len(selected))])
  key = b64decode(keyb64)

  from Crypto.Cipher import AES
  pt = b""
  for i in range(0,len(ct),16):
    ckey = key[i:i+16]
    cipher = AES.new(ckey, AES.MODE_ECB)
    cpt = cipher.decrypt(ct[i:i+16])
    pt += cpt
  print(b"HFCTF{"+pt+b"}")

ct = bytes([0xb1, 0xac, 0x12, 0xc5, 0xb5, 0x74, 0xb3, 0x72, 0x01, 0xe8, 0xc1, 0x0b, 0x30, 0x43, 0x54, 0x87, 0x5b, 0x92, 0xda, 0x37, 0x30, 0xa5, 0x07, 0x97, 0xf9, 0xbc, 0x8a, 0xdf, 0x7e, 0x05, 0x26, 0x95, 0xcb, 0x99, 0xcb, 0xef, 0x46, 0xc4, 0x11, 0x5b, 0xb6, 0x3f, 0xb3, 0xb1, 0x2a, 0x35, 0x03, 0xc7])
for line in lines:
  ans = [0 for i in range(65)]
  for i,j in  line:
    ans[i] = j
    ans[j] = i
  decode(ct, ans[1:])


