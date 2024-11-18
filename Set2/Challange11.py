from collections import defaultdict
from Crypto.Cipher import AES
import random
import os

def xor(b1, b2):
    b = bytearray(len(b1))
    for i in range(len(b1)):
        b[i] = b1[i] ^ b2[i]
    return b

def pkcs7_pad(msg, blk):
    pad_len = blk - (len(msg)%blk)
    return msg + bytes([pad_len])*pad_len

def pkcs7_unpad(msg):
	padding = msg[-1]
	length = len(msg)

	for i in range(length-1, length-padding-1, -1):
		if msg[i] != msg[-1]:
			return msg
	unpadded_msg = bytearray()
	unpadded_msg[:] = msg[:-padding]
	return unpadded_msg

def ecb_enc(buffer, key):
    obj = AES.new(key, AES.MODE_ECB)
    return bytearray(obj.encrypt(bytes(buffer)))

def ecb_dec(buffer, key):
    obj = AES.new(key, AES.MODE_ECB)
    return bytearray(obj.decrypt(bytes(buffer)))

def cbc_enc(msg, iv, key):
	AES_blk_size = AES.block_size
	plaintext = pkcs7_pad(msg, AES_blk_size)
	ciphertext = bytearray(len(plaintext))
	previous_blk = iv
	plaintext_len = len(plaintext)
	for i in range(0, plaintext_len, AES_blk_size):
		ciphertext[i:i+AES_blk_size] = ecb_enc(xor(plaintext[i:i+AES_blk_size], previous_blk), key)
		previous_blk = ciphertext[i:i+AES_blk_size]
	return ciphertext

def cbc_dec(ciphertext, iv, key):
    AES_blk_size = AES.block_size
    ciphertext_len = len(ciphertext)
    plaintext = bytearray(ciphertext_len)
    previous_blk = iv
    for i in range(0, ciphertext_len, AES_blk_size):
        plaintext[i:i+AES_blk_size] = xor(ecb_dec(ciphertext[i:i+AES_blk_size], key), previous_blk)
        previous_blk = ciphertext[i:i+AES_blk_size]
    return pkcs7_unpad(plaintext)

def rand_bytes(s):
	randbytes = os.urandom(s)
	return randbytes

def append_bytes(plaintext):
	after = random.randint(5,10)
	before = random.randint(5,10)
	new_plaintext = b''

	after = rand_bytes(after)
	before = rand_bytes(before)

	#print("After->", after)
	#print("Before->", before)

	new_plaintext = before + plaintext + after
	return new_plaintext

def choose_enc_mode():
	mode = random.randint(0,1)
	if mode==0:
		return "ECB"
	else:
		return "CBC"

def Is_ECB(ciphertext, blk):
	reps = defaultdict(lambda: -1)
	for i in range(0, len(ciphertext), blk):
		block = bytes(ciphertext[i:i+blk])
		reps[block]+=1
	return sum(reps.values()) > 0


def encrypt_and_detect_oracle(plaintext):
	choosed_mode = choose_enc_mode()
	key = rand_bytes(16)
	if choosed_mode == "ECB":
		msg = pkcs7_pad(append_bytes(plaintext), 16)
		enc = ecb_enc(msg, key)
		print("Encrypted: ", enc)
		if Is_ECB(enc, AES.block_size):
			print("Its is encrypted using ECB mode")
		#dec = pkcs7_unpad(ecb_dec(enc, key))
		#print("Decrypted: ", dec)

	else:
		iv = rand_bytes(16)
		enc = cbc_enc(append_bytes(plaintext), iv, key)
		print("Encrypted: ", enc)
		if not Is_ECB(enc, AES.block_size):
			print("Not Encrypted using ECB mode")
		#dec = cbc_dec(enc, iv, key)
		#print("Decrypted: ", dec)

def main():
	encrypt_and_detect_oracle(bytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 'utf-8'))

main()
