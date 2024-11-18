from collections import defaultdict
from Crypto.Cipher import AES
import base64
import random
import os

unknown_string = bytearray(base64.b64decode(
        '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''
    ))

def pkcs7_unpad(msg):
	padding = msg[-1]
	length = len(msg)

	for i in range(length-1, length-padding-1, -1):
		if msg[i] != msg[-1]:
			return msg
	unpadded_msg = bytearray()
	unpadded_msg[:] = msg[:-padding]
	return unpadded_msg

def pad_pkcs7(msg, blk):
    pad_len = blk - (len(msg)%blk)
    return msg + bytes([pad_len])*pad_len

def random_key(length):
    return os.urandom(length)

rand_size = random.randint(0,255)
rand_bytes = random_key(rand_size)
key = random_key(16)

def ecb_enc(buffer, key):
    obj = AES.new(key, AES.MODE_ECB)
    return bytearray(obj.encrypt(bytes(buffer)))

def encryption_oracle(data):
    
    plaintext = pad_pkcs7(
        rand_bytes + data + unknown_string,
        AES.block_size,
    )
    return ecb_enc(plaintext, key)

def get_block_size():
    ciphertext_length = len(encryption_oracle(bytearray()))
    i = 1
    while True:
        data = bytearray("A" * i, 'utf-8')
        new_ciphertext_length = len(encryption_oracle(data))
        if ciphertext_length != new_ciphertext_length:
            return new_ciphertext_length - ciphertext_length
        i += 1

def Is_ECB(ciphertext, blk):
	reps = defaultdict(lambda: -1)
	for i in range(0, len(ciphertext), blk):
		block = bytes(ciphertext[i:i+blk])
		reps[block]+=1
	return sum(reps.values()) > 0

def get_unknown_string_size():
    ciphertext_length = len(encryption_oracle(bytearray()))
    i = 1
    while True:
        data = bytearray("A" * i, 'utf-8')
        new_ciphertext_length = len(encryption_oracle(data))
        if ciphertext_length != new_ciphertext_length:
            return new_ciphertext_length - i
        i += 1

def get_unknown_string(index, padding_size):
	block_size = get_block_size()
	unknown_string_size = get_unknown_string_size()
	unknown_string = bytearray()
	
	unknown_string_size_rounded = int((unknown_string_size / block_size) + 1) * block_size
	for i in range(unknown_string_size_rounded - 1, 0, -1):
		d1 = bytearray("A" * (i+padding_size), 'utf-8')
		c1 = encryption_oracle(d1)[index:unknown_string_size_rounded+index]
		for c in range(256):
			d2 = d1[:] + unknown_string + bytes(chr(c), 'utf-8')
			c2 = encryption_oracle(d2)[index:unknown_string_size_rounded+index]
			if c1 == c2:
				unknown_string += bytes(chr(c), 'utf-8')
				break
	return unknown_string


def get_prefix_size():
	reps = 10
	buf = 'YELLOW SUBMARINE'

	for prefix_padding_size in range(16):
		prepend_bytes_size = bytearray("A"*prefix_padding_size, 'utf-8')
		cipher = encryption_oracle(prepend_bytes_size+bytearray(buf*reps, 'utf-8'))
		prev_blk = count = index = None
		for i in range(0, len(cipher), 16):
			blk = cipher[i:i+16]
			if blk == prev_blk:
				count+=1
			else:
				index = i
				count = 1
				prev_blk = blk
			
			if count == reps:
				return index, prefix_padding_size


index, padding_size = get_prefix_size()
print (pkcs7_unpad(get_unknown_string(index, padding_size)).decode('utf-8'))


