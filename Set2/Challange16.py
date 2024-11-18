from Crypto.Cipher import AES
import random
import os

def xor(b1, b2):
	b = bytearray(len(b1))
	for i in range(len(b2)):
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

key = rand_bytes(16)
iv = rand_bytes(16)

def append_bytes(plaintext):
	after = random.randint(5,10)
	before = random.randint(5,10)
	new_plaintext = b''

	after = rand_bytes(after)
	before = rand_bytes(before)

	new_plaintext = before + plaintext + after
	return new_plaintext



def bit_flip_attack():
	first_blk = "0"*16
	second_blk = "AadminAtrueA"
	plaintext = first_blk + second_blk
	
	offset = 32 #Prefix length is 32 bytes it means(2-block)
	ciphertext = enc_oracle(plaintext)
	# Change the first byte in first_block 'A' so we change the first byte in
    # second_block to be ';'
	res = bytes(xor(bytearray(chr(ciphertext[offset]), 'utf-8'), xor(bytearray("A", 'utf-8'), bytearray(";", 'utf-8'))))
	ciphertext[offset] = int.from_bytes(res, "little")	#to convert bytes to int

	res = bytes(xor(bytearray(chr(ciphertext[offset+6]), 'utf-8'), xor(bytearray("A", 'utf-8'), bytearray("=", 'utf-8'))))
	ciphertext[offset+6] = int.from_bytes(res, "little")	#to convert bytes to int

	res = bytes(xor(bytearray(chr(ciphertext[offset+11]), 'utf-8'), xor(bytearray("A", 'utf-8'), bytearray(";", 'utf-8'))))
	ciphertext[offset+11] = int.from_bytes(res, "little")	#to convert bytes to int

	dec = cbc_dec(ciphertext, iv, key)
	if b";admin=true;" in dec:
		print("cracked: ", dec)
	else:
		print("try again")
	


def enc_oracle(input_data):
	input_data = input_data.replace(";", "%3b").replace("=", "%3d")
	plaintext = bytearray("comment1=cooking%20MCs;userdata=" + input_data + ";comment2=%20like%20a%20pound%20of%20bacon", 'utf-8')
	return cbc_enc(plaintext, iv, key)
	
bit_flip_attack()
