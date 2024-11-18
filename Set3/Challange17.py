#https://crypto.stackexchange.com/questions/3714/how-does-a-padding-oracle-attack-work
#https://perso.heavyberry.com/articles/2015-12/cryptopals3
#https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth
#https://robertheaton.com/2013/07/29/padding-oracle-attack/

from Crypto.Cipher import AES
import base64
import random
import os

def rand_bytes(size):
	return os.urandom(size)

key = rand_bytes(16)
iv = rand_bytes(16)

str_lst = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

s = base64.b64decode(random.choice(str_lst))
print(s)

def xor(b1, b2):
    b = bytearray(len(b1))
    for i in range(len(b1)):
        b[i] = b1[i] ^ b2[i]
    return b

def pkcs7_pad(msg, blk):
    pad_len = blk - (len(msg)%blk)
    return msg + bytes([pad_len])*pad_len

def pkcs7_padding_validation(byte_string: bytes)->bytes:
    last_byte = byte_string[-1]
    if last_byte > len(byte_string):
        return False
    for i in range(last_byte, 0, -1):
        if byte_string[-i] != last_byte:
            return False
    return True

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
    return plaintext

def cbc_padding_oracle_attack(ciphertext):
	#Here we are only decrypting for second last blk
	#for decrypting second last blk we need third last blk
	#for decrypting third last blk we need fourth last blk and so on
	#we can decrypt all blk in similar manner except first blk
	#To decrypt first blk we need iv

	c1 = bytearray(b"\x00"*16)
	i2 = bytearray(b"\x00"*16)

	blk_lst = []

	#spliting the ciphertext into blks
	for i in range(0, len(ciphertext), 16):
		blk_lst.append(ciphertext[i:i+16])
	
	byte = 1	#valid padding byte
	
	#we are iterating from backwards
	for j in range(15, -1, -1):	#to obtain every byte in ciphertext we change every byte of c1
		for i in range(0, 255):	#all possible 256 values
			c1[j] = i
			mk_blk = c1 + blk_lst[-2]
			deced = cbc_dec(mk_blk, iv, key)

			#if padding is valid
			if pkcs7_padding_validation(deced):
				#print(i^c1[j]^0x01)
				break
		
		##--IN ITERATION 1--##
		#store the byte ^ i(our guessed byte) into i2[j]
		#let say i = 46 gives us valid padding for very first iteration	(valid padidng byte will be 0x01)
		#therefore i2[15] = 46 ^ byte(which is 1) => 47
		##--IN ITERATION 2--##
		#now in second iteration
		#let say i = 12 gives us valid padding for second iteration	(valid padidng byte will be 0x02)
		#therefore i2[14] = 12 ^ byte(which is 2) => 14

		#And so on for other bytes in blk

		i2[j] = i ^ byte

		#print("I->{}-".format(hex(i)), end="")
		#print(hex(i2[j]), end="-")
		#print(chr(blk_lst[-3][15] ^ i2[-1]))

		##--IN ITERATION 1--##
		#now we have valid byte for last byte of our ciphertext blk
		#setting c1 for next iteration c1[j-1] or c[14]
		#now the valid padding occurs when byte c[14] will give 2
		##--IN ITERATION 2--##
		#now we have valid byte for	second last byte of our ciphertext blk
		#setting c1 for next iteration c1[j-2] or c[13]
		#now the valid padding occurs when byte c[13] will give 3
		
		#And so on for other bytes in blk

		byte+=1	
		
		##--IN ITERATION 1--##
		#first set c1[15] to byte that give 2 at oracle when decrypting by c1[15] = i2[15](47) ^ 2 => 45
		#and run for c1[j-1] or c[14] for every i
		##--IN ITERATION 2--##
		#first set c1[14] & c[15] to byte that give 3 at oracle when decrypting by c1[14] = i2[14](14) ^ 3 => 13		c1[15] = i2[15](47) ^ 3 => 44
		#and run for c1[j-2] or c[13] for every i

		#And so on for other bytes in blk

		for k in range(j,16):
			c1[k] = i2[k] ^ byte
			#print(hex(c1[k]), end="-")
			#print("At k->{}".format(k))
		#print()
			#print(c1[k])

	print(xor(blk_lst[-3],i2))



def cbc_padding_oracle_enc():
	cbc_padding_oracle_attack(cbc_enc(s, iv, key))


cbc_padding_oracle_enc()
