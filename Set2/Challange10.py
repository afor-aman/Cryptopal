from Crypto.Cipher import AES
import base64

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

def ebc_enc(buffer, key):
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
		ciphertext[i:i+AES_blk_size] = ebc_enc(xor(plaintext[i:i+AES_blk_size], previous_blk), key)
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

def main():
    #plaintext = bytearray("Hello my name is Michael", 'utf-8')
    iv = bytearray(b'\x00' * AES.block_size)
    key = "YELLOW SUBMARINE"
    #enc = cbc_enc(plaintext, iv, key)
    #print("After Encryption->", enc)
    ciphertext = bytearray("".join(list(open("file.txt", "r"))), 'utf-8')
    ciphertext = base64.b64decode(ciphertext)
    dec = cbc_dec(ciphertext, iv, key)
    print("After Decryption->", dec)
    
main()
