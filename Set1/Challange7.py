#Link to file.txt->https://cryptopals.com/static/challenge-data/7.txt
#Required Library pip install pycryptodome
import base64
from Crypto.Cipher import AES

def decrypt_ecb(ciphertext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	plaintext = cipher.decrypt(ciphertext)
	print(plaintext)

def main():
	key = b'YELLOW SUBMARINE'
	with open('file.txt', 'r') as f:
		ciphertext = base64.b64decode(f.read())
	decrypt_ecb(ciphertext, key)

main()
