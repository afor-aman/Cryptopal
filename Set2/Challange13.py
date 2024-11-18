from Crypto.Cipher import AES
import os

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

def ecb_enc(buffer, key):
    obj = AES.new(key, AES.MODE_ECB)
    return bytearray(obj.encrypt(bytes(buffer)))

def ecb_dec(buffer, key):
    obj = AES.new(key, AES.MODE_ECB)
    return bytearray(obj.decrypt(bytes(buffer)))

def rand_key(size):
	return os.urandom(size)

key = rand_key(16)

def profile_for(data):
	#data.replace("=", "").replace("&", "")
	final_str = "email="+data+"&uid=10&role=user"
	return ecb_enc(pad_pkcs7(bytearray(final_str, 'utf-8'), 16), key)

def parse(parsed_data):
	email_list = []
	for i in parsed_data:
		obj = i.split("=")
		email_list.append(obj[0]+"@"+obj[1]+".com")
	return email_list

def attack(original_email):
	encrypting_format = "email="+original_email+"&uid=10&role=user"
	print(encrypting_format)
	admin_plaintext = pad_pkcs7(b"admin", 16)
	#print(admin_plaintext)
	crafted_email = "A"*10 + admin_plaintext.decode('utf-8')
	admin_ciphertext = profile_for(crafted_email)[16:32]
	#print(pkcs7_unpad(ecb_dec(admin_ciphertext, key)))
	ecb_cut_paste = profile_for(original_email)
	new_email_ciphertext = ecb_cut_paste[:len(encrypting_format)-4] + admin_ciphertext
	final_profile = pkcs7_unpad(ecb_dec(new_email_ciphertext, key)).decode('utf-8') #With admin privilege
	print(final_profile)

def main():
	input_data = "umbre=lla"
	parsed_data = input_data.split("&")
	parsed_list = parse(parsed_data)
	for i in parsed_list:
		attack(i)
main()
