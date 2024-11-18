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

def main():
    buffer = bytearray("YELLOW SUBMARINE", 'utf-8')
    blk_size = 20
    padded = pkcs7_pad(buffer, blk_size)
    print("After Padded->", padded)
    print("After Unpadding->", pkcs7_unpad(padded))
    
main()
