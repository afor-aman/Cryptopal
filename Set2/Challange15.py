def pkcs7_unpad(msg):
	padding = msg[-1]
	length = len(msg)
	for i in range(length-1, length-padding-1, -1):
		if msg[i] != msg[-1]:
			return "Not PKCS7 Padded"
	unpadded_msg = bytearray()
	unpadded_msg[:] = msg[:-padding]
	return unpadded_msg



print(pkcs7_unpad(bytearray("ICE ICE BABY\x04\x04\x04\x03", 'utf-8')))
