#created by JOYBOY

import re

all_result = list()

def have_pattern():
	pattern = input("\nMacthed Pattern or Enter [Default : No Pattern]: ")
	return pattern

def xor_decrypt(ciphertext, key):
    decrypted = []
    for char in ciphertext:
        decrypted_char = chr(ord(char) ^ key)
        decrypted.append(decrypted_char)
    return ''.join(decrypted)

def brute_force_decrypt(ciphertext):
    for key in range(256):  # Try all possible keys (0 to 255)
        decrypted_text = xor_decrypt(ciphertext, key)
        all_result.append(hex(key))
        all_result.append(decrypted_text)


while(True):
	enc = input("\nEnter Encryption Message : ")
	if len(enc)==0:
		print("\nMessage can't be Empty!")
	else:
		break;


u_pattern = have_pattern()
brute_force_decrypt(enc)
flag = False
if len(u_pattern) != 0:
	for i in range(1,len(all_result),2):
		if re.search(u_pattern.lower(), all_result[i].lower()):
			print(f"[+] Key : {all_result[i-1]} , Decrypted Message : {all_result[i]}")
			flag = True
	if not(flag):
		print("Pattern NOT Found!")	
else:
	for i in range(1,len(all_result),2):
		print(f"[+] Key : {all_result[i-1]} , Decrypted Message : {all_result[i]}")	



