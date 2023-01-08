# Implementation of the client application that sends the file to the server. 
# The client application compresses the file and also encrypts the file contents before sending it to the server. 

# This client application knows the public key of the server, uses it to encrypt a randomly generated key that will be used for encrypting the data using AES block cipher in CBC mode. 

# This encrypted key is sent to the server.
# The server uses its private key to decrypt and retrieve the key to decrypt the data and hence obtain the compressed version of the file, which will be subsequently uncompressed to get the actual file. 

# Authenticity of the file contents is provided by HMAC with SHA256

# For networking we are using the standard socket library. 
import socket
import os
import sys

# We are using PyCryptodome for using the cryptographic algorithms. 
# We are using RSA for establishing the shared secret key between our client and server. 
from Crypto.PublicKey import RSA

# We are using AES (Advanced Encryption Standard) cipher in CBC mode for encrypting the compressed ZIP file. 
from Crypto.Cipher import AES

# We are using RSA with PKCS#1 padding for encrypting our shared secret key & IV
from Crypto.Cipher import PKCS1_OAEP


# We use random byte generators designed for cryptography use. 
from Crypto.Random import get_random_bytes

# We need to perform message authentication... 
from Crypto.Hash import HMAC, SHA256

# For compressing data. 
import zlib


# Helper function that helps in calculating the HMAC of a file provided its file path & key for performing HMAC. 
def getHMAC(filePath, symmetricKey):
	# We calculate the HMAC SHA256 of the file. 
	hmac = HMAC.new(symmetricKey, digestmod=SHA256)
	
	with open(filePath, "rb") as fObj:
		while True:
			data = fObj.read(4096)
			if len(data) == 0:
				# When file becomes empty we break the loop. 
				break
			hmac.update(data)
			
	# We finally return the calculated hmac as a byte string. 
	return hmac.digest()
		

# Main entry point of the client application. 
def main():
	
	print("********* CLIENT APPLICATION *********")
	# We read the IP address and port of the public server to connect from the user. 
	ip_address = input("Please provide IP address of the public server: ")
	
	port = int(input("Please provide port of the server: "))
	
	public_key_path = input("Please provide path to *.pem file containing the public key of server: ")
	
	public_key = None
	# We parse the public key from the provided path to the public key file. 
	try:
		with open(public_key_path, "rb") as fObj:
			# We read the full file...
			data = fObj.read()
			
			# Now we construct the public key object from the data parsed from the file. 
			
			public_key = RSA.import_key(data)
			
	except:
		# An error occured while processing the user specified file... 
		# We print an error message and exit.
		print(f"\n[!] An error occured while processing the file expected to contain server public key: '{public_key_path}' \n")
		return 1
	
		
	# We have successfully parsed the public key of the server. 	
	print(f"[*] Successfully parsed server's public key, its contents are: {public_key.exportKey()}\n")
    
	# Now we try to establish connection to the public server. 
	print(f"[*] Connecting to: ({ip_address}, {port})\n")
	
	# First we create the TCP socket object for communicating with the server. 
	clientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
	
	# We connect() to the user provided IP and port. 
	clientSocket.connect((ip_address, port))
	
	# We generate the shared secret key that will be used for encrypting the file that we will send to the server over the network. 
	# We generate a 16 byte key because we are using AES 128 for encrypting our data. 
	symmetricKey = get_random_bytes(16)
	
	# We require a 16 byte IV (initialization vector) because we are performing AES in CBC (cipher block chaining) mode. 
	IV = get_random_bytes(16)
	
	# Since both the IV and key are important for encrypting and decrypting. 
	# The server must know of both their values to decrypt the encrypted file we will be sending it. 
	
	# So we encrypt this information (the key and IV) using the server's public key and send it over the network. 
	
	#------ Shared secret key and IV exchange ------ #
	# This is our shared secret. 
	# This is the FIRST piece of secret info shared with the server. 
	message = IV + symmetricKey
	
	print(f"[*] Shared secret IV: {IV} | Symmetric Key: {symmetricKey}")
	
	# The server knows the format of the message and it can parse out the IV & symmetricKey separately because they both are 16 bytes each. 
	# We encrypt the above message with the server's public key (whicj we already loaded into memory)
	cipherRSA = PKCS1_OAEP.new(public_key)
	messageEnc = cipherRSA.encrypt(message)
	
	# We have encrypted our shared secret. 
	# Now we send this encrypted data to the server! 
	# The server can successfully decrypt it with the server's secret private key. 
	
	print(f"\n[*] Sending shared secret (encrypted using RSA): {messageEnc}\n")
	
	clientSocket.send(messageEnc)
	
	# Now we will ask the user to provide the path to the file that should be sent to the server. 
	filePath = input("[*] Please provide path to file to be sent to server: ")
	
	if not os.path.exists(filePath):
		# We check if the path exists.
		# If not we simply print an error message & exit. 
		print(f"[!] Unable to open: '{filePath}' \n")
		clientSocket.close()
		return 2
		
		
	
	# We will immediately calculate the HMAC of the file contents. 
	# This helps the server in performing message authentication...
	#----- Message authentication code calculated----- #
	messageAuthCode = getHMAC(filePath, symmetricKey)
	
	print(f"[*] HMAC - SHA256 (Message authentication code) of the above file is: {messageAuthCode}\n")
	
	# We read the file fully into memory. 
	buffer = b""
	
	with open(filePath, "rb") as fObj:
		
		while True:
			data = fObj.read(4096)
			
			if len(data) == 0:
				# When there is nothing left to read, we break out.
				break
			buffer += data
			
	
	fName = os.path.basename(filePath)
	print(f"\n[*] Size of the provided file: '{fName}' is: {len(buffer)} bytes.\n")
	
	# ---- This is the Data compression part ----
	# Now we compress the above buffer using zlib ! 
	compressedBuffer = zlib.compress(buffer)
	
	print(f"\n[*] Size of the compressed buffer is: {len(compressedBuffer)} bytes. ")
	
	# Since we compress the data we report the data savings to the user.
	print(f"[*] Data savings: {(len(buffer) - len(compressedBuffer))/len(buffer) * 100.0} %")
	
	
	# Now we wait for the server to ask us to send the compressed file size as well as the name of the original file. 
	message = clientSocket.recv(4096).decode("ascii")
	
	if message == "SIZE_NAME_QUERY":
		# We send the size of the compressed file data to the server. 
		# We also send the file name so server can save the file in its directory. 
		# The size and name are separated by "|" character. 
		# Note: This is not intended to be a secret message. 
		clientSocket.send((str(len(compressedBuffer)) + "|" + fName).encode("ascii"))
		
	# We receive the request from the server for the message authentication code. 
	message = clientSocket.recv(4096).decode("ascii")
	
	if message == "MAC_QUERY":
		# We send our calculated HMAC to the server. 
		clientSocket.send(messageAuthCode)
		
	# We receive the request from the server to proceed with secure upload. 
	message = clientSocket.recv(4096).decode("ascii")
	
	if message != "START_SECURE_UPLOAD":
		# If that is not the message then its an error. 
		print("[!] Error with communication protocol ! ")
		clientSocket.close()
		return 1
		
	# We proceed to encrypt and upload the compressed file. 
	cipherAES = AES.new(iv=IV, key=symmetricKey, mode=AES.MODE_CBC)
	
	# Variable to keep track to slice the compressed buffer. 
	pos = 0
	# We send the data in blocks of 4096 bytes.
	
	# --- The file data as a whole is the second confidiential piece of information send to the server ----
	while True:
		data = compressedBuffer[pos:pos+4096]
		size = len(data)
		
		if size == 0:
			# All the data is sent! 
			break
		
		# Since the block size of AES is 16 bytes, the data must be padded if the length of the data is not a multiple of 16 bytes.
		if size%16 != 0:
			data += b"\x00" * (16 - (size%16))
			
		# Finally we encrypt this data.
		 
		data = cipherAES.encrypt(data)
		
		# We use the send() socket API to send the encrypted data to the server. 
		clientSocket.send(data)
		# The position is advanced. 
		pos += size
		
		
	# Since we are the client appication we wait for the response from the server.
	
	serverResponse = clientSocket.recv(4096).decode("ascii")
	
	if serverResponse == "VERIFICATION_SUCCESS":
		print("[*] Success the file was uploaded correctly and server was able to verify its authenticity!!! ")
	else:
		print("[!] An ERROR occured during the communication and data cannot be verified by server! ")
	
	

if __name__ == "__main__":
	main()




