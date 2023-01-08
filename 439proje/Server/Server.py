# Implementation of the server that receives the compressed and encrypted file from the client application. 

# All communication is encrypted in transit. 

# The secret key used for encryption is exchanged via RSA public key cryptography. 

import os
import sys
import socket

# We import the necessary modules for performing cryptography. 
# We are using RSA for public key cryptography. 
from Crypto.PublicKey import RSA

# We are using AES for performing symmetric encryption. 
from Crypto.Cipher import AES

# Since the client application used RSA with PKCS#1 for encryption we need to use the same combination for decryption. 

from Crypto.Cipher import PKCS1_OAEP

# For message authentication. 
from Crypto.Hash import HMAC, SHA256

# For uncompressing the compressed data. 
import zlib


# The maximum message size that will be read by single call to recv() function. 
MAX_MESSAGE_SIZE = 4096


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
		


# This is the function that handles the connection with a newly accepted client.
# It takes two arguments: first is the client socket and the second is a tuple containing the IP and port of the client that connected. 

def handleConnection(clientSocket, clientAddress):
	# We load the private key of the server so that the encrypted data from the client can be decrypted using the server's (our) private key. 
	private_key = None
	try:
		# We open the file containing the private key. 
		with open("ServerPrivateKey.pem", "rb") as fObj:
			data = fObj.read()
			# We process the data in the file and construct the private key object. 
			private_key = RSA.import_key(data)
			
	except:
			# An error occured while processing private key file.
			# We close the connection with the client and return. 
			clientSocket.close()
			print("[!] An error occured while loading private key from file: 'ServerPrivateKey.pem' \n")
			return 1
			
	# ---- Shared Secret KEY exchange ---- 
	
	message = clientSocket.recv(MAX_MESSAGE_SIZE)
	
	print(f"[*] Received RSA encrypted shared secret: {message} ")
	
	print("\n[*] Decrypting message... \n")
	
	# We decrypt the received message and extract the IV and AES symmetric key. 
	# We initialize the decryption system. 
	# We can decrypt this message using our private key
	cipherRSA = PKCS1_OAEP.new(private_key)
	
	# We finally decrypt the message! 
	messageDec = cipherRSA.decrypt(message)
	
	# Now we extract the symmetric 16 byte key and the 16 byte IV from the decrypted message.. 
	
	IV = messageDec[:16]          # The first sixteen bytes is the IV
	symmetricKey = messageDec[16:] # The remaining 16 bytes is the AES 128 bit key. 
	
	print("[*] Decryption complete! \n")
	
	print(f"[*] AES Key (128 bit): {symmetricKey} | Initialization Vector (IV): {IV}\n")
	
	# ---- All confidential communication with the client hereafter will be encrypted using AES in CBC mode ---
	
	# We set up the AES cipher object. 
	cipherAES = AES.new(iv=IV, key=symmetricKey, mode=AES.MODE_CBC)
	
	# We can use the "cipherAES" object to encrypt and decrypt messages. 
	
	# Now as the server, the server will send a request to provide the size of the compressed file, the name and the HMAC of the file etc... 
	clientSocket.send("SIZE_NAME_QUERY".encode("ascii"))
	# We receive the file size and name.
	recvStr = str(clientSocket.recv(MAX_MESSAGE_SIZE).decode("ascii"))
	
	# The compressed file's size and file name fields are separated by the "|" character. 
	_ = recvStr.split("|")
	compressedDataSize = int(_[0])
	fName = _[1]
	
	print(f"[*] Compressed data size: {compressedDataSize} bytes. \n[*] Filename: '{fName}'")
	
	# We make the request to get the MAC. 
	clientSocket.send("MAC_QUERY".encode("ascii"))
	# We receive the HMAC from the client. 
	messageAuthCode = clientSocket.recv(MAX_MESSAGE_SIZE)

	# The server also tells the client to start the encrypted upload. 
	clientSocket.send("START_SECURE_UPLOAD".encode("ascii"))
	
	nBytesReceived = 0
	maxSize = compressedDataSize
	# Its possible that the data is padded because of AES encryption and hence we calculate the padding applied and add it to the maximum size. 
	if compressedDataSize % 16 != 0: maxSize = compressedDataSize + (16 - (compressedDataSize % 16))
	
	print("\n")
	
	# Buffer that stores the decrypted but compressed file contents. 
	buffer = b""
	while nBytesReceived < maxSize:
		data = clientSocket.recv(MAX_MESSAGE_SIZE)
		# We decrypt the incomming data and append it to the buffer. 
		buffer += cipherAES.decrypt(data)
		
		# The count of the bytes received is updated. 
		nBytesReceived += len(data)
		
		print(f"[*]Bytes received: {nBytesReceived} bytes of {maxSize} bytes. ")
		
		
	# We take only "compressedDataSize" bytes from the decrypted data to remove AES padding if there were any.
	buffer = buffer[:compressedDataSize]
	
	print(f"[*] Received file name: {fName}")
	print(f"[*] Decrypted data size: {len(buffer)} bytes. ")
	# Now we must uncompress the data... 
	buffer = zlib.decompress(buffer)
	
	print(f"[*] Uncompressed data size (actual file size): {len(buffer)} bytes. ")
	
	# We save the data in a temporary file to compute the HMAC
	
	if os.path.exists("TEMPORARY_RECEIVED.bin"): os.remove("TEMPORARY_RECEIVED.bin")
	
	with open("TEMPORARY_RECEIVED.bin", "wb") as fObj: fObj.write(buffer)
	
	# Now we calculate the HMAC of the received data. 
	calculatedMAC = getHMAC("TEMPORARY_RECEIVED.bin", symmetricKey)
	
	# If this calculated MAC is equal to the received HMAC SHA256 then verification is successfull and we inform the client of the same. 
	if calculatedMAC == messageAuthCode:
		# Success! The data is verified and we can save it properly ! 
		print("[*] Successfully verified data ! ")
		clientSocket.send("VERIFICATION_SUCCESS".encode("ascii"))
		os.rename("TEMPORARY_RECEIVED.bin", fName)
		
	else:
		print("[!] ERROR: Unable to verify the authenticity of received data! Discarding it... !")
		clientSocket.send("VERIFICATION_FAILED".encode("ascii"))
		
	# We remove the temporary file as its no longer needed ! 
	if os.path.exists("TEMPORARY_RECEIVED.bin"): os.remove("TEMPORARY_RECEIVED.bin")
	
	print(f"[*] Finished handling client with address: {clientAddress} \n")
	
# The main entry point of our server. 
def main():
	
	
	print("********* SERVER APPLICATION *********")
	
	# First we check if the user has provided sufficient number of command line arguments required for setting up the server. 
	# The server expects the user to provide its IP address and port. 
	if len(sys.argv) != 3:
		print("Usage: {0} <IP> <port>\n".format(sys.argv[0]))
		return 1
	
	# Now we initialize the server!
	print("[*] Initializing... ")

	# We set up the socket that the server uses for listening and accepting connections from the clients. 
	# We are using TCP sockets here. 
	serverSocket = socket.socket(family = socket.AF_INET, type = socket.SOCK_STREAM)
	
	# Now we need to bind the socket to the user specified IP address and port number.
	
	serverSocket.bind((sys.argv[1], int(sys.argv[2])))
	
	# We set up the TCP server socket for listening. 
	serverSocket.listen(5)
	
	# Now we enter into the service loop of the server, where the server accepts incomming connections from the client and receives files from them. 
	print("[*] Server set up and ready to accept connections...")
	while True:
		
		# The server blocks to accept a new connection. 
		clientSocket, clientAddress = serverSocket.accept()
		
		# We print some useful information on the server terminal.
		print(f"[*] Accepted connection from client with address: {clientAddress} . . .")
		
		# We call the function that handles the connection with the client application. 
		handleConnection(clientSocket, clientAddress)
		
		
		# The connection with the client is closed after its handled successfully. 
		clientSocket.close()
	

	# We close the server socket when done. 
	serverSocket.close()
	

if __name__ == "__main__":
	main()


