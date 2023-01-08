# Python script for generating the public & private key *.pem files for our server. 
# We are using the PyCryptodome package for generating the RSA keys securely. 

# When this script is run it will generate two files ending with ".pem" extension. 
# The first file will be called "ServerPublicKey.pem" (the public key) and the second output file is called "ServerPrivateKey.pem" (the private key). 

# NOTE: The server must keep the "ServerPrivateKey.pem" file secret, since its the private key of the server. 

from Crypto.PublicKey import RSA

# The main() function of the key generation script. 
def main():
	
	print("********* SERVER PUBLIC & PRIVATE KEY GENERATOR *********\n")
	
	print("\n[*] Generating 2048 bit RSA keys... \n")
	
	keys = RSA.generate(2048)
	
	# We write the public key to "ServerPublicKey.pem"
	with open("ServerPublicKey.pem", "wb") as fObj:
		fObj.write(keys.publickey().exportKey())
		
	# We write the private keys to "ServerPrivateKey.pem"
	with open("ServerPrivateKey.pem", "wb") as fObj:
		fObj.write(keys.exportKey())
		
	print("\n[*] Successfully completed RSA 2048 key pair generation... \n")
		
	
	return 0
	
	
if __name__ == "__main__":
	main()