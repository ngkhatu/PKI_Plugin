#------------------<<<<<<<<Generating Certificates for PKI using OpenSSL>>>>>>>>>>>>--------------------
# Tutorial from "http://users.dcc.uchile.cl/~pcamacho/tutorial/crypto/openssl/openssl_intro.html"


#----------------------Generate Keys----------------------------------------------
# Generate public/private key pairs: 1024 bits RSA key pairs- key.pem has both keys 
openssl genrsa -out key.pem 1024

# Print "key.pem" contents (will be garbled)
cat key.pem						

# See the details of "key.pem" RSA key pair
openssl rsa -in key.pem -text -noout


#----------------------------Public Key Encryption---------------------------------------------

# Encrypt the private key
openssl rsa -in key.pem -des3 -out enc-key.pem

# Extract public key from the file
openssl rsa -in key.pem -pubout -out pub-key.pem

# Encrypt file (key file should contain both keys, if just public key use -pubin)
openssl rsautl -encrypt -in <input_file> -inkey <llave> -out <output_file>
# Decrypt file (key file should contain both keys, if just public key use -pubin)
openssl rsautl -decrypt -in <input_file> -inkey <llave> -out <output_file>


#----------------------Digital Signature---------------------------------------------

# Create Digital Signature (<hash algorithms> = sha1, md5, ripemd160
openssl dgst -<hash_algorithm> -out <digest_file> <input_file>

# Check hash values of some archive files
openssl rsautl -sign -in <digest> -out <signature> -inkey <key>
# Check validity of signature
openssl rsautl -verify -in <signature> -out <digest> -inkey <key> -pubin


#-----------------------------------Create PKI Root Certificate----------------------

# Configure parameters as needed
cat /usr/lib/ssl/openssl.cnf

# Create a PKI x509 certificate which contains public/private keys (private key used to sign certificates)
openssl req -new -x509 -keyout cakey.pem -out cacert.pem #pair of keys in 'cakey' --> certificate in 'cacert'
# Export PKI certificate into DER format (DER format can be loaded into browser)
openssl x509 -in cacert.pem -outform DER -out cacert.der


#-------------------------------------Create Sub-Authority----------------------------

# User creates "User Certificate Request"
openssl req -new -keyout userkey.pem -out usercert-req.pem

# Generate the User Certificate
openssl ca -in usercert-req.pem -out usercert.pem

# To import signed certificate into browser convert it to PKCS12 format
openssl pkcs12 -export -in usercert.pem -inkey userkey.pem > usercert.p12

