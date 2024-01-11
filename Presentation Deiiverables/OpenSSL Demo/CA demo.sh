#-----------------------------------Create PKI Root Certificate----------------------

# Configure parameters as needed
#cat /usr/lib/ssl/openssl.cnf

# Generate public/private key pairs: 1024 bits RSA key pairs- key.pem has both keys 
openssl genrsa -out NCSU_key_pair.pem 1024

# Create a PKI x509 certificate which contains public/private keys (private key used to sign certificates)
# pair of keys in 'cakey' --> certificate in 'cacert'
# demo uses PEM pass phrase: ncsu123
openssl req -new -x509 -keyout NCSU_key_pair.pem -out NCSU_root_cert.pem

# Export PKI certificate into DER format (DER format can be loaded into browser)
#openssl x509 -in cacert.pem -outform DER -out cacert.der


#-------------------------------------Create Sub-Authority----------------------------

openssl genrsa -out Alice_key_pair.pem 1024
# User creates "User Certificate Request"
openssl req -new -keyout Alice_key_pair.pem -out Alice_usercert-req.pem


# Edit .cnf file with CA info
# Generate the User Certificate
openssl ca -in Alice_usercert-req.pem -out Alice_usercert.pem

# To import signed certificate into browser convert it to PKCS12 format
openssl pkcs12 -export -in usercert.pem -inkey userkey.pem > usercert.p12

