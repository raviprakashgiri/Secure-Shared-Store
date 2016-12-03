#!/bin/bash

#Define directory and file location 
caPath="./demoCA/"
certPath="./demoCA/newcerts/"
caKey="../cert/ca.key"
caCRT="../cert/ca.crt"
caPEM="../cert/ca.pem"
#serverKey="../cert/server/server.key"
serverKey="../cert/server.key"
serverCSR="../cert/server.csr"
serverCRT="../cert/server.crt"
serverPEM="../cert/server.pem"
user1Key="../cert/user1.key"
user1CSR="../cert/user1.csr"
user1CRT="../cert/user1.crt"
user1PEM="../cert/user1.pem"
user2Key="../cert/user2.key"
user2CSR="../cert/user2.csr"
user2CRT="../cert/user2.crt"
user2PEM="../cert/user2.pem"
user3Key="../cert/user3.key"
user3CSR="../cert/user3.csr"
user3CRT="../cert/user3.crt"
user3PEM="../cert/user3.pem"
clientKey="../cert/client.key"
clientCSR="../cert/client.csr"
clientCRT="../cert/client.crt"
clientPEM="../cert/client.pem"

#Required
commonname="CA"
sercommonname="Server"
clicommonname="Client"
us1commonname="User1"
us2commonname="User2"
us3commonname="User3"

#Change to your details
country=US
state=Georgia
city=Atlanta
organization=GATech
organizationalunit=MASTER
email=gatech@gatech.edu

#Optional
password=mypassword

if [ ! -d "$caPath" ]; then  
    mkdir "$caPath"
    mkdir "$certPath"
    touch "./demoCA/index.txt"
    touch "./demoCA/serial"
    echo 01 > "./demoCA/serial"
fi

#CA Key and Certificate Generation Process

if [ ! -f "$caKey" ]; then
    #Generate a key
    echo "Generating key request for CA"
    openssl genrsa -des3 -passout pass:$password -out $caKey 2048 -noout

    #Remove passphrase from the key. Comment the line out to keep the passphrase
    echo "Removing passphrase from key"
    openssl rsa -in $caKey -passin pass:$password -out $caKey  
fi

if [ ! -f "$caCRT" ]; then  
    #Generate CA Certificate
    echo "Generate CA Certificate"
    openssl req -new -x509 -key $caKey -out $caCRT -days 3650 -subj "/C=$country/ST=$state/L=$city/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
fi

if [ ! -f "$caPEM" ]; then  
    #Generate PEM Certificate
    echo "Generate PEM Certificate"
    cat $caCRT $caKey > $caPEM
fi

#Server Key and Certificate Generation Process

if [ ! -f "$serverKey" ]; then
    #Generate a key
    echo "Generating key request for Server"
    openssl genrsa -des3 -passout pass:$password -out $serverKey 2048 -noout

    #Remove passphrase from the key. Comment the line out to keep the passphrase
    echo "Removing passphrase from key"
    openssl rsa -in $serverKey -passin pass:$password -out $serverKey  
fi

if [ ! -f "$serverCSR" ]; then  
    #Generate Server CSR File
    echo "Generate Server CSR"
    openssl req -new -key $serverKey -out $serverCSR -days 3650 -subj "/C=$country/ST=$state/L=$city/O=$organization/OU=$organizationalunit/CN=$sercommonname/emailAddress=$email"
fi

if [ ! -f "$serverCRT" ]; then  
    #Generate Server CSR File
    echo "Generate Server Certificate Signed by CA"
    echo -e 'y\ny' | openssl ca -in $serverCSR -out $serverCRT -cert $caCRT -keyfile $caKey
fi

if [ ! -f "$serverPEM" ]; then  
    #Generate PEM Certificate
    echo "Generate Server PEM Certificate"
    cat $serverCRT $serverKey > $serverPEM
fi

#User1 Key and Certificate Generation Process
if [ ! -f "$user1Key" ]; then
    #Generate a key
    echo "Generating key request for User1"
    openssl genrsa -des3 -passout pass:$password -out $user1Key 2048 -noout

    #Remove passphrase from the key. Comment the line out to keep the passphrase
    echo "Removing passphrase from key"
    openssl rsa -in $user1Key -passin pass:$password -out $user1Key  
fi

if [ ! -f "$user1CSR" ]; then  
    #Generate User1 CSR File
    echo "Generate User1 CSR"
    openssl req -new -key $user1Key -out $user1CSR -days 3650 -subj "/C=$country/ST=$state/L=$city/O=$organization/OU=$organizationalunit/CN=$us1commonname/emailAddress=$email"
fi

if [ ! -f "$user1CRT" ]; then  
    #Generate User1 CRT File
    echo "Generate User1 Certificate Signed by CA"
    echo -e 'y\ny' | openssl ca -in $user1CSR -out $user1CRT -cert $caCRT -keyfile $caKey
fi

if [ ! -f "$user1PEM" ]; then  
    #Generate PEM Certificate
    echo "Generate User1 PEM Certificate"
    cat $user1CRT $user1Key > $user1PEM
fi

#User2 Key and Certificate Generation Process
if [ ! -f "$user2Key" ]; then
    #Generate a key
    echo "Generating key request for User2"
    openssl genrsa -des3 -passout pass:$password -out $user2Key 2048 -noout

    #Remove passphrase from the key. Comment the line out to keep the passphrase
    echo "Removing passphrase from key"
    openssl rsa -in $user2Key -passin pass:$password -out $user2Key  
fi

if [ ! -f "$user2CSR" ]; then  
    #Generate User2 CSR File
    echo "Generate User2 CSR"
    openssl req -new -key $user2Key -out $user2CSR -days 3650 -subj "/C=$country/ST=$state/L=$city/O=$organization/OU=$organizationalunit/CN=$us2commonname/emailAddress=$email"
fi

if [ ! -f "$user2CRT" ]; then  
    #Generate User2 CRT File
    echo "Generate User2 Certificate Signed by CA"
    echo -e 'y\ny' | openssl ca -in $user2CSR -out $user2CRT -cert $caCRT -keyfile $caKey
fi

if [ ! -f "$user2PEM" ]; then  
    #Generate PEM Certificate
    echo "Generate User2 PEM Certificate"
    cat $user2CRT $user2Key > $user2PEM
fi

#User3 Key and Certificate Generation Process
if [ ! -f "$user3Key" ]; then
    #Generate a key
    echo "Generating key request for User3"
    openssl genrsa -des3 -passout pass:$password -out $user3Key 2048 -noout

    #Remove passphrase from the key. Comment the line out to keep the passphrase
    echo "Removing passphrase from key"
    openssl rsa -in $user3Key -passin pass:$password -out $user3Key  
fi

if [ ! -f "$user3CSR" ]; then  
    #Generate User3 CSR File
    echo "Generate User3 CSR"
    openssl req -new -key $user3Key -out $user3CSR -days 3650 -subj "/C=$country/ST=$state/L=$city/O=$organization/OU=$organizationalunit/CN=$us3commonname/emailAddress=$email"
fi

if [ ! -f "$user3CRT" ]; then  
    #Generate User3 CRT File
    echo "Generate User3 Certificate Signed by CA"
    echo -e 'y\ny' | openssl ca -in $user3CSR -out $user3CRT -cert $caCRT -keyfile $caKey
fi

if [ ! -f "$user3PEM" ]; then  
    #Generate PEM Certificate
    echo "Generate User3 PEM Certificate"
    cat $user3CRT $user3Key > $user3PEM
fi
#Client Key and Certificate Generation Process
if [ ! -f "$clientKey" ]; then
    #Generate a key
    echo "Generating key request for Client"
    openssl genrsa -des3 -passout pass:$password -out $clientKey 2048 -noout

    #Remove passphrase from the key. Comment the line out to keep the passphrase
    echo "Removing passphrase from key"
    openssl rsa -in $clientKey -passin pass:$password -out $clientKey  
fi

if [ ! -f "$clientCSR" ]; then  
    #Generate Client CSR File
    echo "Generate Client CSR"
    openssl req -new -key $clientKey -out $clientCSR -days 3650 -subj "/C=$country/ST=$state/L=$city/O=$organization/OU=$organizationalunit/CN=$clicommonname/emailAddress=$email"
fi

if [ ! -f "$clientCRT" ]; then  
    #Generate Client CRT File
    echo "Generate Client Certificate Signed by CA"
    echo -e 'y\ny' | openssl ca -in $clientCSR -out $clientCRT -cert $caCRT -keyfile $caKey
fi

if [ ! -f "$clientPEM" ]; then  
    #Generate PEM Certificate
    echo "Generate Client PEM Certificate"
    cat $clientCRT $clientKey > $clientPEM
fi

echo "Start to delete redundant files"
rm -rf $caCRT $serverCSR $serverCRT $clientCSR $clientCRT $caPath $user1CSR $user1CRT $user2CSR $user2CRT $user3CSR $user3CRT
