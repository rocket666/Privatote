#!/bin/bash
# shell img head
mkdir $1
cd $1
openssl genrsa -out RSA_PRIVATE.pem 2048
openssl rsa -in RSA_PRIVATE.pem -pubout -out RSA_PUBLIC.pem
openssl rsa -inform PEM -in RSA_PUBLIC.pem -pubin -modulus -noout | sed 's/^.\{8\}//' | xxd -r -p > pub_key.bin
xxd -i pub_key.bin pub_key.h
unix2dos pub_key.h
