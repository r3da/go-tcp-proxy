#!/bin/bash

# Usage: ./generate_proxy_certs.sh my.example.com
domain=$1

openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout $domain-CA.key -out $domain-CA.crt -subj "/C=US/ST=WA/L=Seattle/O=Proxy/OU=IT Department/CN=${domain}"
openssl req -nodes -newkey rsa:2048 -keyout $domain.key -out $domain.csr -subj "/C=US/ST=WA/L=Seattle/O=Proxy/OU=IT Department/CN=${domain}"
openssl x509 -req -in $domain.csr -days 365 -CA $domain-CA.crt -CAkey $domain-CA.key -CAcreateserial  -out $domain.crt
