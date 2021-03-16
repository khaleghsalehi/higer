#!/bin/bash
#
# xtoken = AES encrytion of email:   khaleghsalehiddddddddd@gmail.net
# AES key: abcdefghijklmnop
# AES iv:  abcdefghijklmnop
#
# online aes encryption/ decryption page: https://www.devglan.com/online-tools/aes-encryption-decryption
#

curl -v --location --request GET 'http://127.0.0.1' \
--header 'xtoken: 8ED8FECD70BC3F95C5F43C33AAAB477513981253585391E50AE6599FEEF692A0146A038654095380F7D9FCB6FA901F7A' \
--header 'token-version: 00000111'

