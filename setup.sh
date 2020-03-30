#!/bin/bash

# System dependencies
echo -e "[*] Updating list of available packages...\n"
sudo apt update

echo -e "\n[*] Installing system dependencies...\n"
sudo apt install openssl

# Python dependencies
echo -e "\n[*] Installing Python2 dependencies...\n"
sudo pip2 install 'pefile>=2019.4.18' distorm3 pycrypto
