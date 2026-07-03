#!/bin/bash

# System dependencies
echo -e "[*] Updating list of available packages...\n"
sudo apt update

echo -e "\n[*] Installing system dependencies...\n"
sudo apt install -y openssl

# Python 3 dependencies (Volatility 3 + plugin requirements)
echo -e "\n[*] Installing Python 3 dependencies...\n"
pip3 install --upgrade 'volatility3' 'pefile>=2019.4.18' 'cryptography'
