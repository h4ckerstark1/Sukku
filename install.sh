#!/bin/bash

echo "[+] Installing Sukku Dependencies"

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

sudo apt install nmap -y

export PATH=$PATH:$(go env GOPATH)/bin

echo "[+] Building Sukku"

go build -o sukku

echo "[+] Installation Completed"
