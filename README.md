Project II, Distributed System

Here are step by step instructions for compiling and running this program:
1) Install OPENSSL Library, if not already installed:
  $sudo apt-get install libssl-dev

2) Compile "server.c" and "client.c" program, using flags for ssl, and crypto libraries; or using Makefile:
  $make

3) Generate keys and certificates for CA, server, and clients in directory cert with linux bash script cert.sh:
  $./cert.sh

4) Execute program:
  a) Start server:
  $./server <pass>

  b) Start client:
    $./client <client>
