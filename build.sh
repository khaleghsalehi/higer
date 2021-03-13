#!/bin/bash
echo "=========================="
make clean
clear
sudo kill 9 $(ps -aux | grep nginx | awk '{print $2}')

echo '
  _    _ _
 | |  | (_)
 | |__| |_  __ _  ___ _ __ _ __
 |  __  | |/ _` |/ _ \ '__ | '__|
 | |  | | | (_| |  __/ |  | |
 |_|  |_|_|\__, |\___|_|  |_|
            __/ |
           |___/
           For Back-End Protection
           Version 0.1
 By: Innovera Technology
     https://innovera.ir
 '
make clean
#read -p "Enter setup path: " SETUP_DIR
sudo rm -R /home/khalegh/output
SETUP_DIR=/home/khalegh/output
mkdir $SETUP_DIR
mkdir $SETUP_DIR/sbin
./configure --with-debug --prefix=$SETUP_DIR \
  --sbin-path=$SETUP_DIR/sbin \
  --with-http_sub_module \
  --with-http_ssl_module \
  --with-compat \
  --add-dynamic-module=module/ngx_http_header_inspect

make

sudo make install
sudo cp conf/nginx.conf $SETUP_DIR/conf/

sudo $SETUP_DIR/sbin/nginx -c $SETUP_DIR/conf/nginx.conf
