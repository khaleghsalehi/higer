#!/bin/bash
mkdir /home/khalegh/hc/sbin
./configure --with-debug --prefix=/home/khalegh/hc  \
	  --sbin-path=/home/khalegh/hc/sbin/ \
	  --with-http_sub_module \
	  --with-http_ssl_module \
	  --with-compat \
    --add-dynamic-module=module/ngx_http_header_inspect
make
sudo make install
sudo cp conf/nginx.conf /home/khalegh/hc/conf/