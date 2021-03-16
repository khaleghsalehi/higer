![alt text](higer.png)

# Higer

Higer is a Nginx module for header inspection. Higer has been developed for security goals in order to allow an
authorized access and simply blocking any bad request to back-ends .

### Name

ngx_http_header_inspect - Inspect custom token (in request headers)

### Synopsis

```
location /foo {
            inspect_headers on;
            inspect_headers_log_violations on;
            inspect_headers_log_uninspected on;
            inspect_headers_block_violations on;
            inspect_headers_token_name xtoken;
            inspect_headers_regex_pattern "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";
            inspect_headers_version_name token-version;
            inspect_headers_version 00000010;
            inspect_headers_aes_key aaaaaaaaaaaaaaaa;
            inspect_headers_aes_key bbbbbbbbbbbbbbbb;
            proxy_pass https://example.com
	}
```

