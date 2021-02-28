![alt text](higer.png)

# Higer

Higer is a Nginx module for header inspection. Higer has been developed for security goals in order to allow an
authorized access and simply blocking any bad request to back-ends .

### Name

ngx_http_header_inspect - Inspect custom token (in request headers)

### Synopsis

```
location /foo {
       inspect_headers on|off;
       inspect_headers_log_violations on|off;
       inspect_headers_log_uninspected on|off;
       inspect_headers_block_violations on|off;
       inspect_headers_token_name "YOUR TOKEN NAME";
       inspect_headers_regex_pattern "CUSTOM REGEX";
       # exmaple 
       # inspect_headers_regex_pattern "[13579]{1}[02468]{3}[13579]{3}";
       # 
       #
	}
```

