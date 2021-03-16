![alt text](higer.png)

# Higer

Higer is a Nginx module for encrypted header inspection. Higer has been developed for security goals in order to allow an
authorized access and simply blocking any bad request to back-ends .

### How it's work?
Higer inspect all of request for encrypted token according to regular expresion (token/s pattern). In order to
MITM attacks protection or token inspection, all of token MUST be encrypted in client side based on AES-128-CBC.
Using techniques such as SSL pinging, obfuscation and encryption, etc.  are considerable for more protection on client side.   


### Name

ngx_http_header_inspect - Inspect custom token (in request headers)

### Synopsis

```
location /foo {
            inspect_headers on|off;
            inspect_headers_log_violations on | off;
            inspect_headers_log_uninspected on|off;
            inspect_headers_block_violations on|off;
            inspect_headers_token_name TOKEN_ID;
            inspect_headers_regex_pattern "YOUR_REGEX_PATTERN";
            # e.g ^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ only allow valid email address as a token
            inspect_headers_version_name TOKEN_VERSION_ID;
            inspect_headers_version VERSION_NUMBER; # diget len 8
            inspect_headers_aes_key AES_KEY; # len 16 
            inspect_headers_aes_key AES_IV; # len 16
            proxy_pass https://example.com
	}
```
### FAQ
* How to match multi-pattern token?
    * try in your regex pattern, e.g, ([a-z]600|[a-z]700|[a-z]800)
* can I consider higher as a dynamic and independent nginx module only??
    * Sure, compile higher module as a standalone and dynamic nginx module, it's work



