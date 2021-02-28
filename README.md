![alt text](higer.png)
# Higer

Higer is a Nginx module for header inspection. Higer has been developed for security goals in order
to allow an authorized access and simply blocking  any bad request to back-ends .


###Name
ngx_http_header_inspect - Inspect custom token (in request headers)

###Synopsis
```
location /foo {
        inspect_headers on;
        inspect_headers_log_violations on;
        inspect_headers_log_uninspected on;
        inspect_headers_block_violations on;
	}
```

