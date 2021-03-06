
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/home/khalegh/123/sbin -t

	kill -USR2 `cat /home/khalegh/123/logs/nginx.pid`
	sleep 1
	test -f /home/khalegh/123/logs/nginx.pid.oldbin

	kill -QUIT `cat /home/khalegh/123/logs/nginx.pid.oldbin`
