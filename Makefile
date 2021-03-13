
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
	/home/khalegh/higer/sbin -t

	kill -USR2 `cat /home/khalegh/higer/logs/nginx.pid`
	sleep 1
	test -f /home/khalegh/higer/logs/nginx.pid.oldbin

	kill -QUIT `cat /home/khalegh/higer/logs/nginx.pid.oldbin`
