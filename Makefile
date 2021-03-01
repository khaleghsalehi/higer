
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
	/home/khalegh/pep4444/sbin -t

	kill -USR2 `cat /home/khalegh/pep4444/logs/nginx.pid`
	sleep 1
	test -f /home/khalegh/pep4444/logs/nginx.pid.oldbin

	kill -QUIT `cat /home/khalegh/pep4444/logs/nginx.pid.oldbin`
