obj-m += dm-dedup.o

dm-dedup-objs := dm-dedup-cbt.o dm-dedup-hash.o dm-dedup-ram.o dm-dedup-check.o dm-dedup-rw.o dm-dedup-target.o

# EXTRA_CFLAGS := -Idrivers/md -I/usr/include -I/usr/include/x86_64-linux-gnu

EXTRA_CFLAGS := -Idrivers/md

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
