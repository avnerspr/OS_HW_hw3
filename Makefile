
obj-m := message_slot.o

KDIR := /lib/modules/$(shell uname -r)/build 
PWD := $(shell pwd)
CFAGS_message_slot.o := -std=gnu11 -Wno-declaration-after-statement

all:
		$(MAKE) -C $(KDIR) M=$(PWD) modules

clean: 
		$(MAKE) -C $(KDIR) M=$(PWD) clean
