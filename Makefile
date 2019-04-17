ifeq ($(KERNELRELEASE),)  

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 
PWD := $(shell pwd)  

.PHONY: build clean  

build: install_mod sneaky_process
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules  

install_mod:
	gcc -Wall -Werror -g -o install_mod install_mod.c
sneaky_process:
	gcc -Wall -Werror -g -o sneaky_process sneaky_process.c

clean:
	rm -rf *.o *~ core .depend .*.cmd *.order *.symvers *.ko *.mod.c sneaky_process install_mod
else  

$(info Building with KERNELRELEASE = ${KERNELRELEASE}) 
obj-m :=    sneaky_mod.o  

endif
