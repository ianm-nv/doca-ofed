KPVER ?= $(shell uname -r)
KSRC ?= /lib/modules/$(KPVER)/build

# Check if MST_KERNEL_HEADER_PATH environment variable is defined
ifdef MST_KERNEL_HEADER_PATH
    KSRC := $(MST_KERNEL_HEADER_PATH)/build
endif

# Oracle Linux OS.
ifneq ($(shell if (echo $(KPVER) | grep -qE 'uek'); then \
                                       echo "YES"; else echo ""; fi),)
override WITH_MAKE_PARAMS += ctf-dir=$(CWD)/.ctf
endif

NNT_DRIVER_LOCATION = ../../nnt_driver
PACKAGE_NAME = nnt-driver
PACKAGE_VERSION = 1.0.0
PACKAGE_RC = 1

%: %.in
	sed \
		-e 's/@PACKAGE_NAME@/$(PACKAGE_NAME)/g' \
		-e 's/@PACKAGE_VERSION@/$(PACKAGE_VERSION)/g' \
		-e 's/@PACKAGE_RC@/$(PACKAGE_RC)/g' \
	<$< >$@

obj-m += mst_pciconf.o
EXTRA_CFLAGS= -I$(PWD)/$(NNT_DRIVER_LOCATION)
mst_pciconf-objs += $(NNT_DRIVER_LOCATION)/nnt_device.o $(NNT_DRIVER_LOCATION)/nnt_dma.o $(NNT_DRIVER_LOCATION)/nnt_pci_conf_access.o \
		 			$(NNT_DRIVER_LOCATION)/nnt_pci_conf_access_recovery.o $(NNT_DRIVER_LOCATION)/nnt_memory_access.o \
		   	        $(NNT_DRIVER_LOCATION)/nnt_ioctl.o mst_pciconf_bc.o $(NNT_DRIVER_LOCATION)/nnt_gpu.o

all:
	make -C $(KSRC) M=$(PWD) CONFIG_CTF= CONFIG_CC_STACKPROTECTOR_STRONG= $(WITH_MAKE_PARAMS) modules

clean:
	make -C $(KSRC) M=$(PWD) clean
