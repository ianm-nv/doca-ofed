# :warning: The project webpage is at http://knem.gitlabpages.inria.fr

## :warning: For questions and problems, see 'Reporting Bugs' at the end of this file.



# Build and Install

Build and install knem with:
```
$ ./configure
$ make
$ make install
```

By default, knem will be installed in `/opt/knem`. Use `--prefix` on
the configure line to change this.
To place the kernel module and udev rules in the standard locations,
you should then run:
```
$ /path/to/knem/install/sbin/knem_local_install
```

If building from a GIT clone, you want to run:
```
$ ./autogen.sh
```
before running the configure script. Note that automake >= 1.10
and autoconf >= 2.61 will be needed by autoreconf.


# Load the Kernel Module

Once installed, you should load the driver:
```
$ modprobe knem
```
The `/dev/knem` device file should appear under group `rdma`,
so any user should be added to this group before using knem.

If you did not run `knem_local_install`, you may load the module
manually with:
```
$ insmod /path/to/knem/install/lib/modules/$(uname -r)/knem.ko
```
You should then adjust its permissions manually since the relevant
udev rules were not installed:
```
$ chgrp rdma /dev/knem
```


# Check the Driver Status

You may check the driver status by cat'ing the device file:
```
$ cat /dev/knem
knem 0.8.1
 Driver ABI=0xc
 Flags: forcing 0x0, ignoring 0x0
 DMAEngine: KernelSupported Enabled ChansAvail ChunkMin=1024B
 Debug: NotBuilt
[...]
```
It also shows counters that will be updated at runtime:
```
 Requests Submitted          : 10243
 Requests Processed/DMA      : 5621
 Requests Processed/Thread   : 2
[...]
```

# Check Data Transfers and Performance

You may test the driver with the given tools program.
To check the knem performance within a single process:
```
$ /path/to/knem/install/bin/knem_loopback
     1024:	4.203 us	243.63 MB/s	 232.34 MiB/s
[...]
 16777216:	12921.820 us	1298.36 MB/s	 1238.22 MiB/s
```
To check performance between separate processes:
```
$ /path/to/knem/install/bin/knem_pingpong
     1024:	4.367 us	234.48 MB/s	 223.61 MiB/s
[...]
 16777216:	12843.322 us	1306.30 MB/s	 1245.78 MiB/s
```

To check that vectorial data transfers work fine:
```
$ /path/to/knem/install/bin/knem_vect_test
got driver ABI c and feature mask 1
got lid 5d3528e8dd352285
last properly copied at 3432460
looks good
```



# Reporting Bugs

In case of problem, make sure you read the README first :)
Please also look at the documentation in the doc/ directory
or online at http://knem.gitlabpages.inria.fr/doc/knem.html

Bugs should be reported on http://gitlab.inria.fr/knem/knem
or sent to knem@inria.fr (need to be subscribed for posting).
Questions may be asked there too.

When reporting a problem, make sure you include:
* the version number of KNEM
  (or the output of `git show` if you checked out the GIT repository)
* the output (as root) of
  + `cat /dev/knem`
* the whole outputs (as root) of:
  + `lsmod`
  + `dmesg`
* the whole output of the program if a program did not work
  as expected
* the whole output of `configure`, `config.log` and `knem_checks.h`,
  and of the compilation if reporting a build problem
