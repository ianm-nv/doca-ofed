AM_CPPFLAGS = -I@srcdir@/include \
              -I@builddir@/include \
              -I@top_srcdir@/include

AM_LDFLAGS = @top_builddir@/lib/libxpmem.la

noinst_PROGRAMS = xpmem_proc1 xpmem_proc2 xpmem_master
TESTS = run.sh

EXTRA_DIST = include/xpmem_test.h run.sh

