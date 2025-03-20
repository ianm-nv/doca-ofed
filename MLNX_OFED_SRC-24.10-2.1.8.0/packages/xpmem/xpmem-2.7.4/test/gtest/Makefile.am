#
# Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

if HAVE_GTEST

SUBDIRS = common/googletest

noinst_PROGRAMS = gtest

gtest_CPPFLAGS = \
        -I$(srcdir)/common/googletest/include \
        -I$(top_srcdir)/include

gtest_CXXFLAGS = \
        -g -std=c++14 -O2

gtest_LDADD = \
        $(builddir)/common/googletest/libgtest.la \
        $(top_builddir)/lib/libxpmem.la

gtest_LDFLAGS = \
        -lpthread

gtest_SOURCES = \
        common/xpmem_test.cc \
        test_basic.cc \
        test_multi.cc \
        test_main.cc

noinst_HEADERS = \
        common/xpmem_test.h

endif
