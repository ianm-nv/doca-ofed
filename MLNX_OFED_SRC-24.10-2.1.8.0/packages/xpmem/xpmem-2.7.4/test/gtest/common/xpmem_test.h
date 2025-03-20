/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef XPMEM_TEST_H
#define XPMEM_TEST_H

#include <cstring>
#include <iostream>
#include <sstream>
#include <utility>
#include <vector>

extern "C" {
#include <xpmem.h>
}
#include <sys/mman.h>
#include <unistd.h>

#include <memory>

template <typename T, int (*F)(T)>
struct xpmem_deleter {
  void operator()(T *id) const {
    F(*id);
    delete id;
  }
};

using handle_segid =
    std::unique_ptr<xpmem_segid_t, xpmem_deleter<xpmem_segid_t, xpmem_remove>>;
using handle_apid =
    std::unique_ptr<xpmem_apid_t, xpmem_deleter<xpmem_apid_t, xpmem_release>>;

#define INFO message_stream("INFO")

class message_stream {
 public:
  message_stream(const std::string &title);
  ~message_stream();

  template <typename T>
  message_stream &operator<<(const T &value) {
    m_str << value;
    return *this;
  }

 private:
  std::ostringstream m_str;
};

class xpmem_test {
  static const int DEFAULT_MMAP_PROT = PROT_READ | PROT_WRITE;
  static const int DEFAULT_MMAP_FLAGS = MAP_PRIVATE | MAP_ANONYMOUS;

 protected:
  handle_segid make(void *vaddr = 0, size_t size = XPMEM_MAXADDR_SIZE,
                    uintptr_t perms = 0600);

  handle_apid get(xpmem_segid_t segid, int flags = XPMEM_RDWR);

  std::shared_ptr<void> attach(xpmem_apid_t apid, off_t offset, size_t length);

  std::shared_ptr<void> attach(xpmem_apid_t apid, void *ptr, size_t length);

  static size_t page_size();

  static void pattern_fill(void *ptr, size_t size, int seed);

  std::pair<bool, off_t> pattern_check(void *ptr, size_t size, int seed);

  static int pattern_next(int seed);

  static std::vector<int> randomized_sequence(int count);

 public:
  static void *mmap(size_t size, int prot = DEFAULT_MMAP_PROT,
                    int flags = DEFAULT_MMAP_FLAGS) {
    return mmap(nullptr, size, prot, flags);
  }
  static void *mmap(void *base, size_t size, int prot = DEFAULT_MMAP_PROT,
                    int flags = DEFAULT_MMAP_FLAGS);
};

class mmap_areas {
  class area {
    void *buf;
    size_t len;

   public:
    area(void *data, size_t length) : buf(data), len(length) {}
    uint8_t *ptr() { return reinterpret_cast<uint8_t*>(buf); }
    size_t size() { return len; }
  };
  std::vector<area> area_list;

  void clear();
  void *mmap(size_t size) { return xpmem_test::mmap(size); }

 public:
  ~mmap_areas();
  static size_t holes_sum(size_t size, int count);
  bool make_holes(size_t hole_size, size_t size, int count,
                  bool fault_pages = true);
  auto &areas() { return area_list; }
};
#endif  // XPMEM_TEST_H
