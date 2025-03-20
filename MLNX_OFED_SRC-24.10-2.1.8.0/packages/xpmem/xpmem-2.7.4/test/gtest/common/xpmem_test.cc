/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "xpmem_test.h"

#include <algorithm>
#include <random>

message_stream::message_stream(const std::string &title) {
  static const char PADDING[] = "          ";
  static const size_t WIDTH = strlen(PADDING);

  m_str << "[";
  m_str.write(PADDING, std::max(WIDTH - 1, title.length()) - title.length());
  m_str << title << " ] ";
}

message_stream::~message_stream() { std::cout << m_str.str() << std::endl; }

handle_segid xpmem_test::make(void *vaddr, size_t size, uintptr_t perm) {
  return handle_segid(new xpmem_segid_t(
      xpmem_make(vaddr, size, XPMEM_PERMIT_MODE, (void*)perm)));
}

handle_apid xpmem_test::get(xpmem_segid_t segid, int flags) {
  return handle_apid(
      new xpmem_apid_t(xpmem_get(segid, flags, XPMEM_PERMIT_MODE, NULL)));
}

std::shared_ptr<void> xpmem_test::attach(xpmem_apid_t apid, off_t offset,
                                         size_t length) {
  struct xpmem_addr addr = {apid, offset};
  return std::shared_ptr<void>(xpmem_attach(addr, length, NULL), xpmem_detach);
}

std::shared_ptr<void> xpmem_test::attach(xpmem_apid_t apid, void *ptr,
                                         size_t length) {
  return attach(apid, reinterpret_cast<unsigned long>(ptr), length);
}

void *xpmem_test::mmap(void *addr, size_t size, int prot, int flags) {
  size_t aligned_size = (size + page_size() - 1) & ~(page_size() - 1);
  void *ptr = ::mmap(addr, aligned_size, prot, flags, -1, 0);
  if (ptr == MAP_FAILED) {
    return NULL;
  }
  return ptr;
}

size_t xpmem_test::page_size() {
  static size_t page_size = 0;

  if (page_size == 0) {
    page_size = sysconf(_SC_PAGESIZE);
  }

  return page_size;
}

void xpmem_test::pattern_fill(void *ptr, size_t size, int seed) {
  int *p = reinterpret_cast<int*>(ptr);
  int *end = p + size / sizeof(*p);
  while (p < end) {
    *(p++) = seed;
    seed = pattern_next(seed);
  }
}

std::pair<bool, off_t> xpmem_test::pattern_check(void *ptr, size_t size,
                                                 int seed) {
  int *p = reinterpret_cast<int*>(ptr);
  int *end = p + size / sizeof(*p);

  if (p > end) {
    return {false, -1};
  }

  while (p < end) {
    if (seed != *p) {
      off_t off = reinterpret_cast<char*>(p) - reinterpret_cast<char*>(ptr);
      return {false, off};
    }
    seed = pattern_next(seed);
    ++p;
  }
  return {true, 0};
}

int xpmem_test::pattern_next(int seed) {
  // LFSR
  return (seed << 1) | (__builtin_parityl(seed & 1337));
}

std::vector<int> xpmem_test::randomized_sequence(int count) {
  std::vector<int> value(count);
  for (int i = 0; i < count; i++) {
    value[i] = i;
  }

  std::random_device rd;
  std::default_random_engine rng(rd());
  std::shuffle(value.begin(), value.end(), rng);
  return value;
}

void mmap_areas::clear() {
  for (auto a : area_list) {
    munmap(a.ptr(), a.size());
  }
  area_list.clear();
}

mmap_areas::~mmap_areas() { clear(); }

// Return 'count' mmap'd areas of 'size' with holes before and after
bool mmap_areas::make_holes(size_t hole_size, size_t size, int count,
                            bool fault_pages) {
  size_t overall = (hole_size + size) * count + hole_size;

  clear();

  // Find virtual memory area
  auto addr = reinterpret_cast<uint8_t*>(xpmem_test::mmap(overall));
  if (!addr) {
    return false;
  }
  munmap(addr, overall);
  addr += hole_size;

  int n = 1;
  for (int i = 0; i < count; i++) {
    uint8_t *ptr = reinterpret_cast<uint8_t*>(xpmem_test::mmap(addr, size));
    area_list.emplace_back(ptr, size);
    if (!ptr || ptr != addr) {
      goto fail;
    }
    for (auto j = 0; j < size; j += sizeof(uint32_t)) {
      *reinterpret_cast<uint32_t*>(ptr + j) = n++;
    }
    addr += size + hole_size;
  }

  return true;
fail:
  for (auto a : area_list) {
    if (a.ptr()) {
      munmap(a.ptr(), a.size());
    }
  }
  area_list.clear();
  return false;
}

size_t mmap_areas::holes_sum(size_t size, int count) {
  size_t n = size / sizeof(uint32_t) * count;
  return n * (n + 1) / 2;
}
