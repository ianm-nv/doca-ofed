/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include <common/xpmem_test.h>
#include <gtest/gtest.h>

#include <utility>

class test_basic : public xpmem_test, public testing::Test {
 protected:
  auto create_xpmem(uintptr_t make_perms, uintptr_t get_perms) {
    xpmem_segid_t segid = xpmem_make(NULL, 10 * page_size(), XPMEM_PERMIT_MODE,
                                     (void*)make_perms);
    xpmem_apid_t apid = -1;
    if (segid != -1) {
      apid = xpmem_get(segid, get_perms, XPMEM_PERMIT_MODE, NULL);
    }
    return std::make_pair(segid, apid);
  }
};

TEST_F(test_basic, randomized_sequence_inversions) {
  int count = 1000;
  int prev = -1;
  int total = 0;

  for (auto i : randomized_sequence(count)) {
    if (i < prev) {
      total++;
    }
    prev = i;
  }
  ASSERT_GT(total, count / 3);
}

TEST_F(test_basic, randomized_sequence_ok) {
  int count = 1000;
  std::vector<int> field(count, 0);
  for (auto i : randomized_sequence(count)) {
    field[i] = 1;
  }
  int total = 0;
  for (auto f : field) {
    total += f;
  }
  ASSERT_EQ(count, total);
}

TEST_F(test_basic, xpmem_make_success) {
  xpmem_segid_t segid =
      xpmem_make(NULL, 1 << 16, XPMEM_PERMIT_MODE, (void*)0600);

  ASSERT_NE(-1, segid);
  ASSERT_EQ(0, xpmem_remove(segid));
}

TEST_F(test_basic, xpmem_make_unaligned_failure) {
  xpmem_segid_t segid =
      xpmem_make((void*)12, 1 << 16, XPMEM_PERMIT_MODE, (void*)0600);
  ASSERT_EQ(-1, segid);
}

TEST_F(test_basic, xpmem_make_perm_failure) {
  xpmem_segid_t segid = xpmem_make(NULL, 1 << 16, 0, (void*)0600);
  ASSERT_EQ(-1, segid);
}

TEST_F(test_basic, xpmem_make_overflow_failure) {
  xpmem_segid_t segid =
      xpmem_make((void*)-2, 1 << 16, XPMEM_PERMIT_MODE, (void*)0600);
  ASSERT_EQ(-1, segid);
}

TEST_F(test_basic, xpmem_remove_error) { ASSERT_EQ(-1, xpmem_remove(-1)); }

TEST_F(test_basic, xpmem_remove_unknown) { ASSERT_EQ(-1, xpmem_remove(12345)); }

TEST_F(test_basic, xpmem_remove_twice) {
  xpmem_segid_t segid =
      xpmem_make(NULL, 10 * page_size(), XPMEM_PERMIT_MODE, (void*)0600);
  ASSERT_NE(-1, segid);
  ASSERT_EQ(0, xpmem_remove(segid));
  ASSERT_EQ(-1, xpmem_remove(segid));
}

TEST_F(test_basic, xpmem_get_bad_segid) {
  xpmem_apid_t apid = xpmem_get(-1, XPMEM_RDWR, XPMEM_PERMIT_MODE, (void*)0600);
  ASSERT_EQ(-1, apid);
}

TEST_F(test_basic, xpmem_get_bad_segid_positive) {
  xpmem_apid_t apid =
      xpmem_get(12345, XPMEM_RDWR, XPMEM_PERMIT_MODE, (void*)0600);
  ASSERT_EQ(-1, apid);
}

TEST_F(test_basic, xpmem_get_success) {
  xpmem_segid_t segid =
      xpmem_make(NULL, 10 * page_size(), XPMEM_PERMIT_MODE, (void*)0600);
  ASSERT_NE(-1, segid);

  xpmem_apid_t apid =
      xpmem_get(segid, XPMEM_RDWR, XPMEM_PERMIT_MODE, (void*)0600);
  ASSERT_NE(-1, apid);
  ASSERT_EQ(0, xpmem_release(apid));
  ASSERT_EQ(0, xpmem_remove(segid));
}

TEST_F(test_basic, xpmem_get_bad_permit_mode) {
  xpmem_segid_t segid =
      xpmem_make(NULL, 10 * page_size(), XPMEM_PERMIT_MODE, (void*)0200);
  ASSERT_NE(-1, segid);

  xpmem_apid_t apid = xpmem_get(segid, 9999, XPMEM_PERMIT_MODE, (void*)0);
  EXPECT_EQ(-1, apid);

  ASSERT_EQ(0, xpmem_remove(segid));
}

TEST_F(test_basic, xpmem_get_read_attach) {
  xpmem_segid_t segid =
      xpmem_make(NULL, 10 * page_size(), XPMEM_PERMIT_MODE, (void*)0400);
  ASSERT_NE(-1, segid);
  xpmem_apid_t apid =
      xpmem_get(segid, XPMEM_RDONLY, XPMEM_PERMIT_MODE, (void*)0);
  EXPECT_NE(-1, apid);

  struct xpmem_addr addr;
  addr.apid = apid;
  addr.offset = 2 * page_size();
  auto att_ptr = xpmem_attach(addr, 3 * page_size(), NULL);
  EXPECT_NE(nullptr, att_ptr);
  ASSERT_EQ(0, xpmem_remove(segid));
}

// Missing: Group permission checks
TEST_F(test_basic, xpmem_get_allowed_permit) {
  std::vector<std::pair<uintptr_t, uintptr_t>> okay = {
    {0600, XPMEM_RDONLY},
    {0400, XPMEM_RDONLY},
  };
  for (auto pair : okay) {
    auto mem = create_xpmem(pair.first, pair.second);
    ASSERT_NE(-1, mem.first);
    EXPECT_NE(-1, mem.second);
    ASSERT_EQ(0, xpmem_remove(mem.first));
  }
}

TEST_F(test_basic, xpmem_get_not_allowed_permit) {
  std::vector<std::pair<uintptr_t, uintptr_t>> fails = {
    {0400, XPMEM_RDWR},
    {0200, XPMEM_RDWR},
    {0200, XPMEM_RDONLY},
    {0000, XPMEM_RDWR},
    {0000, XPMEM_RDONLY},
  };
  for (auto pair : fails) {
    auto mem = create_xpmem(pair.first, pair.second);
    ASSERT_NE(-1, mem.first);
    if (geteuid() == 0) {
      EXPECT_NE(-1, mem.second);
    } else {
      EXPECT_EQ(-1, mem.second);
    }
    ASSERT_EQ(0, xpmem_remove(mem.first));
  }
}

class xpmem_context {
  xpmem_segid_t segid;
  xpmem_apid_t apid;

  uint8_t* mmap_ptr;
  uint8_t* att_ptr;

  size_t page_size;

  int mmap_count;
  int xpmem_size;

 public:
  uint8_t* att() const { return att_ptr; }
  uint8_t* ptr() const { return mmap_ptr; }

  xpmem_context(size_t page) : page_size(page) {}
  void Setup(int count, int leading, int trailing, int attach_off,
             int attach_count, uintptr_t make_perms = 0600,
             uintptr_t attach_perms = XPMEM_RDWR) {
    mmap_count = count;
    mmap_ptr = static_cast<uint8_t*>(mmap(NULL, mmap_count * page_size,
                                          PROT_READ | PROT_WRITE,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    ASSERT_NE(nullptr, mmap_ptr);

    void* seg_base = mmap_ptr + leading * page_size;
    xpmem_size = mmap_count + trailing - leading;
    segid = xpmem_make(seg_base, xpmem_size * page_size, XPMEM_PERMIT_MODE,
                       (void*)make_perms);
    ASSERT_NE(-1, segid);

    apid = xpmem_get(segid, attach_perms, XPMEM_PERMIT_MODE, (void*)NULL);
    ASSERT_NE(-1, apid);

    struct xpmem_addr addr;
    addr.apid = apid;
    addr.offset = attach_off * page_size;
    att_ptr = static_cast<uint8_t*>(
        xpmem_attach(addr, attach_count * page_size, NULL));
    ASSERT_NE((void*)-1, att_ptr);
  }

  ~xpmem_context() {
    EXPECT_EQ(0, xpmem_detach(att_ptr));
    EXPECT_EQ(0, xpmem_release(apid));
    EXPECT_EQ(0, xpmem_remove(segid));
    munmap(mmap_ptr, mmap_count * page_size);
  }
};

TEST_F(test_basic, xpmem_small_share) {
  int count = 10;    // mmap page count
  int leading = -3;  // share before mmapped area
  int trailing = 2;  // share after mmapped area
  int attach_off = 1;
  int attach_count = count + 2;

  xpmem_context ctx(page_size());
  ctx.Setup(count, leading, trailing, attach_off, attach_count);

  int offset = leading + attach_off;
  uint8_t* val_p = ctx.att() - (offset * page_size());

  for (int i = 0; i < count; i++) {
    *val_p = 0x22;
    val_p += page_size();
  }
}

TEST_F(test_basic, xpmem_crash_before_mmap) {
  ASSERT_DEATH(
      {
        int count = 10;
        int leading = -1;

        xpmem_context ctx(page_size());
        ctx.Setup(count, leading, 0, 0, count);
        *ctx.att() = 0x11;  // Crash: Attached one page before mmap() area
      },
      "");
}

TEST_F(test_basic, xpmem_crash_after_munmap) {
  ASSERT_DEATH(
      {
        int count = 10;
        int leading = -1;
        int trailing = 1;

        xpmem_context ctx(page_size());
        ctx.Setup(count, leading, trailing, 0, count + 2);

        munmap(ctx.ptr(), count * page_size());

        auto ptr = ctx.att() + (page_size() * (count / 2));
        *ptr = 0x11;
      },
      "");
}

TEST_F(test_basic, same_process_64_pages) {
  auto segid = make();
  INFO << "segid: 0x" << std::hex << *segid;

  auto apid = get(*segid);
  INFO << "apid: 0x" << std::hex << *apid;

  const size_t size = 64 * page_size();

  auto seg_ptr = mmap(size);
  INFO << "seg_ptr: " << seg_ptr;

  auto att_ptr = attach(*apid, seg_ptr, size);
  INFO << "att_ptr: " << att_ptr;

  static const int seed = 0xdeadbeef;
  pattern_fill(seg_ptr, size, seed);

  auto result = pattern_check(att_ptr.get(), size, seed);
  auto expect = std::make_pair<bool, int>(true, 0);
  ASSERT_EQ(expect.first, result.first);
}

TEST_F(test_basic, mmap_holes) {
  auto hole_size = 2 * page_size();
  auto size = 3 * page_size();
  auto count = 10;

  mmap_areas mappings;
  bool ret = mappings.make_holes(hole_size, size, count);
  ASSERT_TRUE(ret);

  auto areas = mappings.areas();
  EXPECT_EQ(count, areas.size());
  auto next = areas.front().ptr();

  for (auto area : areas) {
    auto vm_start = area.ptr();
    auto vm_end = area.ptr() + area.size();
    INFO << "vma: " << std::hex << (void*)vm_start << "-" << std::hex
         << (void*)vm_end;
    EXPECT_EQ(next, vm_start);
    EXPECT_EQ(next + size, vm_end);
    next += size + hole_size;
  }
}

TEST_F(test_basic, mmap_holes_populate) {
  mmap_areas mappings;
  bool ret = mappings.make_holes(page_size(), 2 * page_size(), 10);
  ASSERT_TRUE(ret);
  auto areas = mappings.areas();

  for (auto area : areas) {
    for (int i = 0; i < area.size(); i++) {
      area.ptr()[i] = 0;
    }
  }
}

TEST_F(test_basic, mmap_holes_death_before) {
  ASSERT_DEATH(
      {
        mmap_areas mappings;
        bool ret = mappings.make_holes(4 * page_size(), page_size(), 3);
        ASSERT_TRUE(ret);

        auto areas = mappings.areas();
        EXPECT_EQ(3, areas.size());
        *(areas.front().ptr() - page_size()) = 0;
      },
      "");
}

TEST_F(test_basic, mmap_holes_death_after) {
  ASSERT_DEATH(
      {
        mmap_areas mappings;
        bool ret = mappings.make_holes(4 * page_size(), page_size(), 3);
        ASSERT_TRUE(ret);

        auto areas = mappings.areas();
        EXPECT_EQ(3, areas.size());
        *(areas.back().ptr() + areas.back().size()) = 0;
      },
      "");
}

TEST_F(test_basic, mmap_holes_sum) {
  auto size = 256 * page_size();
  auto count = 12;

  size_t total = 0;
  int n = 1;
  for (auto i = 0; i < count; i++) {
    for (auto j = 0; j < size; j += sizeof(uint32_t)) {
      total += n++;
    }
  }
  ASSERT_EQ(total, mmap_areas::holes_sum(size, count));
}
