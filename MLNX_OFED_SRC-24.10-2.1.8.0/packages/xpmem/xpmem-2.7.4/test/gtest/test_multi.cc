/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include <common/sync.h>
#include <common/xpmem_test.h>
#include <gtest/gtest.h>
#include <sys/resource.h>
#include <sys/time.h>

class CoreDumpDisable {
  struct rlimit limit;

 public:
  CoreDumpDisable() {
    struct rlimit zero_limit = {};
    EXPECT_EQ(0, getrlimit(RLIMIT_CORE, &limit));
    EXPECT_EQ(0, setrlimit(RLIMIT_CORE, &zero_limit));
  }

  ~CoreDumpDisable() { setrlimit(RLIMIT_CORE, &limit); }
};

class test_multi : public Sync, public xpmem_test, public testing::Test {
  template <typename T>
  T* shared_memory() {
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_SHARED | MAP_ANONYMOUS;
    return static_cast<T*>(::mmap(NULL, sizeof(T), prot, flags, -1, 0));
  }

 protected:
  Area* m_area = NULL;
  std::vector<pid_t> pids;

  void SetUp() {
    m_area = shared_memory<Area>();
    ASSERT_TRUE(m_area != NULL);
    SetArea(m_area);

    m_count = 1;
  }

  void WaitpidAll(int expect_status = 0) {
    if (pids.size()) {
      INFO << "Waiting for " << pids.size() << " pid(s)";
    }
    for (auto pid : pids) {
      int status;
      int ret = waitpid(pid, &status, 0);
      EXPECT_GT(ret, -1);

      if (expect_status) {
        EXPECT_TRUE(WIFSIGNALED(status));
        EXPECT_EQ(expect_status, WTERMSIG(status));
      } else {
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(0, WEXITSTATUS(status));
      }
    }
    pids.clear();
  }

  void TearDown() {
    WaitpidAll();
    munmap(m_area, sizeof(*m_area));
  }

  void Start(int procs, std::function<void()> func) {
    int id = m_count;
    m_count += procs;
    for (int i = 0; i < procs; i++) {
      pid_t pid = fork();
      ASSERT_GT(pid, -1);
      if (!pid) {
        Self(id + i);
        func();
        exit(::testing::Test::HasFailure());
      }
      pids.push_back(pid);
    }
    INFO << "Forked " << procs << " process(es)";
  }
};

class test_multi_xpmem : public test_multi {
 protected:
  handle_segid segid;
  handle_apid apid;
  int seed;
  void* data_ptr;
  size_t data_size;

  void SetUp() {
    test_multi::SetUp();
    seed = 0xdeadbeef;
    data_ptr = nullptr;
    segid = std::move(make());
    ASSERT_NE(-1, *segid);
    apid = get(*segid);
    ASSERT_NE(-1, *apid);
  }

  void TearDown() {
    if (data_ptr) {
      ASSERT_EQ(0, munmap(data_ptr, data_size));
      data_ptr = nullptr;
    }
    test_multi::TearDown();
  }

  void StartAttach(int peers, void* data_ptr, size_t size,
                   std::function<void(void*)> action, int segid_count = 1,
                   bool no_wait = false) {
    Start(peers, [&]() {
      Wait();
      for (int s = 0; s < segid_count; s++) {
        auto sid = Share()->segid[s];
        ASSERT_NE(-1, sid);

        auto aid = get(sid);
        ASSERT_NE(-1, *aid);

        auto att_ptr = attach(*aid, data_ptr, size);
        ASSERT_NE(data_ptr, att_ptr.get());
        ASSERT_NE((void*)-1, att_ptr.get());

        action(att_ptr.get());
      }
      if (!no_wait) {
        Wait();
      }
    });
  }

  void StartSimpleOneToManyPeers(
      int peers, int pages,
      std::function<void(void*, size_t)> filler = [](void*, size_t) {},
      std::function<void(void*)> fork_action = [](void*) {}) {
    auto size = page_size() * pages;
    data_ptr = mmap(size);
    data_size = size;

    filler(data_ptr, data_size);
    StartAttach(peers, data_ptr, size, fork_action);

    Share()->segid[0] = *segid;
    SignalAllStartFinish();
  }

  void SignalAllStartFinish() {
    SignalAll();  // Wait for all peers and unblock them
    SignalAll();  // Wait for all peers to complete and let them terminate
  }

  testing::AssertionResult test_pattern_check(void* ptr, size_t size, int seed);
};

TEST_F(test_multi, start_capturing_lambdas) {
  int n = 100;
  Start(n, [this]() {});
  WaitpidAll();
}

TEST_F(test_multi, p2p_simple_signal) {
  int tries = 300;

  pid_t pid = fork();
  ASSERT_GT(pid, -1);
  if (!pid) {
    Self(1);

    for (int i = 0; i < tries; i++) {
      Wait();
      EXPECT_EQ(i * 2 + 1, Share()->segid[0]);
      Share()->segid[1]++;
      Signal(0);
      Wait();
      EXPECT_EQ(i * 2 + 2, Share()->segid[0]);
    }
    exit(::testing::Test::HasFailure());
  } else {
    Self(0);

    for (int i = 0; i < tries; i++) {
      WaitFor(1);
      Share()->segid[0]++;
      Signal(1);

      Wait();
      EXPECT_EQ(i + 1, Share()->segid[1]);
      Share()->segid[0]++;

      Signal(1);
    }
    int status;
    int ret = waitpid(pid, &status, 0);
    ASSERT_GT(ret, -1);
    EXPECT_TRUE(WIFEXITED(status));
    ASSERT_EQ(0, WEXITSTATUS(status));
  }
}

TEST_F(test_multi, p2p_multi_signal) {
  int tries = 200;
  int peers = 5;
  int seed = 0xabcde;

  Start(peers, [&]() {
    while (tries-- > 0) {
      Wait();
      seed = pattern_next(seed);
      EXPECT_EQ(Share()->segid[0], seed);
    }
  });

  while (tries-- > 0) {
    WaitForAll();
    seed = pattern_next(seed);
    Share()->segid[0] = seed;
    SignalAll();
  }
}

TEST_F(test_multi, p2p_multi_chained) {
  int tries = 100;
  int peers = 15;
  int seed = 0xabcde;
  int index = 0;

  Start(peers, [&]() {
    while (tries-- > 0) {
      Wait();

      EXPECT_EQ(Share()->segid[0], (index << 6) + Id());

      int next = Id() + 1;
      int next_index = index++;
      if (next >= m_count) {
        if (!tries) {
          break;
        }
        next = 1;
        next_index++;
      }

      Share()->segid[0] = (next_index << 6) + next;
      Signal(next);
    }
  });

  WaitForAll();
  Share()->segid[0] = (index << 6) + 1;
  Signal(1);
}

testing::AssertionResult test_multi_xpmem::test_pattern_check(void* ptr,
                                                              size_t size,
                                                              int seed) {
  auto result = pattern_check(ptr, size, seed);
  if (result.first == true) {
    return testing::AssertionSuccess();
  }
  if (result.second < -1) {
    return testing::AssertionFailure() << "pointer overflow";
  }
  return testing::AssertionFailure() << "at offset " << result.second;
}

class test_multi_xpmem_peers_pages
    : public test_multi_xpmem,
      public testing::WithParamInterface<std::tuple<int, int>> {
 protected:
  void StartSimpleOneToMany(
      std::function<void(void*, size_t)> filler = [](void*, size_t) {},
      std::function<void(void*)> fork_action = [](void*) {}) {
    int peers = std::get<0>(GetParam());
    int pages = std::get<1>(GetParam());
    StartSimpleOneToManyPeers(peers, pages, filler, fork_action);
  }
};

// Only exercises the xpmem ioctl()
TEST_P(test_multi_xpmem_peers_pages, simple_one_to_many_no_fault) {
  StartSimpleOneToMany();
}

TEST_P(test_multi_xpmem_peers_pages, simple_one_to_many_no_child_fault) {
  auto filler = [&](void* ptr, size_t size) { pattern_fill(ptr, size, seed); };
  StartSimpleOneToMany(filler);
}

TEST_P(test_multi_xpmem_peers_pages, simple_one_to_many_no_parent_fault) {
  auto fork_action = [&](void* ptr) {
    // Read fault, but pattern won't be there
    ASSERT_FALSE(test_pattern_check(ptr, data_size, seed));
  };
  StartSimpleOneToMany([](void*, size_t) {}, fork_action);
}

TEST_P(test_multi_xpmem_peers_pages, simple_one_to_many_no_parent_fault_write) {
  auto fork_action = [&](void* ptr) {
    // Read fault, but pattern won't be there
    memset(ptr, 'a', data_size);
  };
  StartSimpleOneToMany([](void*, size_t) {}, fork_action);
}

TEST_P(test_multi_xpmem_peers_pages, simple_one_to_many_sparse) {
  int peers = std::get<0>(GetParam());
  int pages = std::get<1>(GetParam());

  int total_pages = 100 * 1000;
  if (pages > total_pages) {
    GTEST_SKIP();
  }
  auto filler = [&](void* ptr, size_t size) {
    for (int i = 0; i < size; i += page_size()) {
      auto input = reinterpret_cast<int*>(reinterpret_cast<char*>(ptr) + i);
      *input = i + seed + 432;
    }
  };
  auto fork_action = [&](void* ptr) {
    auto output = reinterpret_cast<int*>(ptr);
    for (int i = 0; i < pages * page_size(); i += 200 * page_size()) {
      auto output = reinterpret_cast<int*>(reinterpret_cast<char*>(ptr) + i);
      EXPECT_EQ(i + seed + 432, *output);
    }
  };
  StartSimpleOneToManyPeers(peers, total_pages, filler, fork_action);
}

TEST_P(test_multi_xpmem_peers_pages, simple_one_to_many) {
  int peers = std::get<0>(GetParam());
  int pages = std::get<1>(GetParam());

  auto filler = [&](void* ptr, size_t size) { pattern_fill(ptr, size, seed); };
  auto fork_action = [&](void* ptr) {
    ASSERT_TRUE(test_pattern_check(ptr, data_size, seed));
  };
  StartSimpleOneToMany(filler, fork_action);
}

TEST_P(test_multi_xpmem_peers_pages, simple_one_to_many_mempcy) {
  int peers = std::get<0>(GetParam());
  int pages = std::get<1>(GetParam());

  auto size = page_size() * pages;
  data_ptr = mmap(size);
  data_size = size;

  pattern_fill(data_ptr, size, seed);

  auto fork_action = [&](void* ptr) {
    void* buf = malloc(size);
    ASSERT_NE(nullptr, buf);

    memset(buf, 0, size);
    Wait();

    memcpy(buf, ptr, size);
    free(buf);
  };
  StartAttach(peers, data_ptr, size, fork_action);

  Share()->segid[0] = *segid;
  SignalAll();             // malloc / memset
  SignalAllStartFinish();  // Start memcpy
}

TEST_P(test_multi_xpmem_peers_pages, parallel_many_to_one) {
  int peers = std::get<0>(GetParam());
  int pages = std::get<1>(GetParam());

  auto size = page_size() * pages;
  data_ptr = mmap(size);
  data_size = size;

  auto fork_action = [&](void* ptr) {
    auto data = static_cast<uint8_t*>(ptr);
    for (int i = 0; i < size; i += page_size() / 2) {
      seed = pattern_next(seed);
      data[i] = seed;  // Uses lowest byte only
    }
  };
  StartAttach(peers, data_ptr, size, fork_action);

  WaitForAll();  // Wait for them to be ready
  Share()->segid[0] = *segid;
  SignalAllStartFinish();  // Start fork action and wait for them to finish

  for (int i = 0; i < size; i += page_size() / 2) {
    seed = pattern_next(seed);
    EXPECT_EQ(static_cast<uint8_t>(seed),
              *(static_cast<uint8_t*>(data_ptr) + i));
  }
}

TEST_P(test_multi_xpmem_peers_pages, parallel_multi_same_segs) {
  int peers = std::get<0>(GetParam());
  int pages = std::get<1>(GetParam());

  auto size = page_size() * pages;
  data_ptr = mmap(size);
  data_size = size;
  ASSERT_NE(nullptr, data_ptr);

  int segid_count = 10;

  auto fork_action = [&](void* ptr) {
    auto data = static_cast<uint8_t*>(ptr);
    for (int i = 0; i < size; i += page_size() / 2) {
      seed = pattern_next(seed);
      data[i] = seed;
    }
  };
  StartAttach(peers, data_ptr, size, fork_action, segid_count);

  std::vector<decltype(segid)> segments;
  for (int i = 0; i < segid_count; i++) {
    segments.emplace_back(make());
    ASSERT_NE(-1, *segments[i]);
    Share()->segid[i] = *segments[i];
  }
  SignalAllStartFinish();  // Start peers and wait for them to finish

  while (segid_count-- > 0) {
    for (int i = 0; i < size; i += page_size() / 2) {
      seed = pattern_next(seed);
      if (!segid_count) {
        EXPECT_EQ(static_cast<uint8_t>(seed),
                  *(static_cast<uint8_t*>(data_ptr) + i));
      }
    }
  }
}

TEST_P(test_multi_xpmem_peers_pages, parallel_multi_reverse) {
  int peers = std::get<0>(GetParam());
  int pages = std::get<1>(GetParam());
  auto size = page_size() * pages;
  data_ptr = mmap(size);
  data_size = size;

  ASSERT_NE(nullptr, data_ptr);

  auto fork_action = [&](void* ptr) {
    auto data = static_cast<uint8_t*>(ptr);
    for (int i = size - 1; i >= 0; i -= page_size()) {
      seed = pattern_next(seed);
      data[i] = seed;
    }
  };
  StartAttach(peers, data_ptr, size, fork_action);

  Share()->segid[0] = *segid;
  SignalAllStartFinish();

  for (int i = size - 1; i >= 0; i -= page_size()) {
    seed = pattern_next(seed);
    EXPECT_EQ(static_cast<uint8_t>(seed),
              *(static_cast<uint8_t*>(data_ptr) + i));
  }
}

TEST_P(test_multi_xpmem_peers_pages, parallel_multi_random_seq) {
  int peers = std::get<0>(GetParam());
  int pages = std::get<1>(GetParam());
  auto size = page_size() * pages;
  data_ptr = mmap(size);
  data_size = size;

  ASSERT_NE(nullptr, data_ptr);

  auto sequence = randomized_sequence(pages);
  auto fork_action = [&](void* ptr) {
    auto data = static_cast<uint8_t*>(ptr);
    for (auto i : sequence) {
      *reinterpret_cast<uint32_t*>(data + i * page_size()) = i;
    }
  };
  StartAttach(peers, data_ptr, size, fork_action);

  Share()->segid[0] = *segid;
  SignalAllStartFinish();

  auto ptr = static_cast<uint8_t*>(data_ptr);
  for (int i = 0; i < pages; i++) {
    auto data = reinterpret_cast<uint32_t*>(ptr + i * page_size());
    EXPECT_EQ(i, *data);
  }
}

TEST_P(test_multi_xpmem_peers_pages, sequential_multi) {
  int peers = std::get<0>(GetParam());
  int pages = std::get<1>(GetParam());
  auto size = page_size() * pages;
  data_ptr = mmap(size);
  data_size = size;

  ASSERT_NE(nullptr, data_ptr);
  memset(data_ptr, 0, size);

  auto fork_action = [&](void* ptr) {
    auto data = static_cast<uint8_t*>(ptr);
    for (int i = 0; i < pages; i++) {
      *reinterpret_cast<uint32_t*>(data + i * page_size()) += i * Id();
    }
  };
  StartAttach(peers, data_ptr, size, fork_action);

  Share()->segid[0] = *segid;

  // Peers all work in sequence
  for (int i = 1; i <= peers; i++) {
    Signal(i);  // Start
    Signal(i);  // Wait for completion, unblocks it to finish
  }

  auto ptr = static_cast<uint8_t*>(data_ptr);
  int expect = peers * (peers + 1) / 2;
  for (int i = 0; i < pages; i++) {
    auto data = reinterpret_cast<uint32_t*>(ptr + i * page_size());
    EXPECT_EQ(i * expect, *data);
  }
}

TEST_P(test_multi_xpmem_peers_pages, test_fork) {
  int peers = std::get<0>(GetParam());
  int pages = std::get<1>(GetParam());
  auto size = page_size() * pages;
  data_ptr = mmap(size);
  ASSERT_NE(nullptr, data_ptr);
  data_size = size;

  auto ptr = static_cast<uint8_t*>(data_ptr);
  for (int i = 0; i < pages; i++) {
    *reinterpret_cast<uint32_t*>(ptr + i * page_size()) = i;
  }

  int start = pages / 2;
  int end = std::max(2 * pages / 3, 1);

  INFO << "page range [" << start << ", " << end << "(\n";

  Start(peers, [&]() {
    Wait();

    auto sid = Share()->segid[0];
    ASSERT_NE(-1, sid);
    auto aid = get(sid);
    ASSERT_NE(-1, *aid);
    auto att_ptr = attach(*aid, data_ptr, size);
    ASSERT_NE((void*)-1, att_ptr.get());

    auto ptr = static_cast<uint8_t*>(att_ptr.get());
    for (int i = start; i < end; i++) {
      auto data = reinterpret_cast<uint32_t*>(ptr + i * page_size());

      EXPECT_EQ(i, *data);
      if (i != *data) {
        break;
      }
    }

    Wait();  // Wait for fork()/COW
    for (int i = start; i < end; i++) {
      auto data = reinterpret_cast<uint32_t*>(ptr + i * page_size());
      EXPECT_EQ(2 * i, *data);
      if (2 * i != *data) {
        break;
      }
    }
    Wait();
    for (int i = start; i < end; i++) {
      if (Id() == 1) {
        auto data = reinterpret_cast<uint32_t*>(ptr + i * page_size());
        *data += i;
      }
    }
    Wait();
  });

  Share()->segid[0] = *segid;

  SignalAll();  // Start and wait for peers
  WaitForAll();

  pid_t pid = fork();
  EXPECT_LT(-1, pid);

  if (!pid) {
    for (;;) {
      sleep(1);  // waiting for kill signal below
    }
    exit(0);
  } else {
    // Trigger COW
    for (int i = 0; i < pages; i++) {
      *reinterpret_cast<uint32_t*>(ptr + i * page_size()) += i;
    }

    SignalAll();   // Unblock peer, after COW
    SignalAll();   // Trigger peer Id() == 1 adding
    WaitForAll();  // Wait for all of the them to finish

    for (int i = 0; i < pages; i++) {
      int expect = 2;
      if (i >= start && i < end) {
        expect++;
      }

      auto value = *reinterpret_cast<uint32_t*>(ptr + i * page_size());
      EXPECT_EQ(expect * i, value);
    }
    kill(pid, SIGTERM);
    int status;
    int ret = waitpid(pid, &status, 0);
    EXPECT_GT(ret, -1);
    EXPECT_TRUE(WIFSIGNALED(status));
    EXPECT_EQ(SIGTERM, WTERMSIG(status));
    SignalAll();
  }
}

INSTANTIATE_TEST_SUITE_P(
    peers_pages, test_multi_xpmem_peers_pages,
    testing::Combine(testing::Values(1, 3, 5, 10),
                     testing::Values(1, 2, 3, 4, 5, 6, 10, 100, 200, 500, 1000,
                                     10000, 100 * 1000)),
    [](const testing::TestParamInfo<test_multi_xpmem_peers_pages::ParamType>&
           info) {
      std::stringstream ss;
      auto peers = std::get<0>(info.param);
      auto pages = std::get<1>(info.param);
      ss << "peers_" << peers << "_pages_" << pages;
      return ss.str();
    });

class test_multi_xpmem_holes
    : public test_multi_xpmem,
      public testing::WithParamInterface<std::tuple<int, int, int>> {};

TEST_P(test_multi_xpmem_holes, p2p_fault_vma_holes) {
  int peers = 1;
  size_t hole_size = std::get<0>(GetParam()) * page_size();
  size_t size = std::get<1>(GetParam()) * page_size();
  auto count = std::get<2>(GetParam());
  size_t overall = count * (hole_size + size) + hole_size;

  mmap_areas mappings;
  bool ret = mappings.make_holes(hole_size, size, count);
  ASSERT_TRUE(ret);

  auto areas = mappings.areas();
  auto hole = areas.front().ptr() - hole_size;

  auto fork_action = [&](void* ptr) {
    size_t total = 0;
    for (int i = 0; i < count; i++) {
      auto area =
          reinterpret_cast<uint8_t*>(ptr) + hole_size + i * (size + hole_size);
      for (int j = 0; j < size; j += sizeof(uint32_t)) {
        total += *reinterpret_cast<uint32_t*>(area + j);
      }
    }
    auto expect_size = mmap_areas::holes_sum(size, count);
    EXPECT_EQ(expect_size, total);
  };
  StartAttach(peers, hole, overall, fork_action);

  Share()->segid[0] = *segid;

  SignalAllStartFinish();
}

INSTANTIATE_TEST_SUITE_P(
    holes, test_multi_xpmem_holes,
    testing::Combine(testing::Values(0, 1, 2, 4, 8, 16, 32, 64, 128),
                     testing::Values(1, 2, 4, 8, 16, 32, 64, 128),
                     testing::Values(16, 64)),
    [](const testing::TestParamInfo<test_multi_xpmem_holes::ParamType>& info) {
      std::stringstream ss;
      auto hole_pages = std::get<0>(info.param);
      auto pages = std::get<1>(info.param);
      auto count = std::get<2>(info.param);

      ss << "hole_" << hole_pages << "_pages_" << pages << "_count_" << count;
      return ss.str();
    });

TEST_F(test_multi_xpmem, p2p_fault_vma_holes_death) {
  int peers = 1;
  size_t hole_size = 2 * page_size();
  size_t size = 1 * page_size();
  auto count = 128;
  size_t overall = count * (hole_size + size) + hole_size;

  mmap_areas mappings;
  bool ret = mappings.make_holes(hole_size, size, count);
  ASSERT_TRUE(ret);

  auto areas = mappings.areas();
  auto hole = areas.front().ptr() - hole_size;

  CoreDumpDisable no_core;
  auto fork_action = [&](void* ptr) {
    auto area = reinterpret_cast<uint8_t*>(ptr) + hole_size / 2 +
                count / 2 * (size + hole_size);
    *reinterpret_cast<uint16_t*>(area) = 0xbad;
  };
  StartAttach(peers, hole, overall, fork_action, 1, true);

  Share()->segid[0] = *segid;
  SignalAll();
  WaitpidAll(hole_size ? SIGBUS : 0);
}
