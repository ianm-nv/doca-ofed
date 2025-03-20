/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef SYNC_H
#include <common/xpmem_test.h>

struct Area {
  uint64_t value;
  xpmem_segid_t segid[16];
};

// Simplest user synchro: transitions: 2- waiting, 1- signaled, 0- consumed it
class Sync {
  Area* m_area;
  int m_id;

 protected:
  int m_count;

 public:
  Sync() : m_id(0), m_count(1) {}

  void SetArea(Area* area) {
    m_area = area;
    memset(m_area, 0, sizeof(*m_area));
  }
  void Self(int id) { m_id = id; }

  int Id() const { return m_id; }

  static uint64_t id_sig(int id = 0) { return 1LLU << (id << 1); }
  static uint64_t id_wait(int id = 0) { return id_sig(id) << 1; }
  static uint64_t id_mask(int id = 0) { return id_sig(id) | id_wait(id); }
  uint64_t id_all(uint64_t mask, int exclude) {
    uint64_t out = 0;
    for (int i = 0; i < m_count; i++, mask <<= 2) {
      if (exclude != i) {
        out |= mask;
      }
    }
    return out;
  }

  bool cas(uint64_t old, uint64_t value) {
    bool weak = true;
    return __atomic_compare_exchange_n(&m_area->value, &old, value, weak,
                                       __ATOMIC_RELEASE, __ATOMIC_ACQUIRE);
  }

  Area* Share() { return m_area; }

  void Done() {
    bool done = false;
    do {
      auto old = __atomic_load_n(&m_area->value, __ATOMIC_ACQUIRE);
      auto value = old & ~id_mask(m_id);
      done = cas(old, value | id_wait(m_id));
    } while (!done);
  }

  void WaitSig() {
    bool done = false;
    int tries = Id() * 5;
    do {
      tries--;
      if (!tries) {
        sched_yield();
        tries = Id() * 5;
      }

      auto old = __atomic_load_n(&m_area->value, __ATOMIC_ACQUIRE);
      if ((old & id_mask(m_id)) != id_sig(m_id)) {
        continue;
      }
      done = cas(old, old & ~id_mask(m_id));
    } while (!done);
  }

  void Wait() {
    Done();
    WaitSig();
  }

  void WaitForMask(uint64_t mask, uint64_t value) {
    decltype(m_area->value) old;
    do {
      old = __atomic_load_n(&m_area->value, __ATOMIC_ACQUIRE);
    } while ((old & mask) != value);
  }
  void WaitFor(int id) { WaitForMask(id_mask(id), id_wait(id)); }
  void WaitForAll() {
    WaitForMask(id_all(id_mask(), m_id), id_all(id_wait(), m_id));
  }
  void SignalMask(uint64_t mask, uint64_t expect, uint64_t value) {
    bool done = false;
    int tries = Id() * 5;
    do {
      tries--;
      if (!tries) {
        sched_yield();
        tries = Id();  // Lower ID, higher priority
      }
      auto old = __atomic_load_n(&m_area->value, __ATOMIC_ACQUIRE);
      if ((old & mask) != expect) {
        continue;
      }
      done = cas(old, (old & ~mask) | value);
    } while (!done);
  }

  void Signal(int id) { SignalMask(id_mask(id), id_wait(id), id_sig(id)); }
  void SignalAll() {
    SignalMask(id_all(id_mask(), m_id), id_all(id_wait(), m_id),
               id_all(id_sig(), m_id));
  }
};
#endif  // SYNC_H
