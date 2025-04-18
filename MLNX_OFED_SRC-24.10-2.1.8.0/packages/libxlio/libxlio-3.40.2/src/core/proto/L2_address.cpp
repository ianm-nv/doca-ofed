/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "core/proto/L2_address.h"

#define MODULE_NAME "L2_addr"

#define L2_panic      __log_panic
#define L2_logerr     __log_info_err
#define L2_logwarn    __log_info_warn
#define L2_loginfo    __log_info_info
#define L2_logdbg     __log_info_dbg
#define L2_logfunc    __log_info_func
#define L2_logfuncall __log_info_funcall

L2_address::L2_address(address_t const address, addrlen_t const len)
{
    set(address, len);
}

void L2_address::set(address_t const address, addrlen_t const len)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (len <= 0 || len > L2_ADDR_MAX) {
        L2_panic("len = %lu", len);
    }

    if (!address) {
        L2_panic("address == NULL");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    // Copy the new address
    m_len = len;
    memcpy((void *)m_p_raw_address, (void *)address, m_len);
}

bool L2_address::compare(L2_address const &other) const
{
    if (other.m_len != m_len) {
        return false;
    }
    return (!memcmp((void *)other.m_p_raw_address, (void *)m_p_raw_address, m_len));
}

const std::string ETH_addr::to_str() const
{
    char s[100] = "";
    if (m_len > 0) {
        sprintf(s, ETH_HW_ADDR_PRINT_FMT, ETH_HW_ADDR_PRINT_ADDR(m_p_raw_address));
    }
    return (std::string(s));
}
