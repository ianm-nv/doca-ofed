#
# Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2021. ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

get_filename_component(prefix "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(exec_prefix "${prefix}")

if(NOT TARGET ucx::ucs)
  add_library(ucx::ucs SHARED IMPORTED)

  set_target_properties(ucx::ucs PROPERTIES
    IMPORTED_LOCATION "${exec_prefix}/lib64/libucs.so"
    INTERFACE_INCLUDE_DIRECTORIES "${prefix}/include"
  )
endif()

if(NOT TARGET ucx::ucp)
  add_library(ucx::ucp SHARED IMPORTED)

  set_target_properties(ucx::ucp PROPERTIES
    IMPORTED_LOCATION "${exec_prefix}/lib64/libucp.so"
    INTERFACE_INCLUDE_DIRECTORIES "${prefix}/include"
  )
endif()

if(NOT TARGET ucx::uct)
  add_library(ucx::uct SHARED IMPORTED)

  set_target_properties(ucx::uct PROPERTIES
    IMPORTED_LOCATION "${exec_prefix}/lib64/libuct.so"
    INTERFACE_INCLUDE_DIRECTORIES "${prefix}/include"
  )
endif()
