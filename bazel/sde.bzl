# //bazel/sde.bzl

# Copyright 2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

load("//bazel:variables.bzl", "NO_MATCH_ERROR")

JUDY = select(
    {
        "//:dpdk_target": ["@local_dpdk_bin//:judy"],
        "//:es2k_target": ["@local_es2k_bin//:judy"],
    },
    no_match_error = NO_MATCH_ERROR,
)

TARGET_SDE = select(
    {
        "//:dpdk_target": ["@local_dpdk_bin//:sde"],
        "//:es2k_target": ["@local_es2k_bin//:sde"],
    },
    no_match_error = NO_MATCH_ERROR,
)

TARGET_SYS = select(
    {
        "//:dpdk_target": ["@local_dpdk_bin//:target_sys"],
        "//:es2k_target": ["@local_es2k_bin//:target_sys"],
    },
    no_match_error = NO_MATCH_ERROR,
)

TARGET_TDI = select(
    {
        "//:dpdk_target": ["@local_dpdk_bin//:tdi"],
        "//:es2k_target": ["@local_es2k_bin//:tdi"],
    },
    no_match_error = NO_MATCH_ERROR,
)

TARGET_UTILS = select(
    {
        "//:dpdk_target": ["@local_dpdk_bin//:target_utils"],
        "//:es2k_target": ["@local_es2k_bin//:target_utils"],
    },
    no_match_error = NO_MATCH_ERROR,
)

TOMMYDS = select(
    {
        "//:dpdk_target": ["@local_dpdk_bin//:tommyds"],
        "//:es2k_target": ["@local_es2k_bin//:tommyds"],
    },
    no_match_error = NO_MATCH_ERROR,
)

XXHASH = select(
    {
        "//:dpdk_target": ["@local_dpdk_bin//:xxhash"],
        "//:es2k_target": ["@local_es2k_bin//:xxhash"],
    },
    no_match_error = NO_MATCH_ERROR,
)
