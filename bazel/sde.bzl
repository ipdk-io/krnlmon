# //bazel/sde.bzl

# Copyright 2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

load("//bazel:variables.bzl", "NO_MATCH_ERROR")

TARGET_SDE = select(
    {
        "//:dpdk_target": ["@local_dpdk_bin//:sde"],
        "//:es2k_target": ["@local_es2k_bin//:sde"],
    },
    no_match_error = NO_MATCH_ERROR,
)

TARGET_SDE_HDRS = select(
    {
        "//:dpdk_target": ["@local_dpdk_bin//:sde_hdrs"],
        "//:es2k_target": ["@local_es2k_bin//:sde_hdrs"],
    },
    no_match_error = NO_MATCH_ERROR,
)

TARGET_SDE_LIBS = select(
    {
        "//:dpdk_target": ["@local_dpdk_bin//:sde_libs"],
        "//:es2k_target": ["@local_es2k_bin//:sde_libs"],
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
