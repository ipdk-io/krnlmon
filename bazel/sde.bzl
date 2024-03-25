# //bazel/sde.bzl

# Copyright 2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

load("//bazel:defs.bzl", "NO_MATCH_ERROR")

TARGET_SDE = select(
    {
        "//bazel:dpdk_target": ["@local_dpdk_bin//:sde"],
        "//bazel:es2k_target": ["@local_es2k_bin//:sde"],
    },
    no_match_error = NO_MATCH_ERROR,
)

TARGET_SDE_HDRS = select(
    {
        "//bazel:dpdk_target": ["@local_dpdk_bin//:sde_hdrs"],
        "//bazel:es2k_target": ["@local_es2k_bin//:sde_hdrs"],
    },
    no_match_error = NO_MATCH_ERROR,
)

TARGET_SDE_LIBS = select(
    {
        "//bazel:dpdk_target": ["@local_dpdk_bin//:sde_libs"],
        "//bazel:es2k_target": ["@local_es2k_bin//:sde_libs"],
    },
    no_match_error = NO_MATCH_ERROR,
)

TARGET_TDI = select(
    {
        "//bazel:dpdk_target": ["@local_dpdk_bin//:tdi"],
        "//bazel:es2k_target": ["@local_es2k_bin//:tdi"],
    },
    no_match_error = NO_MATCH_ERROR,
)
