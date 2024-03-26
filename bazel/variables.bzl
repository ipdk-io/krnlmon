# //bazel/variables.bzl

# Copyright 2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

TARGET_DEFINES = select(
    {
        "//:dpdk_target": ["DPDK_TARGET"],
        "//:es2k_target": ["ES2K_TARGET"],
    },
    no_match_error = "must specify --define target={dpdk|es2k}",
)
