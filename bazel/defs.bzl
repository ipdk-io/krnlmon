# //bazel/defs.bzl

# Copyright 2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

NO_MATCH_ERROR = "Please specify --define target={dpdk|es2k}"

TARGET_DEFINES = select(
    {
        "//flags:dpdk_target": ["DPDK_TARGET"],
        "//flags:es2k_target": ["ES2K_TARGET"],
    },
    no_match_error = NO_MATCH_ERROR,
)

LNW_DEFINES = select(
    {
        "//flags:lnw_v2": ["LNW_V2"],
        "//flags:lnw_v3": ["LNW_V3"],
        "//conditions:default": [],
    },
)
