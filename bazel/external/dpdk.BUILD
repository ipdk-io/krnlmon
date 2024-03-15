# //bazel/external/dpdk.BUILD

# Copyright 2020-present Open Networking Foundation
# Copyright 2022-2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_library")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "sde_libs",
    srcs = glob([
        "dpdk-bin/lib/libbf_switchd_lib.so*",
        "dpdk-bin/lib/libclish.so",
        "dpdk-bin/lib/libdriver.so",
        "dpdk-bin/lib/libtdi.so*",
        "dpdk-bin/lib/libtdi_json_parser.so*",
    ]),
    linkopts = [
        "-lpthread",
        "-lm",
        "-ldl",
    ],
)

cc_library(
    name = "sde_hdrs",
    hdrs = glob([
        "dpdk-bin/include/bf_pal/*.h",
        "dpdk-bin/include/bf_rt/**/*.h",
        "dpdk-bin/include/bf_switchd/**/*.h",
        "dpdk-bin/include/bf_types/*.h",
        "dpdk-bin/include/cjson/*.h",
        "dpdk-bin/include/dvm/*.h",
        "dpdk-bin/include/fixed_function/*.h",
        "dpdk-bin/include/lld/*.h",
        "dpdk-bin/include/osdep/*.h",
        "dpdk-bin/include/pipe_mgr/**/*.h",
        "dpdk-bin/include/port_mgr/**/*.h",
    ]),
    strip_include_prefix = "dpdk-bin/include",
)

cc_library(
    name = "sde",
    deps = [
        ":sde_hdrs",
        ":sde_libs",
    ],
)

cc_library(
    name = "dpdk_rte",
    srcs = glob(["dpdk-bin/lib/x86_64-linux-gnu/*.so*"]),
)

cc_library(
    name = "judy",
    srcs = ["dpdk-bin/lib/libtarget_utils.so"],
    hdrs = glob([
        "dpdk-bin/include/target-utils/third-party/judy-1.0.5/src/*.h",
    ]),
    strip_include_prefix = "dpdk-bin/include/target-utils/third-party/",
)

cc_library(
    name = "target_sys",
    srcs = ["dpdk-bin/lib/libtarget_sys.so"],
    hdrs = glob(["dpdk-bin/include/target-sys/**/*.h"]),
    linkopts = [
        "-lpthread",
        "-lm",
        "-ldl",
    ],
    strip_include_prefix = "dpdk-bin/include",
)

cc_library(
    name = "target_utils",
    srcs = ["dpdk-bin/lib/libtarget_utils.so"],
    hdrs = glob(["dpdk-bin/include/target-utils/**/*.h"]),
    linkopts = [
        "-lpthread",
        "-lm",
        "-ldl",
    ],
    strip_include_prefix = "dpdk-bin/include",
    deps = [":target_sys"],
)

cc_library(
    name = "tdi",
    hdrs = glob([
        "dpdk-bin/include/tdi/**/*.h",
        "dpdk-bin/include/tdi/**/*.hpp",
        "dpdk-bin/include/tdi_rt/**/*.h",
        "dpdk-bin/include/tdi_rt/**/*.hpp",
    ]),
    strip_include_prefix = "dpdk-bin/include",
)

cc_library(
    name = "tommyds",
    srcs = ["dpdk-bin/lib/libtarget_utils.so"],
    hdrs = glob([
        "dpdk-bin/include/target-utils/third-party/tommyds/tommyds/*.h",
    ]),
    strip_include_prefix = "dpdk-bin/include/target-utils/third-party/tommyds",
)

cc_library(
    name = "xxhash",
    srcs = ["dpdk-bin/lib/libtarget_utils.so"],
    hdrs = glob([
        "dpdk-bin/include/target-utils/third-party/xxHash/xxHash/*.h",
    ]),
    strip_include_prefix = "dpdk-bin/include/target-utils/third-party/xxHash",
)
