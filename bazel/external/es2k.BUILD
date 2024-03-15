# bazel/external/es2k.BUILD

# Copyright 2023-2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_library")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "sde_libs",
    srcs = glob([
        # "es2k-bin/lib/libacccp.so",
        "es2k-bin/lib/libclish.so",
        "es2k-bin/lib/libcpf.so",
        "es2k-bin/lib/libcpf_pmd_infra.so",
        "es2k-bin/lib/libdriver.so*",
        "es2k-bin/lib/libipu_p4d_lib.so*",
        "es2k-bin/lib/libpython3.10.so*",
        "es2k-bin/lib/libvfio.so",
        "es2k-bin/lib/libxeoncp.so",
        "es2k-bin/lib/x86_64-linux-gnu/*.so*",
    ]),
    linkopts = [
        "-L/usr/lib/x86_64-linux-gnu",
        "-lglib-2.0",
        "-lpthread",
        "-lm",
        "-ldl",
    ],
)

cc_library(
    name = "sde_hdrs",
    hdrs = glob([
        "es2k-bin/include/cjson/*.h",
        "es2k-bin/include/dvm/*.h",
        "es2k-bin/include/ipu_p4d/**/*.h",
        "es2k-bin/include/ipu_pal/*.h",
        "es2k-bin/include/ipu_types/*.h",
        "es2k-bin/include/osdep/*.h",
        "es2k-bin/include/port_mgr/**/*.h",
    ]),
    strip_include_prefix = "es2k-bin/include",
)

cc_library(
    name = "sde",
    deps = [
        ":sde_hdrs",
        ":sde_libs",
    ],
)

cc_library(
    name = "judy",
    srcs = ["es2k-bin/lib/libtarget_utils.so"],
    hdrs = glob([
        "es2k-bin/include/target-utils/third-party/judy-1.0.5/src/*.h",
    ]),
    strip_include_prefix = "es2k-bin/include/target-utils/third-party/",
)

cc_library(
    name = "target_sys",
    srcs = ["es2k-bin/lib/libtarget_sys.so"],
    hdrs = glob(["es2k-bin/include/target-sys/**/*.h"]),
    strip_include_prefix = "es2k-bin/include",
)

cc_library(
    name = "target_utils",
    srcs = ["es2k-bin/lib/libtarget_utils.so"],
    hdrs = glob(["es2k-bin/include/target-utils/**/*.h"]),
    linkopts = [
        "-lpthread",
        "-lm",
        "-ldl",
    ],
    strip_include_prefix = "es2k-bin/include",
    deps = [":target_sys"],
)

cc_library(
    name = "tdi",
    srcs = [
        "es2k-bin/lib/libtdi.so",
        "es2k-bin/lib/libtdi_json_parser.so",
        "es2k-bin/lib/libtdi_pna.so",
    ],
    hdrs = glob([
        "es2k-bin/include/tdi/**/*.h",
        "es2k-bin/include/tdi/**/*.hpp",
        "es2k-bin/include/tdi_rt/*.h",
    ]),
    strip_include_prefix = "es2k-bin/include",
)

cc_library(
    name = "tommyds",
    srcs = ["es2k-bin/lib/libtarget_utils.so"],
    hdrs = glob([
        "es2k-bin/include/target-utils/third-party/tommyds/tommyds/*.h",
    ]),
    strip_include_prefix = "es2k-bin/include/target-utils/third-party/tommyds",
)

cc_library(
    name = "xxhash",
    srcs = ["es2k-bin/lib/libtarget_utils.so"],
    hdrs = glob([
        "es2k-bin/include/target-utils/third-party/xxHash/xxHash/*.h",
    ]),
    strip_include_prefix = "es2k-bin/include/target-utils/third-party/xxHash",
)
