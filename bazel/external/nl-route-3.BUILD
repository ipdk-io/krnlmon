# //bazel/external/nl-3.BUILD

# Copyright 2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_import")

package(
    default_visibility = ["//visibility:public"],
)

cc_import(
    name = "nl-3",
    hdrs = glob(["netlink/**/*.h"]),
    includes = ["/usr/include/libnl3"],
    system_provided = 1,
)
