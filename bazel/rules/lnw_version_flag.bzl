# //bazel/rules:lnw_version_flag.bzl

# Copyright 2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Defines a build_setting rule for the Linux Networking version.
# Used to define the //flags:lnw_version command-line flag.

# https://github.com/bazelbuild/examples/tree/HEAD/configurations/basic_build_setting

LinuxNetworkingVersion = provider(doc = "", fields = ["version"])

valid_versions = [2, 3]

def _impl(ctx):
    raw_value = ctx.build_setting_value
    if raw_value not in valid_versions:
        msg = str(ctx.label) + ": lnw_version accepts values {" + \
              ",".join([str(x) for x in valid_versions]) + \
              "} but was set to " + str(raw_value)
        fail(msg)

    return LinuxNetworkingVersion(version = raw_value)

lnw_version_flag = rule(
    implementation = _impl,
    build_setting = config.int(flag = True),
)
