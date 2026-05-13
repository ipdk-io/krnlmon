<!-- markdownlint-disable MD041 -->
[![Krnlmon CI Pipeline](https://github.com/ipdk-io/krnlmon/actions/workflows/pipeline.yml/badge.svg)](https://github.com/ipdk-io/krnlmon/actions/workflows/pipeline.yml)
<!-- markdownlint-enable MD041 -->

# THIS PROJECT IS ARCHIVED
Intel will not provide or guarantee development of or support for this project, including but not limited to, maintenance, bug fixes, new releases or updates.  
Patches to this project are no longer accepted by Intel.   
If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the community, please create your own fork of the project. 

# ipdk-io/krnlmon

The Kernel Monitor receives RFC 3549 messages from the Linux Kernel over a
Netlink socket when changes are made to the kernel networking data structures.

## Breaking changes

### 11 Oct 2023

- https://github.com/ipdk-io/krnlmon/pull/59: The NextHop table in the P4
program has been moved from the SEM block (exact match) to the WCM block
(ternary block). The Kernel Monitor must use a different API to write the
entry to the WCM block. krnlmon is no longer compatible with older versions
of the P4 program.
