# ipdk-io/krnlmon
The Kernel Monitor receives RFC 3549 messages from the Linux Kernel over a Netlink socket when changes are made to the kernel networking data structures.

## Breaking changes

Since there is a change in p4 program, where nexthop table has been moved to
WCM block from SEM block (exact match). TDI provides seperate API's for each
block. Since Ternary/WCM needs a MASK to be populated we need to use a newer
API which can take mask as a parameter. Changes with a MACRO has been
introduced in `switchapi/es2k/switch_pd_routing.c`, which defines ternary match
MACRO enablement. If user wants to pick older p4 program, then user need to
modify this MACRO value to 0 and re-build infrap4d to be compatible with
older Exact match type for nexthop table.

PR: https://github.com/ipdk-io/krnlmon/pull/59 introduces this breakage changes.
