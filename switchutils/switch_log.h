#ifndef KRNLMON_LOG_INCLUDED
#define KRNLMON_LOG_INCLUDED

#include "bf_sal/bf_sys_intf.h"
#include "bf_sal/bf_sys_log.h"

#define krnlmon_log_critical(...) \
bf_sys_log_and_trace(KRNLMON, BF_LOG_CRIT, __VA_ARGS__)

#define krnlmon_log_error(...) \
bf_sys_log_and_trace(KRNLMON, BF_LOG_ERR, __VA_ARGS__)

#define krnlmon_log_warn(...) \
bf_sys_log_and_trace(KRNLMON, BF_LOG_WARN, __VA_ARGS__)

#define krnlmon_log_info(...) \
bf_sys_log_and_trace(KRNLMON, BF_LOG_INFO, __VA_ARGS__)

#define krnlmon_log_debug(...) \
bf_sys_log_and_trace(KRNLMON, BF_LOG_DBG, __VA_ARGS__)

#define krnlmon_log krnlmon_log_debug

#endif  // KRNLMON_LOG_INCUDED
