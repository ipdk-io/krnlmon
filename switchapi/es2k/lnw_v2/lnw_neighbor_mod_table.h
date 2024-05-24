/*
 * Copyright 2022-2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * NEIGHBOR_MOD_TABLE for Linux Networking v2.
 */

#ifndef __LNW_NEIGHBOR_MOD_TABLE_H__
#define __LNW_NEIGHBOR_MOD_TABLE_H__

#define LNW_NEIGHBOR_MOD_TABLE "linux_networking_control.neighbor_mod_table"

#define LNW_NEIGHBOR_MOD_TABLE_KEY_VENDORMETA_MOD_DATA_PTR \
  "vmeta.common.mod_blob_ptr"

#define LNW_NEIGHBOR_MOD_TABLE_ACTION_SET_OUTER_MAC \
  "linux_networking_control.set_outer_mac"
#define LNW_ACTION_SET_OUTER_MAC_PARAM_DST_MAC_ADDR "dst_mac_addr"

#endif /* __LNW_NEIGHBOR_MOD_TABLE_H__ */
