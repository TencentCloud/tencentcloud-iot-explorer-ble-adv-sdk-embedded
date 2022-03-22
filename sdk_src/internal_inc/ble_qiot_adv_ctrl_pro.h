/*
 * Copyright (C) 2019 THL A29 Limited, a Tencent company. All rights reserved.
 * Licensed under the MIT License (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://opensource.org/licenses/MIT
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#ifndef TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SDK_INTERNAL_INC_BLE_QIOT_ADV_CTRL_PRO_H_
#define TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SDK_INTERNAL_INC_BLE_QIOT_ADV_CTRL_PRO_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include "ble_qiot_adv_center.h"

// tlv header define, bit 7 - 5 is type, bit 4 - 0 depends on type of data template
#define BLE_QIOT_PARSE_TLV_HEAD_TYPE(_C)        (((_C) & 0XFF) >> 5)
#define BLE_QIOT_PARSE_TLV_HEAD_ID(_C)          ((_C) & 0X1F)

#define BLE_QIOT_EVENT_MAX_SIZE (128)

#define LLSYNC_ADV_SPLIT_DATA_BUILD(x, y) ((x << 4) | (y+1))

#define LLSYNC_ADV_MSG_HEADER_BUILD(x, y) ((x << 4) | (y))

#define LLSYNC_ADV_PROPERTY_DATA_MAX      (127)

typedef struct {
    bool adv_ok;
    uint8_t send_buf[LLSYNC_ADV_MAX_RECV_DATA_LEN];
    uint8_t send_whole_len;
    uint8_t send_data_len;
    uint8_t split_send_num;
    uint8_t split_total_num;
    uint8_t adv_resend_time;
}llsync_adv_property_report_t;

bool llsync_adv_data_split_finish(void);

ble_qiot_ret_status_t llsync_adv_property_data_report(void);

void llsync_adv_property_report_again(void);

void llsync_pro_get_data(void);

bool llsync_pro_fifo_is_empty(void);

ble_qiot_ret_status_t llsync_adv_ctrl_data_handle(const char *in_buf, int buf_len);

void llsync_adv_property_fifo_init(void);

#ifdef __cplusplus
}
#endif
#endif  // TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SDK_INTERNAL_INC_BLE_QIOT_ADV_CTRL_PRO_H_
