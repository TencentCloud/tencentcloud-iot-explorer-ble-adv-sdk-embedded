/*
 * Copyright (C) 2019 Tencent. All rights reserved.
 * Licensed under the MIT License (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://opensource.org/licenses/MIT
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#ifndef TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_INCLUDE_BLE_QIOT_ADV_EXPORT_H_
#define TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_INCLUDE_BLE_QIOT_ADV_EXPORT_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

typedef enum {
    LLSYNC_ADV_RS_OK             = 0,   // success
    LLSYNC_ADV_RS_ERR            = -1,  // normal error
    LLSYNC_ADV_RS_ERR_FLASH      = -2,  // flash error
    LLSYNC_ADV_RS_ERR_PARA       = -3,  // parameters error
    LLSYNC_ADV_RS_VALID_SIGN_ERR = -4,
} ble_qiot_ret_status_t;

/**
 * @brief Scan data analysis function.
 * @param buf Scanned Bluetooth advertising data, Note that the data sent for analysis here needs to conform to the AD Structure.
 * @param buf_len data length
 * @return LLSYNC_ADV_RS_OK is success, other is error
 */
ble_qiot_ret_status_t ble_scan_data_analyze(uint8_t *buf, uint8_t buf_len);

/**
 * @brief Timer callback function, The timer execution period is LLSYNC_ADV_TIMER_INTERVAL.
 * @param param set to NULL
 * @return none
 */
void llsync_adv_timer_cb(void *param);

/**
 * @brief Device current status reporting interface.
 * @param param void
 * @return LLSYNC_ADV_RS_OK is success, other is error
 */
ble_qiot_ret_status_t llsync_adv_property_report(void);

/**
 * @brief SDK startup function.
 * @param param void
 * @return LLSYNC_ADV_RS_OK is success, other is error
 */
ble_qiot_ret_status_t llsync_adv_init(void);

#ifdef __cplusplus
}
#endif
#endif  // TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_INCLUDE_BLE_QIOT_ADV_EXPORT_H_
