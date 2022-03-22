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
#ifndef QCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SAMPLES_NRF52832_QCLOUD_BLE_ADV_CFG_BLE_QIOT_ADV_CFG_H_
#define QCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SAMPLES_NRF52832_QCLOUD_BLE_ADV_CFG_BLE_QIOT_ADV_CFG_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include "nrf_log.h"
#include "nrf_log_internal.h"
#include "ble_qiot_adv_center.h"

// Does the device support simultaneous Bluetooth adverting and scanning?
#ifndef LLSYNC_DEV_ADV_AND_SCAN
#define LLSYNC_DEV_ADV_AND_SCAN 1
#endif

// Unconfigured adv interval：32*0.625=20ms
#define LLSYNC_ADV_INTERVAL               (0x20)

/**< The adverting time-out (in units of seconds). When set to 0, we will never time out. */
#define APP_ADV_DURATION    BLE_GAP_ADV_TIMEOUT_GENERAL_UNLIMITED

// The interval duration cannot exceed the window duration, if the two are equal, it means continuous scanning
#define LLSYNC_SCAN_WINDOW                (0x10)
#define LLSYNC_SCAN_INTERVAL              (0x10)

// Timer period(ms)
#define LLSYNC_ADV_TIMER_INTERVAL         (10)

#define LLSYNC_ADV_RECORD_FLASH_ADDR      0x7e000  // qiot data storage address
#define LLSYNC_ADV_RECORD_FLASH_PAGESIZE  4096     // flash page size, see chip datasheet
#define BLE_QIOT_RECORD_FLASH_PAGENUM     2        // how many pages qiot use

#define LLSYNC_ADV_LOG_PRINT(...)        NRF_LOG_INTERNAL_INFO(__VA_ARGS__)

#define APP_BLE_CONN_CFG_TAG  1 /**< A tag identifying the SoftDevice BLE configuration. */

#ifdef __cplusplus
}
#endif
#endif  // QCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SAMPLES_NRF52832_QCLOUD_BLE_ADV_CFG_BLE_QIOT_ADV_CFG_H_
