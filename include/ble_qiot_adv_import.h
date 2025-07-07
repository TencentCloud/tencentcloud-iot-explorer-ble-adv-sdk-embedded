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
#ifndef TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_INCLUDE_BLE_QIOT_ADV_IMPORT_H_
#define TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_INCLUDE_BLE_QIOT_ADV_IMPORT_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

/**
 * @brief create timer func
 * @param type Loop or single
 * @param timeout_handle timeout callback
 * @return timer handle
 * @note the timer callbanck function is llsync_adv_timer_cb(NULL);
 */
ble_timer_t llsync_timer_create(uint8_t type, ble_timer_cb timeout_handle);

/**
 * @brief start timer func
 * @param timer_id llsync_timer_create to reutrn
 * @param period Timer period
 * @return BLE_QIOT_RS_OK is success, other is error
 */
ble_qiot_ret_status_t llsync_timer_start(ble_timer_t timer_id, uint32_t period);

/**
 * @brief stop timer func
 * @param timer_id llsync_timer_create to reutrn
 * @return BLE_QIOT_RS_OK is success, other is error
 */
ble_qiot_ret_status_t llsync_timer_stop(ble_timer_t timer_id);

/**
 * @brief get the decvice info
 * @param dev_info Fill in the device information according to the structure
 * @return BLE_QIOT_RS_OK is success, other is error
 */
ble_qiot_ret_status_t llsync_get_dev_info(ble_device_info_t *dev_info);

/**
 * @brief flash handle func
 * @param type write or read
 * @param flash_addr flash storage addr
 * @param buf The address where the data is stored
 * @param len stor data length
 * @return Actual operating length
 */
int llsync_flash_handle(e_llsync_flash_user type, uint32_t flash_addr, char *buf, uint16_t len);

/**
 * @brief the advertising handle func
 * @param type start or stop adv
 * @param data_buf Address to send data
 * @param data_len send data len
 * @return BLE_QIOT_RS_OK is success, other is error
 */
ble_qiot_ret_status_t llsync_adv_handle(e_llsync_adv_user type, uint8_t *data_buf, uint8_t data_len);

/**
 * @brief Relevant tips for equipment operation func
 * @param type Specific operation type
 * @return BLE_QIOT_RS_OK is success, other is error
 */
ble_qiot_ret_status_t llsync_dev_operate_handle(e_llsync_dev_operate_user type);

/**
 * @brief the scan handle func
 * @param type start or stop scan
 * @return BLE_QIOT_RS_OK is success, other is error
 */
ble_qiot_ret_status_t llsync_scan_handle(e_llsync_scan_user type);

/**
 * @brief User initialization function, you can add some necessary initialization here, it can be empty.
 * @param void
 * @return void
 */
void llsync_adv_user_ex_init(void);

#ifdef __cplusplus
}
#endif
#endif  // TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_INCLUDE_BLE_QIOT_ADV_IMPORT_H_
