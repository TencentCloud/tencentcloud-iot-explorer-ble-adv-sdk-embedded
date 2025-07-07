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
#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ble_qiot_log.h"
#include "ble_qiot_adv_center.h"
#include "ble_qiot_adv_config.h"
#include "ble_qiot_adv_import.h"
#include "ble_qiot_adv_export.h"

#define PRODUCT_ID  "PRODUCT_ID"
#define DEVICE_NAME "YOUR_DEV_NAME"
#define SECRET_KEY  "YOUR_IOT_PSK"

ble_timer_t llsync_timer_create(uint8_t type, ble_timer_cb timeout_handle)
{
    return NULL;
}

ble_qiot_ret_status_t llsync_timer_start(ble_timer_t timer_id, uint32_t period)
{
    return LLSYNC_ADV_RS_OK;
}

ble_qiot_ret_status_t llsync_timer_stop(ble_timer_t timer_id)
{
    return LLSYNC_ADV_RS_OK;
}

ble_qiot_ret_status_t llsync_get_dev_info(ble_device_info_t *dev_info)
{
    char address[BLE_QIOT_MAC_LEN] = 0;
    memcpy(dev_info->mac, address, BLE_QIOT_MAC_LEN);
    memcpy(dev_info->product_id, PRODUCT_ID, strlen(PRODUCT_ID));
    memcpy(dev_info->device_name, DEVICE_NAME, strlen(DEVICE_NAME));
    memcpy(dev_info->psk, SECRET_KEY, strlen(SECRET_KEY));

    return LLSYNC_ADV_RS_OK;
}

int llsync_flash_handle(e_llsync_flash_user type, uint32_t flash_addr, char *buf, uint16_t len)
{
    int ret = 0;

    if (LLSYNC_ADV_WRITE_FLASH == type) {

    } else if (LLSYNC_ADV_READ_FLASH == type){

    }

    return ret;
}

ble_qiot_ret_status_t llsync_adv_handle(e_llsync_adv_user type, uint8_t *data_buf, uint8_t data_len)
{
    if (LLSYNC_ADV_START == type) {
        ble_qiot_log_i("adv start");

    } else if (LLSYNC_ADV_STOP == type){
        ble_qiot_log_i("adv stop");

    }

    return LLSYNC_ADV_RS_OK;
}

ble_qiot_ret_status_t llsync_scan_handle(e_llsync_scan_user type)
{
    if (LLSYNC_SCAN_START == type) {
        ble_qiot_log_i("scan start");

    } else if (LLSYNC_SCAN_STOP == type){
        ble_qiot_log_i("scan stop");

    }

    return LLSYNC_ADV_RS_OK;
}

ble_qiot_ret_status_t llsync_dev_operate_handle(e_llsync_dev_operate_user type)
{
    ble_qiot_ret_status_t ret = LLSYNC_ADV_RS_OK;

    if (LLSYNC_ADV_DEV_START_NET_HINT == type) {
        //Start to configure network prompt
    } else if (LLSYNC_ADV_DEV_AGREE_NET_HINT == type) {
        //Agree to the network distribution prompt 0: Agree Not 0: Disagree
    } else if (LLSYNC_ADV_DEV_DELETE_HINT == type){
        //Delete configuration prompt
    }

    return LLSYNC_ADV_RS_OK;
}

void llsync_adv_user_ex_init(void)
{
    return;
}

#ifdef __cplusplus
}
#endif
