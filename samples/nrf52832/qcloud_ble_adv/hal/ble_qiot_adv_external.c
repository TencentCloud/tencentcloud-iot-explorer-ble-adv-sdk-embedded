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
#include "ble_qiot_adv_cfg.h"
#include "ble_qiot_adv_import.h"
#include "ble_qiot_adv_export.h"
#include "app_timer.h"
#include "ble_gap.h"
#include "ble_advdata.h"
#include "flash_storage.h"
#include "nrf_ble_scan.h"

#define PRODUCT_ID  "PRODUCT_ID"
#define DEVICE_NAME "YOUR_DEV_NAME"
#define SECRET_KEY  "YOUR_IOT_PSK"

// define a static timer used in bind for example, a good way is used malloc
APP_TIMER_DEF(ble_bind_timer);

ble_timer_t llsync_timer_create(uint8_t type, ble_timer_cb timeout_handle)
{
    app_timer_create((app_timer_id_t const *)&ble_bind_timer,
                    type == LLSYNC_ADV_TIMER_ONE_SHOT_TYPE ? APP_TIMER_MODE_SINGLE_SHOT : APP_TIMER_MODE_REPEATED,
                    (app_timer_timeout_handler_t)timeout_handle);
    NRF_LOG_INFO("create timer id %p", (ble_timer_t)ble_bind_timer);

    return (ble_timer_t)ble_bind_timer;
}

ble_qiot_ret_status_t llsync_timer_start(ble_timer_t timer_id, uint32_t period)
{
    ret_code_t ret = 0;

    ret = app_timer_start((app_timer_id_t)timer_id, APP_TIMER_TICKS(period), NULL);

    return 0 == ret ? LLSYNC_ADV_RS_OK : LLSYNC_ADV_RS_ERR;
}

ble_qiot_ret_status_t llsync_timer_stop(ble_timer_t timer_id)
{
    ret_code_t ret = 0;

    ret = app_timer_stop(timer_id);

    return 0 == ret ? LLSYNC_ADV_RS_OK : LLSYNC_ADV_RS_ERR;
}

ble_qiot_ret_status_t llsync_get_dev_info(ble_device_info_t *dev_info)
{
    char address[LLSYNC_ADV_MAC_LEN] = 0;
    uint32_t       err_code;
    ble_gap_addr_t mac_info;

    err_code = sd_ble_gap_addr_get(&mac_info);
    if (NRF_SUCCESS != err_code) {
        NRF_LOG_ERROR("Get MAC error, ret %d", err_code);
        return err_code;
    }

    dev_info->mac[0] = mac_info.addr[5];
    dev_info->mac[1] = mac_info.addr[4];
    dev_info->mac[2] = mac_info.addr[3];
    dev_info->mac[3] = mac_info.addr[2];
    dev_info->mac[4] = mac_info.addr[1];
    dev_info->mac[5] = mac_info.addr[0];

    memcpy(dev_info->product_id, PRODUCT_ID, strlen(PRODUCT_ID));
    memcpy(dev_info->device_name, DEVICE_NAME, strlen(DEVICE_NAME));
    memcpy(dev_info->psk, SECRET_KEY, strlen(SECRET_KEY));

    return LLSYNC_ADV_RS_OK;
}

int llsync_flash_handle(e_llsync_flash_user type, uint32_t flash_addr, char *buf, uint16_t len)
{
    int ret = 0;
    return len;
    if (LLSYNC_ADV_WRITE_FLASH == type) {
        ret = fstorage_write(flash_addr, len, buf);
    } else if (LLSYNC_ADV_READ_FLASH == type) {
        ret = fstorage_read(flash_addr, len, buf);
    }

    return ret;
}

static uint8_t m_adv_handle =
    BLE_GAP_ADV_SET_HANDLE_NOT_SET; /**< Advertising handle used to identify an advertising set. */
static uint8_t m_enc_advdata[BLE_GAP_ADV_SET_DATA_SIZE_MAX]; /**< Buffer for storing an encoded advertising set. */
static uint8_t m_enc_scan_response_data[BLE_GAP_ADV_SET_DATA_SIZE_MAX]; /**< Buffer for storing an encoded scan data. */

/**@brief Struct that contains pointers to the encoded advertising data. */
static ble_gap_adv_data_t m_adv_data = {
    .adv_data      = {.p_data = m_enc_advdata, .len = BLE_GAP_ADV_SET_DATA_SIZE_MAX},
    .scan_rsp_data = {.p_data = NULL, .len = 0}
    };

ble_qiot_ret_status_t llsync_adv_handle(e_llsync_adv_user type, uint8_t *data_buf, uint8_t data_len)
{
    ret_code_t err_code;
    ble_advdata_t        advdata;
    ble_gap_adv_params_t m_adv_params;
    ble_advdata_manuf_data_t manf_data;

    if (LLSYNC_ADV_START == type) {
        //ble_qiot_log_i("adv start");

        memset(&manf_data, 0, sizeof(manf_data));

        memcpy(m_adv_data.adv_data.p_data, data_buf, data_len);
        m_adv_data.adv_data.len = data_len;

        memset(&m_adv_params, 0, sizeof(m_adv_params));

        m_adv_params.properties.type = BLE_GAP_ADV_TYPE_NONCONNECTABLE_NONSCANNABLE_UNDIRECTED;
        m_adv_params.p_peer_addr     = NULL;    // Undirected advertisement.
        m_adv_params.filter_policy   = BLE_GAP_ADV_FP_ANY;
        m_adv_params.interval        = LLSYNC_ADV_INTERVAL;
        m_adv_params.duration        = APP_ADV_DURATION;       // Never time out.

        err_code = sd_ble_gap_adv_set_configure(&m_adv_handle, &m_adv_data, &m_adv_params);
        if (NRF_SUCCESS != err_code) {
            NRF_LOG_ERROR("sd_ble_gap_adv_set_configure error, ret %d", err_code);
            return LLSYNC_ADV_RS_ERR;
        }

        err_code = sd_ble_gap_adv_start(m_adv_handle, APP_BLE_CONN_CFG_TAG);
        if (NRF_SUCCESS != err_code) {
            NRF_LOG_ERROR("sd_ble_gap_adv_start error, ret %d", err_code);
            return LLSYNC_ADV_RS_ERR;
        }

    } else if (LLSYNC_ADV_STOP == type){
        //ble_qiot_log_i("adv stop");

        err_code = sd_ble_gap_adv_stop(m_adv_handle);
        if (NRF_SUCCESS != err_code) {
            NRF_LOG_ERROR("sd_ble_gap_adv_stop error, ret %d", err_code);
            return LLSYNC_ADV_RS_ERR;
        }
    }

    return LLSYNC_ADV_RS_OK;
}
extern void scan_start(void);
ble_qiot_ret_status_t llsync_scan_handle(e_llsync_scan_user type)
{
    if (LLSYNC_SCAN_START == type) {
        //ble_qiot_log_i("scan start");
        scan_start();
    } else if (LLSYNC_SCAN_STOP == type){
        //ble_qiot_log_i("scan stop");
        nrf_ble_scan_stop();
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
