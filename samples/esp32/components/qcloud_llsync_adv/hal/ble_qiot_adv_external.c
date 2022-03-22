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
#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ble_qiot_adv_config.h"
#include "ble_qiot_log.h"
#include "ble_qiot_adv_import.h"
#include "ble_qiot_adv_center.h"
#include "ble_qiot_adv_config.h"
#include "ble_qiot_adv_export.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "esp_spi_flash.h"
#include "esp_bt_device.h"

#define PRODUCT_ID  "PRODUCT_ID"
#define DEVICE_NAME "YOUR_DEV_NAME"
#define SECRET_KEY  "YOUR_IOT_PSK"

typedef struct ble_esp32_timer_id_ {
    uint8_t       type;
    ble_timer_cb  handle;
    TimerHandle_t timer;
} ble_esp32_timer_id;

ble_timer_t llsync_timer_create(uint8_t type, ble_timer_cb timeout_handle)
{
    ble_esp32_timer_id *p_timer = malloc(sizeof(ble_esp32_timer_id));
    if (NULL == p_timer) {
        return NULL;
    }

    p_timer->type   = type;
    p_timer->handle = timeout_handle;
    p_timer->timer  = NULL;

    return (ble_timer_t)p_timer;
}

ble_qiot_ret_status_t llsync_timer_start(ble_timer_t timer_id, uint32_t period)
{
    ble_esp32_timer_id *p_timer = (ble_esp32_timer_id *)timer_id;

    if (NULL == p_timer->timer) {
        p_timer->timer =
            (ble_timer_t)xTimerCreate("bro_timer", period / portTICK_PERIOD_MS, pdTRUE, NULL, p_timer->handle);
    }
    xTimerReset(p_timer->timer, portMAX_DELAY);

    return LLSYNC_ADV_RS_OK;
}

ble_qiot_ret_status_t llsync_timer_stop(ble_timer_t timer_id)
{
    ble_esp32_timer_id *p_timer = (ble_esp32_timer_id *)timer_id;
    xTimerStop(p_timer->timer, portMAX_DELAY);

    return LLSYNC_ADV_RS_OK;
}

ble_qiot_ret_status_t llsync_get_dev_info(ble_device_info_t *dev_info)
{
    char *address = (char *)esp_bt_dev_get_address();
    memcpy(dev_info->mac, address, 6);
    memcpy(dev_info->product_id, PRODUCT_ID, strlen(PRODUCT_ID));
    memcpy(dev_info->device_name, DEVICE_NAME, strlen(DEVICE_NAME));
    memcpy(dev_info->psk, SECRET_KEY, strlen(SECRET_KEY));

    return LLSYNC_ADV_RS_OK;
}

int llsync_flash_handle(e_llsync_flash_user type, uint32_t flash_addr, char *buf, uint16_t len)
{
    int ret = 0;

    if (LLSYNC_ADV_WRITE_FLASH == type) {
        ret = spi_flash_erase_range(flash_addr, LLSYNC_ADV_RECORD_FLASH_PAGESIZE);
        ret = spi_flash_write(flash_addr, buf, len);
    } else if (LLSYNC_ADV_READ_FLASH == type){
        ret = spi_flash_read(flash_addr, buf, len);
    }

    return ret == ESP_OK ? len : ret;
}

ble_qiot_ret_status_t llsync_adv_handle(e_llsync_adv_user type, uint8_t *data_buf, uint8_t data_len)
{
    if (LLSYNC_ADV_START == type) {
        //ble_qiot_log_i("adv start");
        esp_err_t ret = esp_ble_gap_config_adv_data_raw(data_buf, data_len);
        if (ret) {
            ble_qiot_log_i("config adv data failed, error code = %x", ret);
        }
    } else if (LLSYNC_ADV_STOP == type){
        //ble_qiot_log_i("adv stop");
    esp_ble_gap_stop_advertising();
    }

    return LLSYNC_ADV_RS_OK;
}

static esp_ble_scan_params_t ble_scan_params = {
    .scan_type              = BLE_SCAN_TYPE_ACTIVE,
    .own_addr_type          = BLE_ADDR_TYPE_PUBLIC,
    .scan_filter_policy     = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_interval          = LLSYNC_SCAN_INTERVAL,
    .scan_window            = LLSYNC_SCAN_WINDOW,
    .scan_duplicate         = BLE_SCAN_DUPLICATE_DISABLE
};

ble_qiot_ret_status_t llsync_scan_handle(e_llsync_scan_user type)
{
    if (LLSYNC_SCAN_START == type) {
        //ble_qiot_log_i("scan start");
        esp_ble_gap_set_scan_params(&ble_scan_params);
    } else if (LLSYNC_SCAN_STOP == type){
        //ble_qiot_log_i("scan stop");
        esp_ble_gap_stop_scanning();
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

static esp_ble_adv_params_t adv_params = {
    .adv_int_min       = LLSYNC_ADV_INTERVAL,
    .adv_int_max       = LLSYNC_ADV_INTERVAL,
    .adv_type          = ADV_TYPE_IND,
    .own_addr_type     = BLE_ADDR_TYPE_PUBLIC,
    .channel_map       = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_WLST,
};

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    esp_err_t err;
	uint8_t i = 0;

    switch (event) {
        case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:{
            esp_ble_gap_start_advertising(&adv_params);
            break;
        }

        case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT: {

            //the unit of the duration is second, 0 means scan permanently
            uint32_t duration = 0;
            esp_ble_gap_start_scanning(0);

            break;
        }
        case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT:
            //scan start complete event to indicate scan start successfully or failed
            if ((err = param->scan_start_cmpl.status) != ESP_BT_STATUS_SUCCESS) {
                ble_qiot_log_i("Scan start failed: %s", esp_err_to_name(err));
            }
            break;
        case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
            //adv start complete event to indicate adv start successfully or failed
            if ((err = param->adv_start_cmpl.status) != ESP_BT_STATUS_SUCCESS) {
                ble_qiot_log_i("Adv start failed: %s", esp_err_to_name(err));
            }
            break;
        case ESP_GAP_BLE_SCAN_RESULT_EVT: {
            esp_ble_gap_cb_param_t *scan_result = (esp_ble_gap_cb_param_t *)param;
            if (scan_result->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT) {
                ble_scan_data_analyze(scan_result->scan_rst.ble_adv, scan_result->scan_rst.adv_data_len);
            }
            break;
        }

        case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT:
            if ((err = param->scan_stop_cmpl.status) != ESP_BT_STATUS_SUCCESS){
                ble_qiot_log_i("Scan stop failed: %s", esp_err_to_name(err));
            }
            else {
                ble_qiot_log_i("Stop scan successfully");
            }
            break;

        case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
            if ((err = param->adv_stop_cmpl.status) != ESP_BT_STATUS_SUCCESS){
                ble_qiot_log_i("Adv stop failed: %s", esp_err_to_name(err));
            }
            break;

        default:
            break;
    }
}

void llsync_adv_user_ex_init(void)
{
    esp_err_t status;

    //register the scan callback function to the gap module
    if ((status = esp_ble_gap_register_callback(gap_event_handler)) != ESP_OK) {
        ble_qiot_log_i("gap register error: %s", esp_err_to_name(status));
        return;
    }
    
}

#ifdef __cplusplus
}
#endif
