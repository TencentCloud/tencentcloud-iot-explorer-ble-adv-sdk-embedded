/*
 * ESPRESSIF MIT License
 *
 * Copyright (c) 2017 <ESPRESSIF SYSTEMS (SHANGHAI) PTE LTD>
 *
 * Permission is hereby granted for use on ESPRESSIF SYSTEMS ESP32 only, in which case,
 * it is free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "esp_ota_ops.h"

#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"

#include "ble_qiot_adv_center.h"

static TimerHandle_t ota_reboot_timer;

#define LLSYNC_LOG_TAG "broadcast"

static void test_task(void *pvParameters)
{
    while (1) {
         //ble_event_report_property();
         //ble_event_post(0);
         //ble_event_get_status();
         //ble_secure_bind_user_confirm(BLE_QIOT_SECURE_BIND_CONFIRM);
         //ble_secure_bind_user_confirm(BLE_QIOT_SECURE_BIND_REJECT);
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
}

#define GPIO_INPUT_IO_0     23
#define GPIO_INPUT_PIN_SEL  (1ULL<<GPIO_INPUT_IO_0)

void ble_secure_bind_user_cb(void)
{
    return;
}

void ble_secure_bind_user_notify(uint8_t result)
{
    printf("the binding canceled, result: %d\r\n", result);
    return;
}

void ble_ota_start_cb(void)
{
    printf("ble ota start callback\r\n");
    return;
}

ble_qiot_ret_status_t ble_ota_valid_file_cb(uint32_t file_size, char *file_version)
{
    printf("user valid file, size %d, file_version: %s\r\n", file_size, file_version);
    return LLSYNC_ADV_RS_OK;
}

static void ble_ota_reboot_timer(void *param)
{
    esp_restart();
}

void ble_ota_stop_cb(uint8_t result)
{

    return;
}

int ble_ota_write_flash(uint32_t flash_addr, const char *write_buf, uint16_t write_len)
{
    int ret = 0;

    return ret == ESP_OK ? write_len : ret;
}

void ble_qiot_service_init(void)
{
    esp_err_t ret;

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ret                               = esp_bt_controller_init(&bt_cfg);
    if (ret) {
        ESP_LOGE(LLSYNC_LOG_TAG, "%s enable controller failed: %s", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
    if (ret) {
        ESP_LOGE(LLSYNC_LOG_TAG, "%s enable controller failed: %s", __func__, esp_err_to_name(ret));
        return; 
    }

    ret = esp_bluedroid_init();
    if (ret) {
        ESP_LOGE(LLSYNC_LOG_TAG, "%s init bluetooth failed: %s", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_bluedroid_enable();
    if (ret) {
        ESP_LOGE(LLSYNC_LOG_TAG, "%s enable bluetooth failed: %s", __func__, esp_err_to_name(ret));
        return;
    }

    llsync_adv_init();

    return;

}

void app_main()
{
    nvs_flash_init();

    ble_qiot_service_init();

    xTaskCreate(test_task, "tsk1", 4 * 1024, NULL, 5, NULL);
}
