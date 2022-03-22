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
#include "string.h"
#include "stdbool.h"
#include "ble_qiot_template.h"
#include "ble_qiot_common.h"
#include "ble_qiot_log.h"
#include "ble_qiot_md5.h"
#include "ble_qiot_aes.h"
#include "ble_qiot_fifo.h"
#include "ble_qiot_adv_center.h"
#include "ble_qiot_adv_ctrl_pro.h"

llsync_adv_property_report_t g_property_report;

static uint8_t llsync_fifo_buf[LLSYNC_ADV_FIFOBUF_LEN] = {0};

static FIFOBuffer llsync_pro_fifo;

static void llsync_property_data_build(uint8_t data_len)
{
    uint8_t i = 0;
    uint8_t raw_data[LLSYNC_ADV_MAX_DATA_LEN] = {0x02, 0x01, 0x06, 0x11, 0x07, 0xBA, 0xFE}; 
    uint8_t index = LLSYNC_ADV_INDEX_LEN;
    ble_dev_stor_t stor_info = llsync_adv_stor_get();
    uint16_t dev_addr = HTONS(stor_info.device_address);
    uint8_t message_id = llsync_adv_msg_id_get();

    raw_data[index++] = LLSYNC_ADV_SPLIT_DATA_BUILD(g_property_report.split_total_num, g_property_report.split_send_num);
    raw_data[index++] = data_len + LLSYNC_ADV_MSG_HEADER_LEN + LLSYNC_ADV_DEV_ADDR_LEN;
    raw_data[index++] = LLSYNC_ADV_MSG_HEADER_BUILD(message_id, LLSYNC_ADV_MSG_REPORT);

    memcpy(raw_data + index, &dev_addr, LLSYNC_ADV_DEV_ADDR_LEN);
    index += LLSYNC_ADV_DEV_ADDR_LEN;
    memcpy(raw_data + index, g_property_report.send_buf + g_property_report.send_data_len, data_len);
    index += data_len;

    if (data_len < LLSYNC_ADV_PAYLOAD_SEGMENT_LEN) {
        for (i = 0; i < (LLSYNC_ADV_PAYLOAD_SEGMENT_LEN - data_len); i++) {
            raw_data[index++] = 0;
        }
    }

    g_property_report.send_data_len += data_len;
    g_property_report.split_send_num++;

    llsync_data_to_adv_buf(raw_data, index, LLSYNC_ADV_DATA_REPORT_SPLIT_TYPE);

    llsync_adv_start(LLSYNC_ADV_DATA_REPORT_SPLIT_TYPE, index);
}

ble_qiot_ret_status_t llsync_adv_property_data_report(void)
{
    uint8_t segment_len = LLSYNC_ADV_PAYLOAD_SEGMENT_LEN;
    uint8_t remain_data_len = 0;

    if (g_property_report.adv_ok) {
        return LLSYNC_ADV_RS_OK;
    }

    remain_data_len = g_property_report.send_whole_len - g_property_report.send_data_len;

    llsync_property_data_build((remain_data_len < segment_len) ? remain_data_len : segment_len);

    ble_qiot_log_i("split total num:%d, split send num:%d", g_property_report.split_total_num, g_property_report.split_send_num);
    if (g_property_report.split_send_num == g_property_report.split_total_num) {
        g_property_report.split_send_num = 0;
        g_property_report.send_data_len = 0;
        g_property_report.adv_resend_time++;
        if (g_property_report.adv_resend_time == LLSYNC_ADV_SPLIT_RESEND_TIME) {
            ble_qiot_log_i("adv finish!");
            g_property_report.adv_resend_time = 0;
            g_property_report.adv_ok = true;
            return LLSYNC_ADV_RS_OK;
        }
    }

    return LLSYNC_ADV_RS_OK;
}

static void llsync_data_to_pro_fifo(uint8_t *raw_pro_data, uint8_t valid_data_len)
{
    uint8_t i = 0;

    if ((valid_data_len + 1) > ble_fifo_idle_buf_len(&llsync_pro_fifo)) {
        ble_qiot_log_e("ble fifo full.%d-%d", (valid_data_len + 1), ble_fifo_idle_buf_len(&llsync_pro_fifo));
        return;
    }

    //fifo storage data format: len + data.
    ble_fifo_push(&llsync_pro_fifo, valid_data_len);

    for (i = 0; i < valid_data_len; i++) {
        ble_fifo_push(&llsync_pro_fifo, raw_pro_data[i]);
    }
}

static void llsync_pro_send_ready(void)
{
    g_property_report.send_data_len = 0;
    g_property_report.split_send_num = 0;
    g_property_report.adv_resend_time = 0;
    g_property_report.adv_ok = false;
    g_property_report.split_total_num = (g_property_report.send_whole_len/LLSYNC_ADV_PAYLOAD_SEGMENT_LEN)+
                                        (((g_property_report.send_whole_len%LLSYNC_ADV_PAYLOAD_SEGMENT_LEN) != 0) ? 1 : 0);

    return;
}

static void llsync_adv_property_data_handle(uint8_t *data_buf, uint16_t data_len)
{
    uint8_t key_buf[MD5_DIGEST_SIZE] = {0};
    uint8_t packet_num = 0;
    ble_dev_stor_t stor_info = llsync_adv_stor_get();

    llsync_adv_gen_key(key_buf, stor_info.nonce);

    data_len = llsync_adv_encrypt_data_padding_add((uint8_t *)data_buf, data_len);

    if (LLSYNC_ADV_RS_OK != utils_aes_ecb((uint8_t *)data_buf, data_len, UTILS_AES_ENCRYPT, key_buf)) {
		ble_qiot_log_e("aes encrypt err!");
        return;
    }

    //LLSYNC_ADV_HEX_PRINTF("aes", data_len, data_buf);

    packet_num = (data_len/LLSYNC_ADV_PAYLOAD_SEGMENT_LEN) + (((data_len%LLSYNC_ADV_PAYLOAD_SEGMENT_LEN) != 0) ? 1 : 0);

    if (data_len > LLSYNC_ADV_REPORT_DATA_MAX || packet_num > LLSYNC_ADV_PACKET_MAX_NUM) {
        ble_qiot_log_e("The data too long!");
        return;
    }

    if (llsync_center_fifo_is_empty()) {
        memcpy(g_property_report.send_buf, data_buf, data_len);
        g_property_report.send_buf[data_len] = '\0';
        g_property_report.send_whole_len = data_len;
        llsync_pro_send_ready();
        llsync_adv_property_data_report();
    } else {
        llsync_data_to_pro_fifo(data_buf, data_len);
    }

}

ble_qiot_ret_status_t llsync_adv_property_report(void)
{
    uint8_t  property_id   = 0;
    uint8_t  property_type = 0;
    int      property_len  = 0;
    uint16_t data_len      = 0;
    uint16_t data_buf_off  = 0;
    ble_dev_stor_t stor_info = llsync_adv_stor_get();
    uint8_t data_buf[BLE_QIOT_EVENT_MAX_SIZE] = {0};

    if (stor_info.bind_state != LLSYNC_ADV_DEV_STATUS_BIND_OK) {
        ble_qiot_log_i("The dev not bind.");
        return LLSYNC_ADV_RS_OK;
    }

    ble_qiot_log_i("report property");
    for (property_id = 0; property_id < BLE_QIOT_PROPERTY_ID_BUTT; property_id++) {
        property_type = ble_get_property_type_by_id(property_id);
        if (property_type >= BLE_QIOT_DATA_TYPE_BUTT) {
            ble_qiot_log_e("property(%d) type(%d) invalid", property_id, property_type);
            return LLSYNC_ADV_RS_ERR;
        }

        data_buf[data_len++] = BLE_QIOT_PACKAGE_TLV_HEAD(property_type, property_id);
        data_buf_off         = data_len;

        property_len = ble_user_property_get_data_by_id(property_id, (char *)&data_buf[data_buf_off], sizeof(data_buf) - data_buf_off);
        if (property_len < 0) {
            return LLSYNC_ADV_RS_ERR;
        } else if (property_len == 0) {
            // clean the property head cause no data to post
            data_len--;
            data_buf[data_len] = '0';
            ble_qiot_log_d("property: %d no data to post", property_id);
        } else {
            data_len += property_len;
        }
    }

    ble_qiot_log_i("data_len:%d", data_len);

    if (data_len > LLSYNC_ADV_PROPERTY_DATA_MAX) {
        ble_qiot_log_e("The data too long");
        return LLSYNC_ADV_RS_ERR;
    }

    llsync_adv_property_data_handle(data_buf, data_len);

    return LLSYNC_ADV_RS_OK;
}

void llsync_pro_get_data(void)
{
    uint8_t i = 0;
    uint8_t data_len = 0;

    data_len = ble_fifo_pop(&llsync_pro_fifo);
    for (i = 0; i < data_len; i++) {
        g_property_report.send_buf[i] = ble_fifo_pop(&llsync_pro_fifo);
    }

    g_property_report.send_buf[data_len] = '\0';
    g_property_report.send_whole_len = data_len;
    llsync_pro_send_ready();
    llsync_adv_property_data_report();
}

void llsync_adv_property_report_again(void)
{
    g_property_report.adv_ok = false;

    ble_qiot_log_i("report again");

    llsync_adv_property_data_report();

    return;
}

bool llsync_adv_data_split_finish(void)
{
    return g_property_report.adv_ok;
}

void llsync_adv_property_fifo_init(void)
{
    ble_fifo_init(&llsync_pro_fifo, llsync_fifo_buf, sizeof(llsync_fifo_buf));

    return;
}

bool llsync_pro_fifo_is_empty(void)
{
    return ble_fifo_isempty(&llsync_pro_fifo);
}

#ifdef __cplusplus
}
#endif
