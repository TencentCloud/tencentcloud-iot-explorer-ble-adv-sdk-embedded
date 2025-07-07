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

#include "string.h"
#include "ble_qiot_log.h"
#include "ble_qiot_template.h"
#include "ble_qiot_md5.h"
#include "ble_qiot_aes.h"
#include "ble_qiot_adv_center.h"
#include "ble_qiot_adv_ctrl_pro.h"

// parse tlv data and return the length parsed
int ble_lldata_parse_tlv(const char *buf, int buf_len, e_ble_tlv *tlv)
{
    int      ret_len  = 0;

    tlv->type = BLE_QIOT_PARSE_TLV_HEAD_TYPE(buf[0]);
    if (tlv->type >= BLE_QIOT_DATA_TYPE_BUTT) {
        ble_qiot_log_e("lldata parse invalid type: %d", tlv->type);
        return -1;
    }
    tlv->id = BLE_QIOT_PARSE_TLV_HEAD_ID(buf[0]);
    ret_len++;

    switch (tlv->type) {
        case BLE_QIOT_DATA_TYPE_BOOL:
            tlv->len = sizeof(uint8_t);
            tlv->val = (char *)buf + ret_len;
            ret_len += sizeof(uint8_t);
            break;
        case BLE_QIOT_DATA_TYPE_ENUM:
            tlv->len = sizeof(uint16_t);
            tlv->val = (char *)buf + ret_len;
            ret_len += sizeof(uint16_t);
            break;
        case BLE_QIOT_DATA_TYPE_INT:
            tlv->len = sizeof(uint32_t);
            tlv->val = (char *)buf + ret_len;
            ret_len += sizeof(uint32_t);
            break;
        default:
            break;
    }
    ble_qiot_log_d("tlv parsed, type: %d, id: %d, len: %d", tlv->type, tlv->id, tlv->len);

    return ret_len;
}

ble_qiot_ret_status_t llsync_adv_ctrl_data_handle(const char *in_buf, int buf_len)
{
    uint16_t  parse_len = 0;
    int       ret_len   = 0;
    e_ble_tlv tlv;
    int    ret = LLSYNC_ADV_RS_OK;

    ble_qiot_log_i("handle property data");
    while (parse_len < buf_len) {
        memset(&tlv, 0, sizeof(e_ble_tlv));
        ret_len = ble_lldata_parse_tlv(in_buf + parse_len, buf_len - parse_len, &tlv);
        if (ret_len < 0) {
            return LLSYNC_ADV_RS_ERR;
        }

        parse_len += ret_len;
        if (parse_len > buf_len) {
            ble_qiot_log_e("invalid peroperty data, %d(property len) > %d(buf len)", parse_len, buf_len);
            ret = LLSYNC_ADV_RS_ERR;
            break;
        }

        ret = ble_user_property_set_data(&tlv);
        if (LLSYNC_ADV_RS_OK != ret) {
            ret = LLSYNC_ADV_RS_ERR;
            break;
        }
    }

    llsync_adv_ctrl_data_ack(ret);

    return ret;
}

#ifdef __cplusplus
}
#endif
