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
#include "stdio.h"
#include "stdbool.h"
#include "ble_qiot_log.h"
#include "ble_qiot_md5.h"
#include "ble_qiot_aes.h"
#include "ble_qiot_fifo.h"
#include "ble_qiot_common.h"
#include "ble_qiot_adv_center.h"
#include "ble_qiot_adv_cfg.h"
#include "ble_qiot_adv_import.h"
#include "ble_qiot_adv_export.h"
#include "ble_qiot_adv_ctrl_pro.h"

static uint8_t raw_pre_data[LLSYNC_ADV_MAX_DATA_LEN] = {0x02, 0x01, 0x06, 0x11, 0x07, 0xBA, 0xFE};

static uint8_t llsync_fifo_buf[LLSYNC_ADV_FIFOBUF_LEN] = {0};

static FIFOBuffer llsync_fifo;

static uint16_t sg_llsync_timer_cnt = 0;

static ble_dev_stor_t sg_llsync_record_info;

static ble_device_info_t  sg_llsync_dev_info;

static llsync_external_cb user_cb;

static ble_timer_t sg_llsync_adv_timer;

static ble_adv_handle_t sg_llsync_temp_data_proc;

static uint8_t sg_message_id = 1;

static uint8_t sg_adv_or_ack_status = 0;

static uint8_t sg_scan_adv_timer_status = 0;

inline static void llsync_scan_start_if_stop(void)
{   
    if (!LLSYNC_SCAN_ADV_TIMER_BIT_GET(sg_scan_adv_timer_status, LLSYNC_SCAN_START_OR_STOP_BIT)) {
        user_cb.llsync_scan_cb(LLSYNC_SCAN_START);
        LLSYNC_SCAN_ADV_TIMER_START_SET(sg_scan_adv_timer_status, LLSYNC_SCAN_START_OR_STOP_BIT);
    }
}

inline static void llsync_scan_stop_if_start(void)
{
    if (LLSYNC_SCAN_ADV_TIMER_BIT_GET(sg_scan_adv_timer_status, LLSYNC_SCAN_START_OR_STOP_BIT)) {
        user_cb.llsync_scan_cb(LLSYNC_SCAN_STOP);
        LLSYNC_SCAN_ADV_TIMER_STOP_SET(sg_scan_adv_timer_status, LLSYNC_SCAN_START_OR_STOP_BIT);
    }
}

inline static void llsync_adv_start_if_stop(void)
{
    if (!LLSYNC_SCAN_ADV_TIMER_BIT_GET(sg_scan_adv_timer_status, LLSYNC_ADV_START_OR_STOP_BIT)) {
        user_cb.llsync_adv_cb(LLSYNC_ADV_START, sg_llsync_temp_data_proc.adv_data.send_buf, sg_llsync_temp_data_proc.adv_data.send_len);
        LLSYNC_SCAN_ADV_TIMER_START_SET(sg_scan_adv_timer_status, LLSYNC_ADV_START_OR_STOP_BIT);
    }
}

inline static void llsync_adv_stop_if_start(void)
{
    if (LLSYNC_SCAN_ADV_TIMER_BIT_GET(sg_scan_adv_timer_status, LLSYNC_ADV_START_OR_STOP_BIT)) {
        user_cb.llsync_adv_cb(LLSYNC_ADV_STOP, NULL, 0);
        LLSYNC_SCAN_ADV_TIMER_STOP_SET(sg_scan_adv_timer_status, LLSYNC_ADV_START_OR_STOP_BIT);
    }
}

inline static void llsync_timer_start_if_stop(void)
{
    if (!LLSYNC_SCAN_ADV_TIMER_BIT_GET(sg_scan_adv_timer_status, LLSYNC_TIMER_START_OR_STOP_BIT)) {
        user_cb.llsync_timer_start(sg_llsync_adv_timer, LLSYNC_ADV_TIMER_INTERVAL);
        LLSYNC_SCAN_ADV_TIMER_START_SET(sg_scan_adv_timer_status, LLSYNC_TIMER_START_OR_STOP_BIT);
    }
}

inline static void llsync_timer_stop_if_start(void)
{
    if (LLSYNC_SCAN_ADV_TIMER_BIT_GET(sg_scan_adv_timer_status, LLSYNC_TIMER_START_OR_STOP_BIT)) {
        user_cb.llsync_timer_stop(sg_llsync_adv_timer);
        LLSYNC_SCAN_ADV_TIMER_STOP_SET(sg_scan_adv_timer_status, LLSYNC_TIMER_START_OR_STOP_BIT);
    }
}

static void llsync_adv_buf_clear(void)
{
    sg_llsync_temp_data_proc.recv_data_buf[0] = '\0';
    sg_llsync_temp_data_proc.recv_data_len = 0;
    sg_llsync_temp_data_proc.packet_seq_flag = 0;
    sg_llsync_timer_cnt = 0;
}

void llsync_adv_start(e_ble_adv_time_type type, uint8_t index)
{
    #if !LLSYNC_DEV_ADV_AND_SCAN
    llsync_scan_stop_if_start();
    #endif

    llsync_timer_start_if_stop();
}

void llsync_data_to_adv_buf(uint8_t *raw_adv_data, uint8_t valid_data_len, e_ble_adv_time_type type)
{
    uint8_t i = 0;

    //sizeof(uint8_t) + type = 2
    if ((valid_data_len + 2) > ble_fifo_idle_buf_len(&llsync_fifo)) {
        ble_qiot_log_e("ble fifo full.%d-%d", (valid_data_len + 2), ble_fifo_idle_buf_len(&llsync_fifo));
        return;
    }

    //fifo storage data format: len + type + data.
    ble_fifo_push(&llsync_fifo, valid_data_len);
    ble_fifo_push(&llsync_fifo, type);

    for (i = 0; i < valid_data_len; i++) {
        ble_fifo_push(&llsync_fifo, raw_adv_data[i]);
    }
}

/**************Unconfigured network broadcast protocol*********************
|   CID    |  frame Ctrl |  MAC[4:5] |   PID   | dev name len |  dev name |
|  2 bytes |   2 bytes   |  2 bytes  | 10 bytes|    1 byte    |  n bytes  |
**************************************************************************/
static void llsync_adv_net_start(void)
{
    uint8_t index = LLSYNC_ADV_UNNET_LEN;
    uint8_t name_len = strlen(sg_llsync_dev_info.device_name);
    uint8_t unconfigured_data[LLSYNC_ADV_MAX_DATA_LEN] = {0x02, 0x01, 0x06};

    //The overall length of the data whose AD type is 0xff
    //3 is the length occupied by the AD type and the number of bytes occupied by the length of the device name and split cycle time len.
    unconfigured_data[index++] = LLSYNC_ADV_CID_LEN + LLSYNC_ADV_FRAME_CTRL_LEN + LLSYNC_ADV_MAC_LAST_LEN + LLSYNC_ADV_PRODUCT_ID_LEN + name_len + 3;
    unconfigured_data[index++] = LLSYNC_ADV_AD_TYPE_MANUFACTURE;
    unconfigured_data[index++] = LLSYNC_ADV_UUID_LOW;
    unconfigured_data[index++] = LLSYNC_ADV_UUID_HIGH;
    unconfigured_data[index++] = LLSYNC_ADV_FRAME_CTRL_HIGH;
    unconfigured_data[index++] = LLSYNC_ADV_FRAME_CTRL_LOW;
    unconfigured_data[index++] = sg_llsync_dev_info.mac[4];
    unconfigured_data[index++] = sg_llsync_dev_info.mac[5];
    memcpy(&unconfigured_data[index], sg_llsync_dev_info.product_id, LLSYNC_ADV_PRODUCT_ID_LEN);
    index += LLSYNC_ADV_PRODUCT_ID_LEN;
    unconfigured_data[index++] = name_len;
    memcpy(&unconfigured_data[index], sg_llsync_dev_info.device_name, name_len);
    index += name_len;
    unconfigured_data[index++] = LLSYNC_APP_ADV_SPLIT_CYCLE_TIME;

    sg_llsync_temp_data_proc.adv_data.send_len = index;

    llsync_data_to_adv_buf(unconfigured_data, index, LLSYNC_ADV_NOT_NETWORK_TYPE);

    //LLSYNC_ADV_HEX_PRINTF("Unconfigured data", index, unconfigured_data);

    llsync_adv_start(LLSYNC_ADV_NOT_NETWORK_TYPE, index);

    return;
}

static void llsync_dev_net_distribution(void)
{
    if (LLSYNC_ADV_DEV_STATUS_BIND_OK == sg_llsync_record_info.bind_state) {
        ble_qiot_log_i("The device is already bound!");
        #if !LLSYNC_DEV_ADV_AND_SCAN
        llsync_scan_start_if_stop();
        #endif

        return;
    }

    llsync_adv_net_start();
}

static void llsync_adv_data_exchange(uint8_t *inbuf, uint8_t *outbuf, uint8_t len)
{
    uint8_t i = 0;

    for (i = 0; i < len/2; i++) {
        inbuf[i] = inbuf[i] ^ inbuf[len-i-1];
        outbuf[len-i-1] = inbuf[i] ^ inbuf[len-i-1];
        outbuf[i] = inbuf[i] ^ outbuf[len-i-1];
    }
}

static bool llsync_is_mesh_packet(uint8_t *adv_data, uint8_t adv_data_len, uint8_t *outbuf)
{
    uint16_t index = 0;

    //Find data of AD type 0x07
    while (index < adv_data_len) {
        if (adv_data[index+1] == LLSYNC_ADV_AD_TYPE_COMPLETE_128UUIDS) {
            if ((index+adv_data[index]-1) < adv_data_len) {
                if ((adv_data[index+adv_data[index]-1] == LLSYNC_ADV_UUID_LOW) && (adv_data[index+adv_data[index]] == LLSYNC_ADV_UUID_HIGH)){
                    //The scanned data is reversed, here to flip.
                    llsync_adv_data_exchange(&adv_data[index+2], outbuf, adv_data[index]-1);
                    //LLSYNC_ADV_HEX_PRINTF("adv", (adv_data[index]-1), outbuf);
                    return true;
                }
            }
        }
        index += adv_data[index]+1;
    }

    return false;
}

static ble_qiot_ret_status_t llsync_adv_data_assemble(uint8_t const *databuf)
{
    uint8_t actual_data_len = 0;
    uint8_t packet_seq = 0;

    if (databuf[LLSYNC_ADV_DATA_LEN_INDEX] < (LLSYNC_ADV_MSG_HEADER_LEN+LLSYNC_ADV_DEV_ADDR_LEN)) {
        ble_qiot_log_e("data len err:%d!", databuf[LLSYNC_ADV_DATA_LEN_INDEX]);
        llsync_adv_buf_clear();
        return LLSYNC_ADV_RS_ERR_PARA;
    }

    sg_llsync_temp_data_proc.total_packet_num = LLSYNC_ADV_GET_TOTAL_PACKET_NUM(databuf[LLSYNC_ADV_PACKAGE_NUM_INDEX]);

    packet_seq = LLSYNC_ADV_GET_PACKET_SEQ(databuf[LLSYNC_ADV_PACKAGE_NUM_INDEX]);

    if (packet_seq > sg_llsync_temp_data_proc.total_packet_num) {
        ble_qiot_log_e("package err %d-%d!", sg_llsync_temp_data_proc.packet_seq_flag, sg_llsync_temp_data_proc.total_packet_num);
        llsync_adv_buf_clear();
        return LLSYNC_ADV_RS_ERR_PARA;
    }

    if (0 == sg_llsync_temp_data_proc.packet_seq_flag) {
        sg_llsync_temp_data_proc.received_packet_num = 0;
    }

    sg_llsync_temp_data_proc.msg_head = databuf[LLSYNC_ADV_MSG_HEADER_INDEX];

    if (LLSYNC_PACKET_SEQ_NOT_RECEIVED(sg_llsync_temp_data_proc.packet_seq_flag, packet_seq)) {
        actual_data_len = databuf[LLSYNC_ADV_DATA_LEN_INDEX]-LLSYNC_ADV_MSG_HEADER_LEN-LLSYNC_ADV_DEV_ADDR_LEN;
        //Put the package of the corresponding serial number to the corresponding buf
        memcpy(&sg_llsync_temp_data_proc.recv_data_buf[(packet_seq-1)*LLSYNC_ADV_PAYLOAD_SEGMENT_LEN], &databuf[LLSYNC_ADV_DATA_INDEX], actual_data_len);
        sg_llsync_temp_data_proc.recv_data_len += actual_data_len;
        LLSYNC_PACKET_SEQ_RECEIVED_SET(sg_llsync_temp_data_proc.packet_seq_flag, packet_seq);
        sg_llsync_temp_data_proc.received_packet_num++;
    }

    //LLSYNC_ADV_HEX_PRINTF("recv data", sg_llsync_temp_data_proc.recv_data_len, sg_llsync_temp_data_proc.recv_data_buf);

    ble_qiot_log_i("total num:%d, recv num:%d", sg_llsync_temp_data_proc.total_packet_num, sg_llsync_temp_data_proc.received_packet_num);

    if (sg_llsync_temp_data_proc.total_packet_num == sg_llsync_temp_data_proc.received_packet_num) {
        ble_qiot_log_i("recv ok!");
        sg_llsync_temp_data_proc.data_buf_status = LLSYNC_ADV_DATA_BUF_RECEIVE_OK;
        sg_llsync_temp_data_proc.received_packet_num = 0;
    } else {
        sg_llsync_temp_data_proc.data_buf_status = LLSYNC_ADV_DATA_BUF_RECEIVING;
    }

    return LLSYNC_ADV_RS_OK;
}

static bool llsync_adv_data_recv_ok(uint8_t const *databuf)
{
    if ( LLSYNC_ADV_RS_OK != llsync_adv_data_assemble(databuf)) {
        return false;
    }

    if (LLSYNC_ADV_DATA_BUF_RECEIVE_OK != sg_llsync_temp_data_proc.data_buf_status) {
        return false;
    }

    return true;
}

static int llsync_adv_decrypt_data_padding_remove(uint8_t *pInOutData, uint8_t datalen)
{
    uint8_t padding_len = 0;
    uint8_t i = 0;
    uint8_t j = 0;

    padding_len = pInOutData[datalen-1];

    for (i = 0; i < padding_len; i++) {
        if (padding_len == pInOutData[datalen-1-i]) {
            j++;
        }
    }

    if (j == padding_len) {
        datalen -= padding_len;
    } else {
        ble_qiot_log_e("data err!");
        return LLSYNC_ADV_RS_ERR_PARA;
    }

    ble_qiot_log_i("datalen:%d",datalen);

    return datalen;
}

int llsync_adv_encrypt_data_padding_add(uint8_t *pInOutData, uint8_t datalen)
{
    int padlen = 0;
    int i = 0;

    /*PKCS7-padding*/
    padlen = AES_BLOCKLEN - datalen % AES_BLOCKLEN;

    for(i = 0; i < padlen; i++) {
        pInOutData[datalen+i] = padlen;
    }

    return (datalen + padlen);
}

static int llsync_adv_decrypt_data(void)
{
    int ret = LLSYNC_ADV_RS_OK;
    uint8_t key_buf[MD5_DIGEST_SIZE] = {0};

    if ((sg_llsync_temp_data_proc.recv_data_len % AES_BLOCKLEN) != 0) {
        ble_qiot_log_e("data len err:%d", sg_llsync_temp_data_proc.recv_data_len);
        return LLSYNC_ADV_RS_ERR_PARA;
    }

    llsync_adv_gen_key(key_buf, sg_llsync_record_info.nonce);

    ret = utils_aes_ecb((uint8_t *)sg_llsync_temp_data_proc.recv_data_buf, sg_llsync_temp_data_proc.recv_data_len, UTILS_AES_DECRYPT, key_buf);
    if (LLSYNC_ADV_RS_OK != ret) {
        return ret;
    }

    //LLSYNC_ADV_HEX_PRINTF("aes data", sg_llsync_temp_data_proc.recv_data_len, sg_llsync_temp_data_proc.recv_data_buf);

    ret = llsync_adv_decrypt_data_padding_remove(sg_llsync_temp_data_proc.recv_data_buf, sg_llsync_temp_data_proc.recv_data_len);
    if (ret != LLSYNC_ADV_RS_ERR_PARA) {
        sg_llsync_temp_data_proc.recv_data_len = ret;
        ret = LLSYNC_ADV_RS_OK;
    }

    return ret;
}

static void llsync_adv_sign_calc(e_ble_msg_type type, uint8_t *md5_out_buf)
{
    uint8_t sign_info[64]              = {0};
    int  sign_info_len              = 0;
    uint8_t key_buf[MD5_DIGEST_SIZE] = {0};
    uint16_t dev_addr = (LLSYNC_ADV_MSG_COMPLETE == type) ? sg_llsync_record_info.device_address : sg_llsync_record_info.nonce;

    memcpy(sign_info + sign_info_len, sg_llsync_dev_info.product_id, sizeof(sg_llsync_dev_info.product_id));
    sign_info_len += sizeof(sg_llsync_dev_info.product_id);
    memcpy(sign_info + sign_info_len, sg_llsync_dev_info.device_name, strlen(sg_llsync_dev_info.device_name));
    sign_info_len += strlen(sg_llsync_dev_info.device_name);
    memcpy(sign_info + sign_info_len, &dev_addr, LLSYNC_ADV_DEV_ADDR_LEN);
    sign_info_len += LLSYNC_ADV_DEV_ADDR_LEN;
    llsync_adv_gen_key(key_buf, dev_addr);

    sign_info_len = llsync_adv_encrypt_data_padding_add((uint8_t *)sign_info, sign_info_len);

    if (LLSYNC_ADV_RS_OK != utils_aes_ecb((uint8_t *)sign_info, sign_info_len, UTILS_AES_ENCRYPT, key_buf)) {
        ble_qiot_log_i("aes encrypt err!");
        return;
    }

    utils_md5(sign_info, sign_info_len, md5_out_buf);
}

static uint8_t llsync_adv_data_build(e_ble_msg_type type, uint8_t ack, uint8_t start_index)
{
    uint16_t dev_addr = HTONS(sg_llsync_record_info.device_address);
    uint8_t end_index = start_index;
    uint8_t msg_len = LLSYNC_ADV_MSG_HEADER_LEN+LLSYNC_ADV_DEV_ADDR_LEN+LLSYNC_ADV_ACK_LEN;
    uint8_t md5_out_buf[MD5_DIGEST_SIZE] = {0};
    uint8_t i = 0;

    if (((type == LLSYNC_ADV_MSG_INVITE_ACK) || (type == LLSYNC_ADV_MSG_COMPLETE)) && (ack == LLSYNC_ADV_ACK_SUCC)) {
        msg_len += LLSYNC_ADV_SIGN_LEN;
    }

    raw_pre_data[end_index++] = LLSYNC_ADV_SINGLE_PACKET;
    raw_pre_data[end_index++] = msg_len;
    raw_pre_data[end_index++] = LLSYNC_ADV_GET_MSG_HEADER(sg_llsync_temp_data_proc.msg_head, type);

    switch (type) {
        case LLSYNC_ADV_MSG_DELETE:
        case LLSYNC_ADV_MSG_ACK:
            memcpy(raw_pre_data + end_index, &dev_addr, LLSYNC_ADV_DEV_ADDR_LEN);
            end_index += LLSYNC_ADV_DEV_ADDR_LEN;
            break;

        case LLSYNC_ADV_MSG_COMPLETE:
            if (ack == LLSYNC_ADV_ACK_SUCC) {
                memcpy(raw_pre_data + end_index, &dev_addr, LLSYNC_ADV_DEV_ADDR_LEN);
                end_index += LLSYNC_ADV_DEV_ADDR_LEN;
            } else {
                raw_pre_data[end_index++] = sg_llsync_dev_info.mac[4];
                raw_pre_data[end_index++] = sg_llsync_dev_info.mac[5];
            }
            break;

        case LLSYNC_ADV_MSG_INVITE_ACK:
            raw_pre_data[end_index++] = sg_llsync_dev_info.mac[4];
            raw_pre_data[end_index++] = sg_llsync_dev_info.mac[5];
            break;

        default:
            break;
    }

    raw_pre_data[end_index++] = ack;

    if (((type == LLSYNC_ADV_MSG_INVITE_ACK) || (type == LLSYNC_ADV_MSG_COMPLETE)) && (ack == LLSYNC_ADV_ACK_SUCC)) {
        llsync_adv_sign_calc(type, md5_out_buf);

        for (i = 0; i < MD5_DIGEST_SIZE / 2; i++) {
            raw_pre_data[end_index++] = md5_out_buf[i] ^ md5_out_buf[i + MD5_DIGEST_SIZE / 2];
        }
    }

    return (end_index - start_index);
}

/*************************Device control message****************************
|   CID    |  PackageNum |  Length   | Msgheader | dev addr |  ctrl data   |
|  2 bytes |   1 byte    |  1 byte   |  1 byte   |  2 bytes |  n <=9 bytes |
***************************************************************************/
static ble_qiot_ret_status_t llsync_adv_data_ctrl(uint8_t const *databuf)
{
    ble_qiot_ret_status_t ret = LLSYNC_ADV_RS_OK;

    if (!llsync_adv_data_recv_ok(databuf)) {
        return LLSYNC_ADV_RS_OK;
    }

    ret = llsync_adv_decrypt_data();
    if (ret != LLSYNC_ADV_RS_OK) {
        ble_qiot_log_e("aes decrypt err.");
        return ret;
    }

    llsync_adv_ctrl_data_handle((char *)(sg_llsync_temp_data_proc.recv_data_buf), sg_llsync_temp_data_proc.recv_data_len);

    return ret;
}

void llsync_adv_gen_key(uint8_t *key, uint16_t nonce)
{
	uint8_t xor_buf[LLSYNC_ADV_PSK_LEN] 	     = {0};
    uint8_t i = 0;
    uint8_t j = 0;
    uint8_t *temp = (uint8_t *)&nonce;

    //XOR using psk and nonce loop
    for (i = 0; i < LLSYNC_ADV_PSK_LEN; i++) {
		xor_buf[i] = sg_llsync_dev_info.psk[i] ^ temp[j];
        j ^= 1;
	}

	utils_md5(xor_buf, LLSYNC_ADV_PSK_LEN, key);

	return;
}

/**********Distribution network invitation broadcast protocol************
|   CID    |  PackageNum |  Length   | Msgheader | Mac[4:5] |  nonce    |
|  2 bytes |   1 byte    |  1 byte   |  1 byte   |  2 bytes |  2 bytes  |
************************************************************************/
static ble_qiot_ret_status_t llsync_adv_provisioning_invite(uint8_t const *databuf)
{
    uint8_t index = LLSYNC_ADV_INDEX_LEN;
    uint16_t nonce_num = 0;

    ble_qiot_log_i("llsync adv provisioning invite!");

    if (!llsync_adv_data_recv_ok(databuf)) {
        return LLSYNC_ADV_RS_OK;
    }

    memcpy(&nonce_num, sg_llsync_temp_data_proc.recv_data_buf, sizeof(nonce_num));
    sg_llsync_record_info.nonce = HTONS(nonce_num);

    ble_qiot_log_i("nonce:%x", sg_llsync_record_info.nonce);

    if (user_cb.llsync_dev_operate_cb) {
        user_cb.llsync_dev_operate_cb(LLSYNC_ADV_DEV_START_NET_HINT);
    }

    /**********Distribution network invitation confirmation message*******************
    |   CID    |  PackageNum |  Length   | Msgheader | Mac[4:5] |  ACK    |  Sign    |
    |  2 bytes |   1 byte    |  1 byte   |  1 byte   |  2 bytes |  1 byte |  8 bytes |
    *********************************************************************************/
    if ((user_cb.llsync_dev_operate_cb) && (LLSYNC_ADV_RS_OK != user_cb.llsync_dev_operate_cb(LLSYNC_ADV_DEV_AGREE_NET_HINT)) ) {
        //The user does not agree with the distribution network
        index += llsync_adv_data_build(LLSYNC_ADV_MSG_INVITE_ACK, LLSYNC_ADV_ACK_FAIL, index);
    } else {
        index += llsync_adv_data_build(LLSYNC_ADV_MSG_INVITE_ACK, LLSYNC_ADV_ACK_SUCC, index);
    }

    //LLSYNC_ADV_HEX_PRINTF("net data", index, sg_llsync_temp_data_proc.adv_data.send_buf);

    llsync_data_to_adv_buf(raw_pre_data, index, LLSYNC_ADV_PROVISIONING_RSP_TYPE);

    llsync_adv_start(LLSYNC_ADV_PROVISIONING_RSP_TYPE, sg_llsync_temp_data_proc.adv_data.send_len);

    return LLSYNC_ADV_RS_OK;
}

/**************************Distribution network data issuance******************************
|   CID    |  PackageNum |  Length   | Msgheader | Mac[4:5] |  Encrypt provisioning data   |
|  2 bytes |   1 byte    |  1 byte   |  1 byte   |  2 bytes |         n bytes              |
*******************************************************************************************/
static ble_qiot_ret_status_t llsync_adv_provisioning_data(uint8_t const *databuf)
{
    ble_qiot_ret_status_t ret = LLSYNC_ADV_RS_OK;
    uint8_t index = LLSYNC_ADV_INDEX_LEN;
    uint16_t dev_addr = 0;

    if (!llsync_adv_data_recv_ok(databuf)) {
        return LLSYNC_ADV_RS_OK;
    }

    ret = llsync_adv_decrypt_data();
    if (LLSYNC_ADV_RS_OK == ret) {
        dev_addr = (sg_llsync_temp_data_proc.recv_data_buf[1] << 8) | sg_llsync_temp_data_proc.recv_data_buf[0];

        sg_llsync_record_info.device_address = HTONS(dev_addr);

        ble_qiot_log_i("dev addr:%02x", sg_llsync_record_info.device_address);

        index += llsync_adv_data_build(LLSYNC_ADV_MSG_COMPLETE, LLSYNC_ADV_ACK_SUCC, index);
    } else {
        index += llsync_adv_data_build(LLSYNC_ADV_MSG_COMPLETE, LLSYNC_ADV_ACK_FAIL, index);
    }

    llsync_data_to_adv_buf(raw_pre_data, index, LLSYNC_ADV_PROVISIONING_RSP_TYPE);

    llsync_adv_start(LLSYNC_ADV_PROVISIONING_RSP_TYPE, sg_llsync_temp_data_proc.adv_data.send_len);

    return ret;
}

/*********************Device delete message ack***********************
|   CID    |  PackageNum |  Length   | Msgheader | dev addr |  ACK   |
|  2 bytes |   1 byte    |  1 byte   |  1 byte   |  2 bytes | 1 byte |
*********************************************************************/
static void ble_adv_delete_dev(void)
{
    uint8_t index = LLSYNC_ADV_INDEX_LEN;

    index += llsync_adv_data_build(LLSYNC_ADV_MSG_DELETE, LLSYNC_ADV_ACK_SUCC, index);

    llsync_data_to_adv_buf(raw_pre_data, index, LLSYNC_ADV_PROVISIONING_RSP_TYPE);

    memset(&sg_llsync_record_info, 0, sizeof(sg_llsync_record_info));
    if (sizeof(sg_llsync_record_info) != user_cb.llsync_flash_cb(LLSYNC_ADV_WRITE_FLASH, LLSYNC_ADV_RECORD_FLASH_ADDR, \
                            (char *)&sg_llsync_record_info, sizeof(sg_llsync_record_info))) {
        ble_qiot_log_e("llsync adv write flash failed");
        return;
    }

    llsync_adv_start(LLSYNC_ADV_PROVISIONING_RSP_TYPE, sg_llsync_temp_data_proc.adv_data.send_len);

    if (user_cb.llsync_dev_operate_cb) {
        user_cb.llsync_dev_operate_cb(LLSYNC_ADV_DEV_DELETE_HINT);
    }

    llsync_dev_net_distribution();
}

/***************Device delete message************************
|   CID    |  PackageNum |  Length   | Msgheader | dev addr |
|  2 bytes |   1 byte    |  1 byte   |  1 byte   |  2 bytes |
************************************************************/
static ble_qiot_ret_status_t llsync_adv_provisioning_delete(uint8_t const *databuf)
{
    if (!llsync_adv_data_recv_ok(databuf)) {
        return LLSYNC_ADV_RS_OK;
    }

    ble_adv_delete_dev();

    return LLSYNC_ADV_RS_OK;
}

static ble_qiot_ret_status_t llsync_adv_ack_handle(uint8_t const *databuf)
{
    if (!llsync_adv_data_recv_ok(databuf)) {
        return LLSYNC_ADV_RS_OK;
    }

    LLSYNC_ADV_OR_ACK_BIT_SET1(sg_adv_or_ack_status, LLSYNC_ACK_STATUS_BIT);

    ble_qiot_log_i("llsync adv recv ack:%d", databuf[LLSYNC_ADV_DATA_INDEX]);

    if (LLSYNC_ADV_ACK_SUCC == databuf[LLSYNC_ADV_DATA_INDEX]) {
        //msg id is cycled between 1 to 15
        sg_message_id = (sg_message_id % 0x0F) + 1;
    }

    if ((!ble_fifo_isempty(&llsync_fifo)) || (!llsync_pro_fifo_is_empty())) {
        LLSYNC_ADV_OR_ACK_BIT_SET0(sg_adv_or_ack_status, LLSYNC_ACK_STATUS_BIT);
        llsync_timer_start_if_stop();
    }

    return LLSYNC_ADV_RS_OK;
}

/***************Network distribution complete ack*********************
|   CID    |  PackageNum |  Length   | Msgheader | dev addr |  ACK   |
|  2 bytes |   1 byte    |  1 byte   |  1 byte   |  2 bytes | 1 byte |
**********************************************************************/
static ble_qiot_ret_status_t llsync_adv_provisioning_data_ack(uint8_t const *databuf)
{
    ble_qiot_ret_status_t ret = LLSYNC_ADV_RS_OK;

    if (!llsync_adv_data_recv_ok(databuf)) {
        return LLSYNC_ADV_RS_OK;
    }

    if (LLSYNC_ADV_ACK_SUCC == databuf[LLSYNC_ADV_DATA_INDEX]) {
        sg_llsync_record_info.bind_state = LLSYNC_ADV_DEV_STATUS_BIND_OK;

        if (sizeof(sg_llsync_record_info) != user_cb.llsync_flash_cb(LLSYNC_ADV_WRITE_FLASH, LLSYNC_ADV_RECORD_FLASH_ADDR, \
                            (char *)&sg_llsync_record_info, sizeof(sg_llsync_record_info))) {
            ble_qiot_log_e("llsync adv write flash failed");
            ret = LLSYNC_ADV_RS_ERR;
        }
    } else {
        ble_qiot_log_e("provisioning ack status err");
        ret = LLSYNC_ADV_RS_ERR;
    }

    return ret;
}

static bool llsync_adv_bind_status_is_right(uint8_t msg_type)
{
    switch(msg_type) {
        case LLSYNC_ADV_MSG_INVITE:
        case LLSYNC_ADV_MSG_DATA:
        case LLSYNC_ADV_MSG_COMPLETE_ACK:
            return (LLSYNC_ADV_DEV_STATUS_BIND_OK != sg_llsync_record_info.bind_state);

        case LLSYNC_ADV_MSG_DELETE:
        case LLSYNC_ADV_MSG_CONTROL:
        case LLSYNC_ADV_MSG_ACK:
            return (LLSYNC_ADV_DEV_STATUS_BIND_OK == sg_llsync_record_info.bind_state);
    }

    return false;
}

static void llsync_adv_scan_switch(void)
{
    static uint8_t adv_scan_flag = 0;

    adv_scan_flag ^= 1;

    if (0 == adv_scan_flag) {
        #if !LLSYNC_DEV_ADV_AND_SCAN
        llsync_scan_stop_if_start();
        #endif
        llsync_adv_start_if_stop();
    } else {
        llsync_adv_stop_if_start();
        #if !LLSYNC_DEV_ADV_AND_SCAN
        llsync_scan_start_if_stop();
        #endif
    }
}

static bool llsync_adv_data_filter(uint8_t const *databuf)
{
    uint8_t msg_type = LLSYNC_ADV_GET_MSG_TYPE(databuf[LLSYNC_ADV_MSG_HEADER_INDEX]);
    uint16_t dev_addr = HTONS(sg_llsync_record_info.device_address);

    ble_qiot_log_i("buf:%x,mac:%x %x, addr:%x,type:%d,bind:%d", databuf[LLSYNC_ADV_DEV_ADDR_INDEX], sg_llsync_dev_info.mac[4], 
                    sg_llsync_dev_info.mac[5], dev_addr, msg_type, sg_llsync_record_info.bind_state);

    switch(msg_type) {
        case LLSYNC_ADV_MSG_INVITE:
        case LLSYNC_ADV_MSG_DATA:
            LLSYNC_ADV_DEV_ADDR_CHECK(&databuf[LLSYNC_ADV_DEV_ADDR_INDEX], &sg_llsync_dev_info.mac[4], LLSYNC_ADV_RS_ERR_PARA);
            break;

        case LLSYNC_ADV_MSG_COMPLETE_ACK:
        case LLSYNC_ADV_MSG_DELETE:
        case LLSYNC_ADV_MSG_CONTROL:
        case LLSYNC_ADV_MSG_ACK:
            LLSYNC_ADV_DEV_ADDR_CHECK(&databuf[LLSYNC_ADV_DEV_ADDR_INDEX], &dev_addr, LLSYNC_ADV_RS_ERR_PARA);
            break;
    }

    return llsync_adv_bind_status_is_right(msg_type);
}

static ble_qiot_ret_status_t llsync_adv_data_analysis(uint8_t const *databuf)
{
    uint8_t msg_type = LLSYNC_ADV_GET_MSG_TYPE(databuf[LLSYNC_ADV_MSG_HEADER_INDEX]);
    ble_qiot_ret_status_t ret = LLSYNC_ADV_RS_ERR;
    static uint8_t msg_id = 0;

    //ble_qiot_log_i("type:%d,buf[2]:%x,buf[4]:%x,msg id:%x, buf status:%d", msg_type, databuf[LLSYNC_ADV_PACKAGE_NUM_INDEX], 
    //                databuf[LLSYNC_ADV_MSG_HEADER_INDEX],msg_id,sg_llsync_temp_data_proc.data_buf_status);
    if (((databuf[LLSYNC_ADV_MSG_HEADER_INDEX]) == (msg_id)) && (!LLSYNC_PACKET_SEQ_NOT_RECEIVED(sg_llsync_temp_data_proc.packet_seq_flag, 
        LLSYNC_ADV_GET_PACKET_SEQ(databuf[LLSYNC_ADV_PACKAGE_NUM_INDEX])))) {
        ble_qiot_log_d("repeate msg!");
        return LLSYNC_ADV_RS_OK;
    }

    if (!llsync_adv_data_filter(databuf)) {
        ble_qiot_log_e("addr err");
        return ret;
    }

    if ((databuf[LLSYNC_ADV_MSG_HEADER_INDEX]) != (msg_id)) {
        msg_id = databuf[LLSYNC_ADV_MSG_HEADER_INDEX];
        llsync_adv_buf_clear();
        sg_llsync_temp_data_proc.packet_seq_flag = 0;
        sg_llsync_temp_data_proc.data_buf_status = LLSYNC_ADV_DATA_BUF_IDLE;
        llsync_timer_stop_if_start();
        llsync_adv_stop_if_start();
    }

    if (ble_fifo_isempty(&llsync_fifo)) {
        LLSYNC_ADV_OR_ACK_BIT_SET0(sg_adv_or_ack_status, LLSYNC_ADV_STATUS_BIT);
    }

    switch(msg_type) {
        case LLSYNC_ADV_MSG_INVITE:
            ret = llsync_adv_provisioning_invite(databuf);
            break;

        case LLSYNC_ADV_MSG_DATA:
            ret = llsync_adv_provisioning_data(databuf);
            break;

        case LLSYNC_ADV_MSG_COMPLETE_ACK:
            ret = llsync_adv_provisioning_data_ack(databuf);
            break;

        case LLSYNC_ADV_MSG_DELETE:
            ret = llsync_adv_provisioning_delete(databuf);
            break;

        case LLSYNC_ADV_MSG_CONTROL:
            ret = llsync_adv_data_ctrl(databuf);
            break;

        case LLSYNC_ADV_MSG_ACK:
            ret = llsync_adv_ack_handle(databuf);
            break;

        default:
            ble_qiot_log_e("msg_type err:%d", msg_type);
            break;
    }

    return ret;
}

/*********************Device delete message ack***********************
|   CID    |  PackageNum |  Length   | Msgheader | dev addr |  ACK   |
|  2 bytes |   1 byte    |  1 byte   |  1 byte   |  2 bytes | 1 byte |
*********************************************************************/
void llsync_adv_ctrl_data_ack(uint8_t ret)
{
    uint8_t index = LLSYNC_ADV_INDEX_LEN;

    index += llsync_adv_data_build(LLSYNC_ADV_MSG_ACK, (ret == LLSYNC_ADV_RS_OK) ? LLSYNC_ADV_ACK_SUCC : LLSYNC_ADV_ACK_FAIL, index);

    llsync_data_to_adv_buf(raw_pre_data, index, LLSYNC_ADV_PROVISIONING_RSP_TYPE);

    llsync_adv_start(LLSYNC_ADV_PROVISIONING_RSP_TYPE, sg_llsync_temp_data_proc.adv_data.send_len);
}

static void llsync_adv_stop_succ_handle(void)
{
    if ((sg_llsync_temp_data_proc.adv_time_type == LLSYNC_ADV_DATA_REPORT_SPLIT_TYPE)) {
        llsync_timer_stop_if_start();
        #if !LLSYNC_DEV_ADV_AND_SCAN
        llsync_scan_start_if_stop();
        #endif
        llsync_adv_buf_clear();
        sg_llsync_temp_data_proc.adv_time_type = LLSYNC_ADV_PROPERTY_WAIT_ACK_TYPE;
        llsync_timer_start_if_stop();
    }
}

static void llsync_adv_fifo_data_handle(void)
{
    uint8_t data_len = 0;
    uint8_t i = 0;

    data_len = ble_fifo_pop(&llsync_fifo);
    sg_llsync_temp_data_proc.adv_time_type = ble_fifo_pop(&llsync_fifo);
    memset(sg_llsync_temp_data_proc.adv_data.send_buf, 0, sizeof(sg_llsync_temp_data_proc.adv_data.send_buf));

    for (i = 0; i < data_len; i++) {
        sg_llsync_temp_data_proc.adv_data.send_buf[i] = ble_fifo_pop(&llsync_fifo);
        //ble_qiot_log_i("data:%d-%x",i, sg_llsync_temp_data_proc.adv_data.send_buf[i]);
    }

    ble_qiot_log_i("cnt:%d, time type:%d,",sg_llsync_timer_cnt, sg_llsync_temp_data_proc.adv_time_type);

    sg_llsync_temp_data_proc.adv_data.send_len = data_len;
    if (LLSYNC_ADV_NOT_NETWORK_TYPE != sg_llsync_temp_data_proc.adv_time_type) {
        sg_llsync_temp_data_proc.adv_data.send_len = LLSYNC_ADV_DATA_TOTAL_LENGTH;
    }

    llsync_adv_start_if_stop();

    LLSYNC_ADV_OR_ACK_BIT_SET1(sg_adv_or_ack_status, LLSYNC_ADV_STATUS_BIT);
}

static void llsync_adv_not_network_handle(void)
{
    sg_llsync_timer_cnt++;
    if (!(sg_llsync_timer_cnt%((int)LLSYNC_ADV_SINGLE_DURATION/LLSYNC_ADV_TIMER_INTERVAL))) {
        llsync_adv_scan_switch();
    } 

    if ((sg_llsync_timer_cnt*LLSYNC_ADV_TIMER_INTERVAL) >= LLSYNC_ADV_TOTAL_TIME) {
        sg_llsync_timer_cnt = 0;
        LLSYNC_ADV_OR_ACK_BIT_SET0(sg_adv_or_ack_status, LLSYNC_ADV_STATUS_BIT);
        if (ble_fifo_isempty(&llsync_fifo)) {
            llsync_adv_stop_if_start();
            #if !LLSYNC_DEV_ADV_AND_SCAN
            llsync_scan_start_if_stop();
            #endif
        } else {
            llsync_adv_stop_if_start();
        }
    }
}

static void llsync_adv_provosioning_rsp_handle(void)
{
    sg_llsync_timer_cnt++;
    #if !LLSYNC_DEV_ADV_AND_SCAN
    if (!(sg_llsync_timer_cnt%(LLSYNC_ADV_SCAN_INTERVAL/LLSYNC_ADV_TIMER_INTERVAL))) {
        llsync_adv_scan_switch();
        return;
    }
    #endif

    if ((sg_llsync_timer_cnt*LLSYNC_ADV_TIMER_INTERVAL) >= LLSYNC_ADV_RSP_DURATION) {
        ble_qiot_log_i("rsp stop");
        sg_llsync_timer_cnt = 0;
        LLSYNC_ADV_OR_ACK_BIT_SET0(sg_adv_or_ack_status, LLSYNC_ADV_STATUS_BIT);
        if (ble_fifo_isempty(&llsync_fifo)) {
            llsync_adv_stop_if_start();
            #if !LLSYNC_DEV_ADV_AND_SCAN
            llsync_scan_start_if_stop();
            #endif
        } else {
            llsync_adv_stop_if_start();
        }
    }
}

static void llsync_adv_data_split_report_handle(void)
{
    sg_llsync_timer_cnt++;
    if ((sg_llsync_timer_cnt*LLSYNC_ADV_TIMER_INTERVAL) >= LLSYNC_ADV_INTERVAL*10) {
        sg_llsync_timer_cnt = 0;
        llsync_adv_stop_if_start();
        if (!llsync_adv_data_split_finish()) {
            LLSYNC_ADV_OR_ACK_BIT_SET0(sg_adv_or_ack_status, LLSYNC_ADV_STATUS_BIT);
            llsync_adv_property_data_report();
        } else {
            llsync_adv_stop_succ_handle();
        }
    }
}

static void llsync_adv_wait_ack_handle(void)
{
    static uint8_t report_num = 0;

    sg_llsync_timer_cnt++;
    if (sg_llsync_timer_cnt*LLSYNC_ADV_TIMER_INTERVAL <= LLSYNC_ADV_TIMER_WAIT_ACK_PERIOD) {
        if (LLSYNC_ADV_OR_ACK_BIT_GET(sg_adv_or_ack_status, LLSYNC_ACK_STATUS_BIT)) {
            ble_qiot_log_i("recv ack ok");
            sg_llsync_timer_cnt = 0;
            LLSYNC_ADV_OR_ACK_BIT_SET0(sg_adv_or_ack_status, LLSYNC_ADV_STATUS_BIT);
            if (ble_fifo_isempty(&llsync_fifo)) {
                report_num = 0;
                LLSYNC_ADV_OR_ACK_BIT_SET0(sg_adv_or_ack_status, LLSYNC_ACK_STATUS_BIT);
            } else {
                llsync_adv_stop_if_start();
            }
        }
    } else {
        sg_llsync_timer_cnt = 0;
        LLSYNC_ADV_OR_ACK_BIT_SET0(sg_adv_or_ack_status, LLSYNC_ADV_STATUS_BIT);
        if (LLSYNC_ADV_RETRANSMISSION_NUM == report_num) {
            report_num = 0;
            ble_qiot_log_i("Resend completed, no ACK received!");
            return;
        }
        report_num++;
        llsync_adv_property_report_again();
    }
}

void llsync_adv_timer_cb(void *param)
{
    if (!LLSYNC_ADV_OR_ACK_BIT_GET(sg_adv_or_ack_status, LLSYNC_ADV_STATUS_BIT)) {
        if (!ble_fifo_isempty(&llsync_fifo)) {
            llsync_adv_fifo_data_handle();
        } else if (!llsync_pro_fifo_is_empty()) {
            llsync_pro_get_data();
        } else {
            llsync_timer_stop_if_start();
        }
    }

    switch(sg_llsync_temp_data_proc.adv_time_type) {
        case LLSYNC_ADV_NOT_NETWORK_TYPE:
            llsync_adv_not_network_handle();
            break;

        case LLSYNC_ADV_PROVISIONING_RSP_TYPE:
            llsync_adv_provosioning_rsp_handle();
            break;

        case LLSYNC_ADV_DATA_REPORT_SPLIT_TYPE:
            llsync_adv_data_split_report_handle();
            break;

        case LLSYNC_ADV_PROPERTY_WAIT_ACK_TYPE:
            llsync_adv_wait_ack_handle();
            break;

        default:
            break;
    }

    return;
}

static ble_qiot_ret_status_t llsync_adv_net_init(void)
{
    if (sizeof(sg_llsync_record_info) != user_cb.llsync_flash_cb(LLSYNC_ADV_READ_FLASH, LLSYNC_ADV_RECORD_FLASH_ADDR,  \
                            (char *)&sg_llsync_record_info, sizeof(sg_llsync_record_info))) {
        ble_qiot_log_e("llsync adv read flash fail.");
        return LLSYNC_ADV_RS_ERR;
    }

    user_cb.llsync_dev_info_cb(&sg_llsync_dev_info);

    if (strlen(sg_llsync_dev_info.device_name) > LLSYNC_ADV_DEV_NAME_MAX_LEN) {
        ble_qiot_log_e("llsync dev name too long!");
        return LLSYNC_ADV_RS_ERR_PARA;
    }

    sg_llsync_adv_timer = user_cb.llsync_timer_create(LLSYNC_ADV_TIMER_PERIOD_TYPE, llsync_adv_timer_cb);
    if (NULL == sg_llsync_adv_timer) {
        ble_qiot_log_e("llsync adv timer create failed");
        return LLSYNC_ADV_RS_ERR;
    }

    llsync_adv_buf_clear();

    memset(&sg_llsync_temp_data_proc, 0, sizeof(ble_adv_handle_t));

	ble_fifo_init(&llsync_fifo, llsync_fifo_buf, sizeof(llsync_fifo_buf));

    llsync_adv_property_fifo_init();

    return LLSYNC_ADV_RS_OK;
}

ble_qiot_ret_status_t ble_scan_data_analyze(uint8_t *buf, uint8_t buf_len)
{
    uint8_t databuf[20] = {0};

    if (llsync_is_mesh_packet(buf, buf_len, databuf)) {
        if (LLSYNC_ADV_RS_OK != llsync_adv_data_analysis(databuf)) {
            ble_qiot_log_e("llsync adv data analyze err!");
            return LLSYNC_ADV_RS_ERR;
        }
    }

    return LLSYNC_ADV_RS_OK;
}

void llsync_adv_user_init(llsync_external_cb *user_cb)
{
    user_cb->llsync_dev_info_cb = llsync_get_dev_info;
    user_cb->llsync_flash_cb = llsync_flash_handle;
    user_cb->llsync_adv_cb = llsync_adv_handle;
    user_cb->llsync_scan_cb = llsync_scan_handle;
    user_cb->llsync_dev_operate_cb = llsync_dev_operate_handle;
    user_cb->llsync_timer_create = llsync_timer_create;
    user_cb->llsync_timer_start = llsync_timer_start;
    user_cb->llsync_timer_stop = llsync_timer_stop;
    user_cb->llsync_user_init = llsync_adv_user_ex_init;
}

ble_qiot_ret_status_t llsync_adv_init(void)
{
    ble_qiot_set_log_level(BLE_QIOT_LOG_LEVEL_INFO);

    ble_qiot_log_i("llsync adv init enter.");

    llsync_adv_user_init(&user_cb);

    if (LLSYNC_ADV_RS_OK != llsync_adv_net_init()) {
        return LLSYNC_ADV_RS_ERR;
    }

    llsync_dev_net_distribution();

    #if LLSYNC_DEV_ADV_AND_SCAN
    llsync_scan_start_if_stop();
    #endif

    llsync_adv_user_ex_init();

    return LLSYNC_ADV_RS_OK;
}

/****************************************************************************************************************/

ble_dev_stor_t llsync_adv_stor_get(void)
{
    return sg_llsync_record_info;
}

uint8_t llsync_adv_msg_id_get(void)
{
    return sg_message_id;
}

bool llsync_center_fifo_is_empty(void)
{
    return ble_fifo_isempty(&llsync_fifo);
}

#ifdef __cplusplus
}
#endif
