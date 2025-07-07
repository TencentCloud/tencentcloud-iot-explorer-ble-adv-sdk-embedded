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
#ifndef TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SDK_INTERNAL_INC_BLE_QIOT_ADV_CENTER_H_
#define TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SDK_INTERNAL_INC_BLE_QIOT_ADV_CENTER_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "ble_qiot_common.h"
#include "ble_qiot_adv_export.h"

/* Split data size */
#define LLSYNC_ADV_PAYLOAD_SEGMENT_LEN    (9)

/* Maximum length of device name */
#define LLSYNC_ADV_DEV_NAME_MAX_LEN       (8)

/* The total length of data of ad type 01 */
#define LLSYNC_ADV_FLAGS_LEN              (3)

/* The total length of data of ad type 07 */
#define LLSYNC_ADV_COMPLETE_128_BIT_UUIDS_LEN         (18)

/* The total length of the overall adv data */
#define LLSYNC_ADV_DATA_TOTAL_LENGTH      (LLSYNC_ADV_FLAGS_LEN+LLSYNC_ADV_COMPLETE_128_BIT_UUIDS_LEN)

/* adv protocol sub-packaging related data subscript index */
#define LLSYNC_ADV_PACKAGE_NUM_INDEX      (2)

/* adv protocol carries data length index */
#define LLSYNC_ADV_DATA_LEN_INDEX         (3)

/* adv protocol message header related data subscript index */
#define LLSYNC_ADV_MSG_HEADER_INDEX       (4)

/* adv protocol device address related data subscript index */
#define LLSYNC_ADV_DEV_ADDR_INDEX         (5)

/* adv protocol valid data subscript index */
#define LLSYNC_ADV_DATA_INDEX             (7)

/* Receive data identification, the corresponding data bit has data as 1, and no data as 0 */
#define  LLSYNC_PACKET_SEQ_RECEIVED_SET(x, y)     ((x) |= (0x01 << (y)))
#define  LLSYNC_PACKET_SEQ_NOT_RECEIVED(x, y)     (!((x) >> (y) & 0x01))

/* Is it currently in the adv stage, stored in the zero bit */
#define LLSYNC_ADV_STATUS_BIT             (0)

/*  Whether ack is received, stored in the first bit */
#define LLSYNC_ACK_STATUS_BIT             (1)

/* Set the corresponding bit to 1 */
#define LLSYNC_ADV_OR_ACK_BIT_SET1(x, y)  ((x) |= (0x01 << (y)))

/* Set the corresponding bit to 0 */
#define LLSYNC_ADV_OR_ACK_BIT_SET0(x, y)  ((x) &= ~(0x01 << (y)))

/* Get the corresponding bit */
#define LLSYNC_ADV_OR_ACK_BIT_GET(x, y)   ((x) >> (y) & 0x01)

/* The start and stop status of the adv, stored in the 0th bit */
#define LLSYNC_ADV_START_OR_STOP_BIT      (0)

/* The start and stop status of the scan, stored in the 1th bit */
#define LLSYNC_SCAN_START_OR_STOP_BIT     (1)

/* The start and stop status of the timer, stored in the 2th bit */
#define LLSYNC_TIMER_START_OR_STOP_BIT    (2)

/* Set the corresponding bit to 1 */
#define LLSYNC_SCAN_ADV_TIMER_START_SET(x, y)     ((x) |= (0x01 << (y)))

/* Set the corresponding bit to 0 */
#define LLSYNC_SCAN_ADV_TIMER_STOP_SET(x, y)      ((x) &= ~(0x01 << (y)))

/* Get the corresponding bit */
#define LLSYNC_SCAN_ADV_TIMER_BIT_GET(x, y)       ((x) >> (y) & 0x01)

#define LLSYNC_ADV_FIFOBUF_LEN              (256)

/* AD Type 0xFF */
#define LLSYNC_ADV_AD_TYPE_MANUFACTURE      (0xFF)

/* AD Type 0x07 */
#define LLSYNC_ADV_AD_TYPE_COMPLETE_128UUIDS  (0x07)

/* Custom header identification */
#define LLSYNC_ADV_UUID                     (0xfeba)

/* uuid high 4 bits */
#define LLSYNC_ADV_UUID_HIGH                ((LLSYNC_ADV_UUID >> 8) & 0xff)

/* uuid low 4 bits */
#define LLSYNC_ADV_UUID_LOW                 (LLSYNC_ADV_UUID & 0xff)

/* The length of the adv protocol field CID */
#define LLSYNC_ADV_CID_LEN                 (2)

/* The length of the adv protocol field MsgHeader */
#define LLSYNC_ADV_MSG_HEADER_LEN          (1)

/* The length of the adv protocol field dev addr */
#define LLSYNC_ADV_DEV_ADDR_LEN            (2)

/* The length of the adv protocol field ack */
#define LLSYNC_ADV_ACK_LEN                 (1)

/* ack response success is 0 */
#define LLSYNC_ADV_ACK_SUCC                (0)

/* ack response fail is 1 */
#define LLSYNC_ADV_ACK_FAIL                (1)

/* The length of the adv protocol field frame ctrl */
#define LLSYNC_ADV_FRAME_CTRL_LEN          (2)

/* The last two digits of the mac address */
#define LLSYNC_ADV_MAC_LAST_LEN            (2)

/* Datagram sequence number */
#define LLSYNC_ADV_GET_PACKET_SEQ(x)       ((x) & 0x0F)

/* Adv message type */
#define LLSYNC_ADV_GET_MSG_TYPE(x)         ((x) & 0x0F)

/* Total number of packets of fragmented data */
#define LLSYNC_ADV_GET_TOTAL_PACKET_NUM(x) (((x) >> 4) & 0x0f)

/* Assemble the message header */
#define LLSYNC_ADV_GET_MSG_HEADER(x, y)    (((x) & 0xF0) | (y))

/* The length of the signature data, the first 8 bits and the last 8 bits of the MD5 value are XORed */
#define LLSYNC_ADV_SIGN_LEN                (8)

/* Maximum length of adv data */
#define LLSYNC_ADV_MAX_DATA_LEN            (31)

/* The maximum data length of the received buf */
#define LLSYNC_ADV_MAX_RECV_DATA_LEN       (132)

/* High 8-bit value of frame control */
#define LLSYNC_ADV_FRAME_CTRL_HIGH         ((LLSYNC_ADV_FRAME_CTRL_DATA >> 8) & 0xff)

/* Low 8-bit value of frame control */
#define LLSYNC_ADV_FRAME_CTRL_LOW          (LLSYNC_ADV_FRAME_CTRL_DATA & 0xff)

/* Maximum number of fragments for data packet */
#define LLSYNC_ADV_PACKET_MAX_NUM           (15)

/* Maximum length of reported adv data */
#define LLSYNC_ADV_REPORT_DATA_MAX (LLSYNC_ADV_PAYLOAD_SEGMENT_LEN*LLSYNC_ADV_PACKET_MAX_NUM)

/* Retransmission times of fragmented data */
#define LLSYNC_ADV_SPLIT_RESEND_TIME        (3)

/* adv and scan switching time interval during response, valid when LLSYNC_DEV_ADV_AND_SCAN == 0 */
#define LLSYNC_ADV_SCAN_INTERVAL            (200)

/* The upper four digits represent the total number of packages, 
    and the lower four digits represent the current number of packages */
#define LLSYNC_ADV_SINGLE_PACKET            (0x11)

/* Fixed prefix length for unconfigured adv data */
#define LLSYNC_ADV_UNNET_LEN                (3)

/* Adv fixed data field size */
#define LLSYNC_ADV_INDEX_LEN                (7)

/* Undistributed network adv times */
#define LLSYNC_ADV_COUNT                    (10)

/* The duration of each broadcast of unconfigured equipment is not less than 120ms */
#define LLSYNC_ADV_SINGLE_DURATION          (LLSYNC_ADV_COUNT*((LLSYNC_ADV_INTERVAL/1.0)*0.625))

/* Total adv time without network(ms) */
#define LLSYNC_ADV_TOTAL_TIME               (600*1000)

/* The broadcast time for the device to send a response(ms) */
#define LLSYNC_ADV_RSP_DURATION             (10*1000)

/* Device waiting time for ack(ms) */
#define LLSYNC_ADV_TIMER_WAIT_ACK_PERIOD    (5*1000)

#define LLSYNC_ADV_PROTOCOL_VERSION         (0)
#define LLSYNC_ADV_FRAME_CTRL_DATA          ((1<<15)|LLSYNC_ADV_PROTOCOL_VERSION)

/* The number of retransmissions after the device does not receive ack data */
#define LLSYNC_ADV_RETRANSMISSION_NUM       (3)

/* app fragmentation broadcast cycle (unit: 10ms) */
#define LLSYNC_APP_ADV_SPLIT_CYCLE_TIME     (40)

#define LLSYNC_ADV_DEV_ADDR_CHECK(bufaddr, addr, err)                                     \
    do {                                                                                  \
        if (memcmp(bufaddr, addr, LLSYNC_ADV_DEV_ADDR_LEN)) {                             \
            return false;                                                                 \
        }                                                                                 \
    }while(0)

#define LLSYNC_ADV_HEX_PRINTF(x, y, z)                                                    \
    do {                                                                                  \
        uint8_t i = 0;                                                                    \
        for (i = 0; i < y; i++) {                                                         \
            ble_qiot_log_i("%s:%d-%02x", x, i, z[i]);                                     \
        }                                                                                 \
    }while(0)

typedef enum {
    LLSYNC_ADV_DEV_STATUS_UNBIND = 0,
    LLSYNC_ADV_DEV_STATUS_BIND_OK,
}e_dev_bind_state;

typedef enum {
    LLSYNC_ADV_NOT_NETWORK_TYPE = 0,
    LLSYNC_ADV_PROVISIONING_RSP_TYPE,
    LLSYNC_ADV_DATA_REPORT_SPLIT_TYPE,
    LLSYNC_ADV_PROPERTY_WAIT_ACK_TYPE,
    LLSYNC_ADV_IDLE_MAX_TYPE,
}e_ble_adv_time_type;

typedef enum {
    LLSYNC_ADV_DATA_BUF_IDLE = 0,
    LLSYNC_ADV_DATA_BUF_RECEIVING,
    LLSYNC_ADV_DATA_BUF_RECEIVE_OK,
}e_adv_data_buf_status;

typedef enum {
    /* Distribution network */
    LLSYNC_ADV_MSG_INVITE = 0x00,
    LLSYNC_ADV_MSG_INVITE_ACK,
    LLSYNC_ADV_MSG_DATA,
    LLSYNC_ADV_MSG_COMPLETE,
    LLSYNC_ADV_MSG_COMPLETE_ACK,
    LLSYNC_ADV_MSG_DELETE,

    // Control data type
    LLSYNC_ADV_MSG_CONTROL = 0x08,
    LLSYNC_ADV_MSG_REPORT,

    LLSYNC_ADV_MSG_ACK = 0x0F,
}e_ble_msg_type;

typedef struct {
    uint8_t send_buf[LLSYNC_ADV_MAX_DATA_LEN];    /* advertising data, conform to AD structure */
    uint8_t send_len;                             /* advertising data len */
}ble_adv_raw_t;

typedef struct {
    uint8_t msg_head;
    uint8_t adv_time_type;
    uint8_t data_buf_status;
    uint8_t recv_data_len;
    uint8_t recv_data_buf[LLSYNC_ADV_MAX_RECV_DATA_LEN];
    uint8_t received_packet_num;
    uint8_t total_packet_num;
    uint16_t packet_seq_flag;
    ble_adv_raw_t adv_data;
}ble_adv_handle_t;

typedef struct {
    uint8_t  bind_state;
    uint16_t device_address;
    uint16_t nonce;
}ble_dev_stor_t;

typedef enum {
    LLSYNC_ADV_WRITE_FLASH,
    LLSYNC_ADV_READ_FLASH,
}e_llsync_flash_user;

typedef enum {
    LLSYNC_ADV_START,
    LLSYNC_ADV_STOP,
}e_llsync_adv_user;

typedef enum {
    LLSYNC_SCAN_START,
    LLSYNC_SCAN_STOP,
}e_llsync_scan_user;

typedef enum {
    LLSYNC_ADV_DEV_START_NET_HINT,
    LLSYNC_ADV_DEV_AGREE_NET_HINT,
    LLSYNC_ADV_DEV_DELETE_HINT
}e_llsync_dev_operate_user;

/* timer type */
enum {
    LLSYNC_ADV_TIMER_ONE_SHOT_TYPE = 0,
    LLSYNC_ADV_TIMER_PERIOD_TYPE,
    LLSYNC_ADV_TIMER_BUTT,
};
typedef void *ble_timer_t;

/* timer callback prototype */
typedef void (*ble_timer_cb)(void *param);

typedef struct ble_device_info_t_ {
    char product_id[LLSYNC_ADV_PRODUCT_ID_LEN];
    char device_name[LLSYNC_ADV_DEVICE_NAME_LEN + 1];
    char psk[LLSYNC_ADV_PSK_LEN];
    char mac[LLSYNC_ADV_MAC_LEN];
} ble_device_info_t;

typedef ble_qiot_ret_status_t (*dev_info_get)(ble_device_info_t* dev_info);
typedef int  (*flash_handle)(e_llsync_flash_user type, uint32_t flash_addr, char *buf, uint16_t len);
typedef ble_qiot_ret_status_t (*adv_handle)(e_llsync_adv_user type, uint8_t *data_buf, uint8_t data_len);
typedef ble_qiot_ret_status_t (*scan_handle)(e_llsync_scan_user type);
typedef uint8_t (*dev_operate_handle)(e_llsync_dev_operate_user type);
typedef ble_timer_t (*timer_init)(uint8_t type, ble_timer_cb timeout_handle);
typedef ble_qiot_ret_status_t (*timer_start)(ble_timer_t timer_id, uint32_t period);
typedef ble_qiot_ret_status_t (*timer_stop)(ble_timer_t timer_id);
typedef void (*user_init)(void);

typedef struct {
    dev_info_get llsync_dev_info_cb;
    flash_handle llsync_flash_cb;
    adv_handle llsync_adv_cb;
    scan_handle llsync_scan_cb;
    dev_operate_handle llsync_dev_operate_cb;
    timer_init llsync_timer_create;
    timer_start llsync_timer_start;
    timer_stop llsync_timer_stop;
    user_init llsync_user_init;
}llsync_external_cb;

ble_dev_stor_t llsync_adv_stor_get(void);

ble_qiot_ret_status_t llsync_adv_init(void);

void llsync_adv_gen_key(uint8_t *key, uint16_t nonce);

void llsync_adv_start(e_ble_adv_time_type type, uint8_t index);

void llsync_adv_ctrl_data_ack(uint8_t ret);

void llsync_data_to_adv_buf(uint8_t *raw_adv_data, uint8_t valid_data_len, e_ble_adv_time_type type);

void llsync_adv_user_init(llsync_external_cb *user_cb);

int llsync_adv_encrypt_data_padding_add(uint8_t *pInOutData, uint8_t datalen);

uint8_t llsync_adv_msg_id_get(void);

bool llsync_center_fifo_is_empty(void);

#ifdef __cplusplus
}
#endif
#endif  // TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SDK_INTERNAL_INC_BLE_QIOT_ADV_CENTER_H_