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
#ifndef TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SDK_INTERNAL_INC_BLE_QIOT_FIFO_H_
#define TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SDK_INTERNAL_INC_BLE_QIOT_FIFO_H_
#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"

typedef struct FIFOBuffer {
    unsigned char * volatile head;
    unsigned char * volatile tail;
    unsigned char * begin;
    unsigned char * end;
}FIFOBuffer;

int ble_fifo_isempty(const FIFOBuffer *fb);

int ble_fifo_isfull(const FIFOBuffer *fb);

void ble_fifo_push(FIFOBuffer *fb, unsigned char c);

unsigned char ble_fifo_pop(FIFOBuffer *fb);

void ble_fifo_flush(FIFOBuffer *fb);

int ble_fifo_isfull_locked(const FIFOBuffer *_fb);

void ble_fifo_init(FIFOBuffer *fb, unsigned char *buf, size_t size);

size_t ble_fifo_len(FIFOBuffer *fb);

size_t ble_fifo_idle_buf_len(FIFOBuffer *fb);

#ifdef __cplusplus
}
#endif
#endif  // TENCENTCLOUD_IOT_EXPLORER_BLE_ADV_SDK_EMBEDDED_SDK_INTERNAL_INC_BLE_QIOT_FIFO_H_
