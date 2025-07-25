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

#include "ble_qiot_log.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HEX_DUMP_BYTE_PER_LINE 16

e_ble_qiot_log_level g_log_level = BLE_QIOT_LOG_LEVEL_INFO;

void ble_qiot_set_log_level(e_ble_qiot_log_level level)
{
    g_log_level = level;
    return;
}

#ifdef __cplusplus
}
#endif
