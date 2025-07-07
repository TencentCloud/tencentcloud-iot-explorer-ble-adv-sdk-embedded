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
#include "ble_qiot_fifo.h"

int ble_fifo_isempty(const FIFOBuffer *fb)
{
	return fb->head == fb->tail;
}

int ble_fifo_isfull(const FIFOBuffer *fb)
{
	return
		((fb->head == fb->begin) && (fb->tail == fb->end))
		|| (fb->tail == fb->head - 1);
}

void ble_fifo_push(FIFOBuffer *fb, unsigned char c)
{
	*(fb->tail) = c;

	if ((fb->tail == fb->end))
		fb->tail = fb->begin;
	else
		fb->tail++;
}

unsigned char ble_fifo_pop(FIFOBuffer *fb)
{
	if ((fb->head == fb->end))
	{
		fb->head = fb->begin;
		return *(fb->end);
	}
	else
		return *(fb->head++);
}

void ble_fifo_flush(FIFOBuffer *fb)
{
	fb->head = fb->tail;
}

int ble_fifo_isfull_locked(const FIFOBuffer *_fb)
{
	return ble_fifo_isfull(_fb);
}

void ble_fifo_init(FIFOBuffer *fb, unsigned char *buf, size_t size)
{
	fb->head = fb->tail = fb->begin = buf;
	fb->end = buf + size - 1;
}

size_t ble_fifo_len(FIFOBuffer *fb)
{
	return fb->end - fb->begin;
}

size_t ble_fifo_idle_buf_len(FIFOBuffer *fb)
{
	if (fb->head > fb->tail)
		return (fb->head - fb->tail);
	else {
		return (fb->end - fb->tail) + (fb->head - fb->begin);
	}
}

#ifdef __cplusplus
}
#endif
