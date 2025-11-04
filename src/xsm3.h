/*
    xsm3.h - part of libxsm3
    Copyright (C) 2022 InvoxiPlayGames
    Modifications Copyright (C) 2025 WiredOpposite.com

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef XSM3_H_
#define XSM3_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t(*xsm3_get_rand_cb_t)(void);
typedef int(*xsm3_printf_cb_t)(const char* fmt, ...);

typedef struct _xsm3_handle_t {
    uint8_t ctrl_id_data[0x1D];
    uint8_t challenge_response[0x30];
    uint8_t console_id[0x8];
    uint8_t kv_2des_key1[0x10];
    uint8_t kv_2des_key2[0x10];
    bool has_kv_keys;
    uint8_t decrypt_buffer[0x30];
    uint8_t id_data[0x20];
    uint8_t rnd_console_data[0x10];
    uint8_t rnd_console_data_enc[0x10];
    uint8_t rnd_console_data_swap[0x10];
    uint8_t rnd_console_data_swap_enc[0x10];
    uint8_t rnd_controller_data[0x10];
    uint8_t challenge_init_hash[0x14];
    uint16_t state;
    xsm3_get_rand_cb_t get_rand_cb;
    xsm3_printf_cb_t printf_cb;
} xsm3_handle_t;

bool xsm3_init(xsm3_handle_t* hxsm3, xsm3_get_rand_cb_t get_rand_cb, xsm3_printf_cb_t printf_cb, uint16_t vid, uint16_t pid, const uint8_t serial[20]);
bool xsm3_get_response(xsm3_handle_t* hxsm3, uint8_t bmRequestType, uint8_t bRequest, uint8_t** resp, uint16_t* resp_len);
bool xsm3_set_request(xsm3_handle_t* hxsm3, uint8_t bmRequestType, uint8_t bRequest, const uint8_t* req_data);

#ifdef __cplusplus
}
#endif

#endif // XSM3_H_