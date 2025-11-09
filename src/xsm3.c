/*
    xsm3.c - part of libxsm3
    Copyright (C) 2022-2023 InvoxiPlayGames
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

#include <string.h>
#include "xsm3.h"
#include "excrypt.h"
#include "usbdsec.h"

#define XSM3_LOG(handle, ...) \
    do { \
        if ((handle != NULL) && (handle->printf_cb != NULL)) { \
            handle->printf_cb(__VA_ARGS__); \
        } \
    } while (0)

static const uint8_t XSM3_DEFAULT_ID_DATA[0x1D] = {
    0x49, 0x4B, 0x00, 0x00, 0x17, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x00, 0x00, 0x80, 0x02, 0x5E, 0x04, 0x8E, 0x02,
    0x03, 0x00, 0x01, 0x01, 0x16
};

// static global keys from the keyvault (shared across every retail system)
static const uint8_t XSM3_KEY_0x1D[0x10] = {
    0xE3, 0x5B, 0xFB, 0x1C, 0xCD, 0xAD, 0x32, 0x5B,
	0xF7, 0x0E, 0x07, 0xFD, 0x62, 0x3D, 0xA7, 0xC4
};
static const uint8_t XSM3_KEY_0x1E[0x10] = {
	0x8F, 0x29, 0x08, 0x38, 0x0B, 0x5B, 0xFE, 0x68,
	0x7C, 0x26, 0x46, 0x2A, 0x51, 0xF2, 0xBC, 0x19
};

// retail keys for generating 0x23/0x24 keys from console ID
static const uint8_t XSM3_ROOT_KEY_0x23[0x10] = {
    0x82, 0x80, 0x78, 0x68, 0x3A, 0x52, 0x3A, 0x98,
    0x10, 0xF4, 0x0C, 0x12, 0x70, 0x66, 0xDC, 0xBA
};
static const uint8_t XSM3_ROOT_KEY_0x24[0x10] = {
	0x66, 0x62, 0x1A, 0x78, 0xF8, 0x60, 0x9C, 0x8A,
    0x26, 0x9A, 0x04, 0xAE, 0xD8, 0x5C, 0x1E, 0xC8
};

static const uint8_t XINPUT_DESC_STR_AUTH[] = {
    0xB2, 0x03, 0x58, 0x00, 0x62, 0x00, 0x6F, 0x00, 0x78, 0x00, 0x20, 0x00,
    0x53, 0x00, 0x65, 0x00, 0x63, 0x00, 0x75, 0x00, 0x72, 0x00, 0x69, 0x00,
    0x74, 0x00, 0x79, 0x00, 0x20, 0x00, 0x4D, 0x00, 0x65, 0x00, 0x74, 0x00,
    0x68, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x20, 0x00, 0x33, 0x00, 0x2C, 0x00,
    0x20, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00,
    0x6F, 0x00, 0x6E, 0x00, 0x20, 0x00, 0x31, 0x00, 0x2E, 0x00, 0x30, 0x00,
    0x30, 0x00, 0x2C, 0x00, 0x20, 0x00, 0xA9, 0x00, 0x20, 0x00, 0x32, 0x00,
    0x30, 0x00, 0x30, 0x00, 0x35, 0x00, 0x20, 0x00, 0x4D, 0x00, 0x69, 0x00,
    0x63, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x66, 0x00,
    0x74, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x70, 0x00,
    0x6F, 0x00, 0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00,
    0x6E, 0x00, 0x2E, 0x00, 0x20, 0x00, 0x41, 0x00, 0x6C, 0x00, 0x6C, 0x00,
    0x20, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67, 0x00, 0x68, 0x00, 0x74, 0x00,
    0x73, 0x00, 0x20, 0x00, 0x72, 0x00, 0x65, 0x00, 0x73, 0x00, 0x65, 0x00,
    0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x64, 0x00, 0x2E, 0x00
};

/*
global device keys from devkit keyvaults
static const uint8_t xsm3_key_0x1D[0x10] = {
    0xC2, 0x15, 0xE5, 0x5E, 0xE5, 0x51, 0x94, 0x2A,
    0xEC, 0x3D, 0x45, 0xEC, 0xB6, 0xE6, 0xF2, 0x16
};
static const uint8_t xsm3_key_0x1E[0x10] = {
    0xC7, 0x45, 0xAD, 0x1F, 0x08, 0x0B, 0xD9, 0xE9,
    0x9B, 0x1C, 0x34, 0xE3, 0xA4, 0x6D, 0xC8, 0xC4
};
*/

// devkit recovery keys for generating 0x23/0x24 keys from console ID
// static const uint8_t xsm3_root_key_0x23[0x10] = {
//     0xB9, 0xE0, 0x9E, 0x68, 0x04, 0x83, 0x91, 0xB3,
//     0x32, 0x45, 0x7A, 0xDA, 0x43, 0x6B, 0x80, 0xAD
// };
// static const uint8_t xsm3_root_key_0x24[0x10] = {
// 	0x92, 0x5D, 0x29, 0x6E, 0xB0, 0x61, 0x0B, 0xF1,
//     0xD6, 0x29, 0x3B, 0xC8, 0xC7, 0xD9, 0x32, 0xBC
// };

static uint8_t xsm3_calculate_checksum(const uint8_t * packet) {
    // packet length in header doesn't include the header itself
    uint8_t packet_length = packet[0x4] + 0x5;
    uint8_t checksum = 0x00;
    int i = 0;
    // checksum is just a XOR over all packet bytes
	for(i = 0x5; i < packet_length; i++) {
		checksum ^= packet[i];
    }
    // last byte of the packet is the checksum
	return checksum;
}

static bool xsm3_verify_checksum(const uint8_t * packet) {
    // packet length in header doesn't include the header itself
    uint8_t packet_length = packet[0x4] + 0x5;
    // last byte of the packet is the checksum
	return (xsm3_calculate_checksum(packet) == packet[packet_length]);
}

bool xsm3_set_identification_data(xsm3_handle_t* hxsm3) {
    const uint8_t* id_data = hxsm3->ctrl_id_data;
    // validate the checksum
    if (!xsm3_verify_checksum(id_data)) {
        XSM3_LOG(hxsm3, " Error: Checksum failed when setting identification data!\n");
        return false;
    }
    // skip over the packet header
    id_data += 0x5;

    // prepare the xsm3_identification_data buffer

    // contains serial number (len: 0xC), unknown (len: 0x2) and the "category node" to use (len: 0x1)
    memcpy(hxsm3->id_data, id_data, 0xF);
    // vendor ID
    memcpy(hxsm3->id_data + 0x10, id_data + 0xF, sizeof(unsigned short));
    // product ID
    memcpy(hxsm3->id_data + 0x12, id_data + 0x11, sizeof(unsigned short));
    // unknown
    memcpy(hxsm3->id_data + 0x14, id_data + 0x13, sizeof(unsigned char));
    // unknown
    memcpy(hxsm3->id_data + 0x15, id_data + 0x16, sizeof(unsigned char));
    // unknown
    memcpy(hxsm3->id_data + 0x16, id_data + 0x14, sizeof(unsigned short));

    XSM3_LOG(hxsm3, " Identification data set successfully\n");
    return true;
}

void xsm3_import_kv_keys(xsm3_handle_t* hxsm3, const uint8_t key1[0x10], const uint8_t key2[0x10]) {
    hxsm3->has_kv_keys = true;
    // copy the provided keys into our buffers
    memcpy(hxsm3->kv_2des_key1, key1, sizeof(hxsm3->kv_2des_key1));
    memcpy(hxsm3->kv_2des_key2, key2, sizeof(hxsm3->kv_2des_key2));
}

void xsm3_generate_kv_keys(xsm3_handle_t* hxsm3, const uint8_t console_id[0x8]) {
    hxsm3->has_kv_keys = true;
    // make a sha-1 hash of the console id
    uint8_t console_id_hash[0x14];
    ExCryptSha(console_id, 0x8, NULL, 0, NULL, 0, console_id_hash, 0x14);
    // encrypt it with the root keys for 1st party controllers
    UsbdSecXSM3AuthenticationCrypt(XSM3_ROOT_KEY_0x23, console_id_hash, 0x10, hxsm3->kv_2des_key1, 1);
    UsbdSecXSM3AuthenticationCrypt(XSM3_ROOT_KEY_0x24, console_id_hash + 0x4, 0x10, hxsm3->kv_2des_key2, 1);
}

bool xsm3_do_challenge_init(xsm3_handle_t* hxsm3, const uint8_t challenge_packet[0x22]) {
    uint8_t incoming_packet_mac[0x8];
    uint8_t response_packet_mac[0x8];
    int i = 0;

    XSM3_LOG(hxsm3, " Starting challenge init\n");
    // validate the checksum
    if (!xsm3_verify_checksum(challenge_packet)) {
        XSM3_LOG(hxsm3, " Error: Checksum failed when validating challenge init!\n");
        return false;
    }

    // decrypt the packet content using the static key from the keyvault
    UsbdSecXSM3AuthenticationCrypt(XSM3_KEY_0x1D, challenge_packet + 0x5, 0x18, hxsm3->decrypt_buffer, 0);
    // first 0x10 bytes are random data
    memcpy(hxsm3->rnd_console_data, hxsm3->decrypt_buffer, 0x10);
    // next 0x8 bytes are from the console certificate
    memcpy(hxsm3->console_id, hxsm3->decrypt_buffer + 0x10, 0x8);
    // last 4 bytes of the packet are the last 4 bytes of the MAC
    UsbdSecXSM3AuthenticationMac(XSM3_KEY_0x1E, NULL, challenge_packet + 5, 0x18, incoming_packet_mac);
    // validate the MAC
    if (memcmp(incoming_packet_mac + 4, challenge_packet + 0x5 + 0x18, 0x4) != 0) {
        XSM3_LOG(hxsm3, " Error: MAC failed when validating challenge init!\n");
        return false;
    }

    XSM3_LOG(hxsm3, " Generating KVs...\n");
    // if we haven't got our KV keys yet, generate it
    if (!hxsm3->has_kv_keys) xsm3_generate_kv_keys(hxsm3, hxsm3->console_id);

    // the random value is swapped at an 8 byte boundary
    memcpy(hxsm3->rnd_console_data_swap, hxsm3->rnd_console_data + 0x8, 0x8);
    memcpy(hxsm3->rnd_console_data_swap + 0x8, hxsm3->rnd_console_data, 0x8);
    // and then encrypted - the regular value encrypted with key 1, the swapped value encrypted with key 2
    XSM3_LOG(hxsm3, " Encrypting random console data...\n");
    UsbdSecXSM3AuthenticationCrypt(hxsm3->kv_2des_key1, hxsm3->rnd_console_data, 0x10, hxsm3->rnd_console_data_enc, 1);
    UsbdSecXSM3AuthenticationCrypt(hxsm3->kv_2des_key2, hxsm3->rnd_console_data_swap, 0x10, hxsm3->rnd_console_data_swap_enc, 1);

    // generate random data
    XSM3_LOG(hxsm3, " Generating random controller data...\n");
    // srand(time(NULL));
    for (i = 0; i < 0x10; i++) {
        hxsm3->rnd_controller_data[i] = hxsm3->get_rand_cb() & 0xFF;
    }

    // clear response buffers
    memset(hxsm3->challenge_response, 0, sizeof(hxsm3->challenge_response));
    memset(hxsm3->decrypt_buffer, 0, sizeof(hxsm3->decrypt_buffer));
    // set header and packet length of challenge response
    hxsm3->challenge_response[0] = 0x49; // packet magic
    hxsm3->challenge_response[1] = 0x4C;
    hxsm3->challenge_response[4] = 0x28; // packet length
    // copy random controller, random console data to the encryption buffer
    memcpy(hxsm3->decrypt_buffer, hxsm3->rnd_controller_data, 0x10);
    memcpy(hxsm3->decrypt_buffer + 0x10, hxsm3->rnd_console_data, 0x10);
    // save the sha1 hash of the decrypted contents for later
    XSM3_LOG(hxsm3, " Calculating challenge init hash...\n");
    ExCryptSha(hxsm3->decrypt_buffer, 0x20, NULL, 0, NULL, 0, hxsm3->challenge_init_hash, 0x14);

    // encrypt challenge response packet using the encrypted random key
    XSM3_LOG(hxsm3, " Encrypting challenge response...\n");
    UsbdSecXSM3AuthenticationCrypt(hxsm3->rnd_console_data_enc, hxsm3->decrypt_buffer, 0x20, hxsm3->challenge_response + 0x5, 1);
    // calculate MAC using the encrypted swapped random key and use it to calculate ACR
    XSM3_LOG(hxsm3, " Calculating MAC for challenge response...\n");
    UsbdSecXSM3AuthenticationMac(hxsm3->rnd_console_data_swap_enc, NULL, hxsm3->challenge_response + 0x5, 0x20, response_packet_mac);
    // calculate ACR and append to the end of the xsm3_challenge_response
    XSM3_LOG(hxsm3, " Calculating ACR for challenge response...\n");
    UsbdSecXSMAuthenticationAcr(hxsm3->console_id, hxsm3->id_data, response_packet_mac, hxsm3->challenge_response + 0x5 + 0x20);
    // calculate the checksum for the response packet
    XSM3_LOG(hxsm3, " Calculating checksum for challenge response...\n");
    hxsm3->challenge_response[0x5 + 0x28] = xsm3_calculate_checksum(hxsm3->challenge_response);

    // the console random value changes slightly after this point
    XSM3_LOG(hxsm3, " Modifying console random data post-challenge init...\n");
    memcpy(hxsm3->rnd_console_data, hxsm3->rnd_controller_data + 0xC, 0x4);
    memcpy(hxsm3->rnd_console_data + 0x4, hxsm3->rnd_console_data + 0xC, 0x4);

    XSM3_LOG(hxsm3, " Challenge init complete\n");
    return true;
}

bool xsm3_do_challenge_verify(xsm3_handle_t* hxsm3, const uint8_t challenge_packet[0x16]) {
    uint8_t incoming_packet_mac[0x8];

    XSM3_LOG(hxsm3, " Starting challenge verify\n");
    // validate the checksum
    if (!xsm3_verify_checksum(challenge_packet)) {
        XSM3_LOG(hxsm3, " Error: Checksum failed when validating challenge verify!\n");
        return false;
    }

    XSM3_LOG(hxsm3, " Decrypting challenge verify...\n");
    // decrypt the packet using the controller generated random value
    UsbdSecXSM3AuthenticationCrypt(hxsm3->rnd_controller_data, challenge_packet + 0x5, 0x8, hxsm3->decrypt_buffer, 0);
    // replace part of our random encryption value with the decrypted buffer
    memcpy(hxsm3->rnd_console_data + 0x8, hxsm3->decrypt_buffer, 0x8);

    XSM3_LOG(hxsm3, " Calculating MAC for challenge verify...\n");
    // calculate the MAC of the incoming packet
    UsbdSecXSM3AuthenticationMac(hxsm3->challenge_init_hash, hxsm3->rnd_console_data, challenge_packet + 0x5, 0x8, incoming_packet_mac);
    // validate the MAC
    if (memcmp(incoming_packet_mac, challenge_packet + 0x5 + 0x8, 0x8) != 0) {
        XSM3_LOG(hxsm3, " Error: MAC failed when validating challenge verify!\n");
        return false;
    }

    XSM3_LOG(hxsm3, " Clearing challenge verify response buffers...\n");
    // clear response buffers
    memset(hxsm3->challenge_response, 0, sizeof(hxsm3->challenge_response));
    memset(hxsm3->decrypt_buffer, 0, sizeof(hxsm3->decrypt_buffer));
    // set header and packet length of challenge response
    hxsm3->challenge_response[0] = 0x49; // packet magic
    hxsm3->challenge_response[1] = 0x4C;
    hxsm3->challenge_response[4] = 0x10; // packet length
    // calculate the ACR value and encrypt it into the outgoing packet using the encrypted random
    XSM3_LOG(hxsm3, " Calculating ACR for challenge verify response...\n");
    UsbdSecXSMAuthenticationAcr(hxsm3->console_id, hxsm3->id_data, hxsm3->rnd_console_data + 0x8, hxsm3->decrypt_buffer);
    XSM3_LOG(hxsm3, " Encrypting challenge verify response...\n");
    UsbdSecXSM3AuthenticationCrypt(hxsm3->rnd_console_data_enc, hxsm3->decrypt_buffer, 0x8, hxsm3->challenge_response + 0x5, 1);
    // calculate the MAC of the encrypted packet and append it to the end
    XSM3_LOG(hxsm3, " Calculating MAC for challenge verify response...\n");
    UsbdSecXSM3AuthenticationMac(hxsm3->rnd_console_data_swap_enc, hxsm3->rnd_console_data, hxsm3->challenge_response + 0x5, 0x8, hxsm3->challenge_response + 0x5 + 0x8);
    // calculate the checksum for the response packet
    XSM3_LOG(hxsm3, " Calculating checksum for challenge verify response...\n");
    hxsm3->challenge_response[0x5 + 0x10] = xsm3_calculate_checksum(hxsm3->challenge_response);

    XSM3_LOG(hxsm3, " Challenge verify complete\n");
    return true;
}

bool xsm3_init(xsm3_handle_t* hxsm3, const xsm3_init_cfg_t* init_cfg) {
    if (hxsm3 == NULL || init_cfg == NULL) {
        return false;
    }
    XSM3_LOG(hxsm3, "xsm3_init: Initializing XSM3 handler\n");
    memset(hxsm3, 0, sizeof(xsm3_handle_t));
    if (init_cfg->get_rand32_cb == NULL) {
        XSM3_LOG(hxsm3, " Error: Invalid config parameters, no RNG method provided.\n");
        return false;
    }

    hxsm3->get_rand_cb = init_cfg->get_rand32_cb;
    hxsm3->printf_cb = init_cfg->printf_cb;
    memcpy(hxsm3->ctrl_id_data, XSM3_DEFAULT_ID_DATA, sizeof(XSM3_DEFAULT_ID_DATA));

    if (init_cfg->serial != NULL) {
        memcpy(hxsm3->ctrl_id_data + 6, init_cfg->serial, 20);
    }
    hxsm3->ctrl_id_data[6] = hxsm3->get_rand_cb() & 0xFF;
    uint8_t* id_data = hxsm3->ctrl_id_data + 5; // Skip header
    if (init_cfg->vid != 0) {
        memcpy(id_data + 15, &init_cfg->vid, sizeof(uint16_t));
    }
    if (init_cfg->pid != 0) {
        memcpy(id_data + 17, &init_cfg->pid, sizeof(uint16_t));
    }

    XSM3_LOG(hxsm3, " Calculating checksum for id data\n");
    hxsm3->ctrl_id_data[0x1C] = xsm3_calculate_checksum(hxsm3->ctrl_id_data);
    
    XSM3_LOG(hxsm3, " Setting identification data\n");
    if (!xsm3_set_identification_data(hxsm3)) {
        return false;
    }

    hxsm3->state = 0x0001;
    XSM3_LOG(hxsm3, " XSM3 handler initialized successfully\n");
    return true;
}

const uint8_t* xsm3_get_response(xsm3_handle_t* hxsm3, uint8_t bmRequestType, uint8_t bRequest, uint16_t* resp_len) {
    if ((bmRequestType != 0xC1) || (hxsm3 == NULL) || (resp_len == NULL) || (!hxsm3->state)) {
        XSM3_LOG(hxsm3, " Error: Invalid parameters\n");
        return NULL;
    }
    uint8_t* resp = NULL;
    switch (bRequest) {
    case 0x81:
        XSM3_LOG(hxsm3, " Providing identification data\n");
        resp = hxsm3->ctrl_id_data;
        *resp_len = sizeof(hxsm3->ctrl_id_data);
        break;
    case 0x83:
        XSM3_LOG(hxsm3, " Providing challenge response\n");
        resp = hxsm3->challenge_response;
        *resp_len = sizeof(hxsm3->challenge_response);
        break;
    case 0x86:
        XSM3_LOG(hxsm3, " Providing auth state response\n");
        hxsm3->state = 2;
        resp = (uint8_t*)&hxsm3->state;
        *resp_len = sizeof(hxsm3->state);
        break;
    default:
        XSM3_LOG(hxsm3, " Error: Unknown bRequest 0x%02X\n", bRequest);
        return NULL;
    }
    return resp;
}

bool xsm3_set_request(xsm3_handle_t* hxsm3, uint8_t bmRequestType, uint8_t bRequest, const uint8_t* req_data) {
    XSM3_LOG(hxsm3, "xsm3_set_request: Received request\n");
    if ((bmRequestType != 0x41) || (hxsm3 == NULL) || (!hxsm3->state)) {
        XSM3_LOG(hxsm3, " Error: Invalid parameters\n");
        return false;
    }
    switch (bRequest) {
    case 0x81:
        return true;
    case 0x82:
        if (req_data == NULL) {
            XSM3_LOG(hxsm3, " Error: Invalid request data for challenge init\n");
            return false;
        }
        XSM3_LOG(hxsm3, " Processing challenge init request...\n");
        return xsm3_do_challenge_init(hxsm3, req_data);
    case 0x87:
        if (req_data == NULL) {
            XSM3_LOG(hxsm3, " Error: Invalid request data for challenge verify\n");
            return false;
        }
        XSM3_LOG(hxsm3, " Processing challenge verify request...\n");
        return xsm3_do_challenge_verify(hxsm3, req_data);
    case 0x84:
    case 0x83:
        return true;
    default:
        XSM3_LOG(hxsm3, " Error: Unknown bRequest 0x%02X\n", bRequest);
        return false;
    }
}

const uint8_t* xsm3_get_xsm3_desc_string(uint16_t* desc_len) {
    *desc_len = sizeof(XINPUT_DESC_STR_AUTH);
    return XINPUT_DESC_STR_AUTH;
}