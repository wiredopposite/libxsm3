# libxsm3

A "library" for completing Xbox Security Method 3 challenges used by the Xbox 360 video game console to authenticate controllers.

## What this does

This library allows an XInput controller emulator to authenticate with retail consoles.

## TODO

- Make sure this is able to work on embedded platforms (e.g. Pi Pico).
- Document more of the values used in the identification packet.
- Unit tests and being able to verify packets from a controller to be valid.

## Uses

libxsm3 is used in the [Santroller](https://github.com/santroller/santroller) and [portal_of_flipper](https://github.com/sanjay900/portal_of_flipper) projects.

## Credits

- [oct0xor](https://github.com/oct0xor) for reversing, documenting and implementing much of the process. ([blog post](https://oct0xor.github.io/2017/05/03/xsm3/), [source code](https://github.com/oct0xor/xbox_security_method_3))
- [emoose](https://github.com/emoose) for reimplementing many of the XeCrypt functions in [ExCrypt](https://github.com/emoose/ExCrypt).
- [sanjay900](https://github.com/sanjay900) and an anonymous contributor for helping discover the retail keys.

## License 

libxsm3 is licensed under the GNU Lesser General Public License version 2.1, or (at your option) any later version.

This project uses [ExCrypt](https://github.com/emoose/ExCrypt), licensed under the [3-clause BSD license](https://github.com/emoose/ExCrypt/blob/b2e037c3102de22d1107d1e362df4ce407d964ac/LICENSE) - all files included are prefixed with "excrypt".

## Example

Being used in a handler for setup requests for the XSM3 interface descriptor

```c
#include "xsm3.h"

xsm3_handle_t xsm3; // XSM3 handle for state tracking/buffers, user allocated

void xinput_initialize(void) {
    xsm3_init(
        &xsm3, // Required: Pointer to xsm3 handle
        get_random_32, // Required: Random number generation function, 8 bit or higher
        printf, // Optional: Print function for internal logging, can be NULL
        idVendor, // Optional: USB VID, can be 0
        idProduct, // Optional: USB PID, can be 0
        NULL // Optional: Serial number array, can be NULL
    );
}

bool xinput_setup_request_handler(usb_setup_request* req, const uint8_t* req_payload) {
    switch (req->bmRequestType & (USB_REQ_TYPE_Msk | USB_REQ_RECIPIENT_Msk)) {
    case USB_REQ_TYPE_VENDOR | USB_REQ_RECIPIENT_INTERFACE:
        switch (req->bmRequestType & USB_REQ_DIR_Msk) {
        case USB_REQ_DIR_DEVTOHOST: // Device to host
            {
            uint8_t* response = NULL;
            uint16_t length = 0;
            if (xsm3_get_response(&xsm3, req->bmRequestType, req->bRequest, &response, &length)) {
                usb_send_control_response(response, length);
                return true; // Request handled
            }
            }
            break;
        case USB_REQ_DIR_HOSTTODEV: // Host to device
            if (xsm3_set_request(&xsm3, req->bmRequestType, req->bRequest, req_payload)) {
                return true; // Request handled
            }
            break;
        default:
            break;
        }
    }
    return false; // Stall or handle other requests
}
```