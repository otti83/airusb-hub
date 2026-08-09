/*
 * AirUSB Hub — the transcribed Windows USB constants, and nothing else.
 *
 * WHY THIS FILE IS PLAIN C WITH NO INCLUDES
 *
 * These numbers have to be usable from two places that cannot both exist in one
 * translation unit:
 *
 *   * `WindowsUsb.h`, which is C++20 with <cstdint> and is compiled on macOS
 *     and Linux so the mapping can be tested without Windows;
 *   * a KERNEL-MODE translation unit that includes <ntddk.h>, <usbdi.h> and
 *     <udecxusbdevice.h>, where the C++ standard library is not available.
 *
 * Anything with an #include in it fails one of those two. So the values live
 * here, as bare macros, and both sides derive from them. Duplicating them
 * instead would defeat the entire purpose — the point is that ONE set of
 * numbers is checked against Microsoft's headers.
 *
 * WHAT MAKES THEM TRUSTWORTHY
 *
 * Nothing, until a build with the WDK compiles `wdk_abi_check.c`, which
 * C_ASSERTs every one of them against the real macro. Until then they are a
 * careful transcription, which is a different thing from a verified constant,
 * and the plan says so out loud.
 */

#ifndef AIRUSB_PLATFORM_WINDOWS_WINDOWSUSBABI_H
#define AIRUSB_PLATFORM_WINDOWS_WINDOWSUSBABI_H

/* UDECX_USB_DEVICE_SPEED (udecxusbdevice.h) */
#define AIRUSB_UDECX_SPEED_LOW    0
#define AIRUSB_UDECX_SPEED_FULL   1
#define AIRUSB_UDECX_SPEED_HIGH   2
#define AIRUSB_UDECX_SPEED_SUPER  3

/* USBD_STATUS (usb.h). The top two bits are USBD_STATUS_TYPE:
 * 0x0 success, 0x4 pending, 0x8 error, 0xC error AND the endpoint is halted. */
#define AIRUSB_USBD_SUCCESS               0x00000000u
#define AIRUSB_USBD_PENDING               0x40000000u
#define AIRUSB_USBD_CRC                   0xC0000001u
#define AIRUSB_USBD_BTSTUFF               0xC0000002u
#define AIRUSB_USBD_DATA_TOGGLE_MISMATCH  0xC0000003u
#define AIRUSB_USBD_STALL_PID             0xC0000004u
#define AIRUSB_USBD_DEV_NOT_RESPONDING    0xC0000005u
#define AIRUSB_USBD_PID_CHECK_FAILURE     0xC0000006u
#define AIRUSB_USBD_UNEXPECTED_PID        0xC0000007u
#define AIRUSB_USBD_DATA_OVERRUN          0xC0000008u
#define AIRUSB_USBD_DATA_UNDERRUN         0xC0000009u
#define AIRUSB_USBD_BUFFER_OVERRUN        0xC000000Cu
#define AIRUSB_USBD_BUFFER_UNDERRUN       0xC000000Du
#define AIRUSB_USBD_NOT_ACCESSED          0xC000000Fu
#define AIRUSB_USBD_FIFO                  0xC0000010u
#define AIRUSB_USBD_ENDPOINT_HALTED       0xC0000030u
#define AIRUSB_USBD_NO_MEMORY             0x80000100u
#define AIRUSB_USBD_INVALID_URB_FUNCTION  0x80000200u
#define AIRUSB_USBD_INVALID_PARAMETER     0x80000300u
#define AIRUSB_USBD_ERROR_BUSY            0x80000400u
#define AIRUSB_USBD_REQUEST_FAILED        0x80000500u
#define AIRUSB_USBD_INVALID_PIPE_HANDLE   0x80000600u
#define AIRUSB_USBD_NO_BANDWIDTH          0x80000700u
#define AIRUSB_USBD_INTERNAL_HC_ERROR     0x80000800u
#define AIRUSB_USBD_ERROR_SHORT_TRANSFER  0x80000900u
#define AIRUSB_USBD_CANCELED              0xC0010000u
#define AIRUSB_USBD_TIMEOUT               0xC0006000u
#define AIRUSB_USBD_DEVICE_GONE           0xC0007000u

/* URB TransferFlags (usb.h) */
#define AIRUSB_USBD_SHORT_TRANSFER_OK      0x00000002u
#define AIRUSB_USBD_TRANSFER_DIRECTION_IN  0x00000001u

/* --- OUR OWN ABI, not Microsoft's --------------------------------------------
 *
 * These are NOT transcribed constants and `wdk_abi_check.c` cannot check them
 * against anything — there is nothing to check them against. They are the
 * driver/host contract, and the thing that keeps them honest is that the C++
 * side derives from the SAME macros: `UdecxIpc.h` static_asserts its own enum
 * values against them, so a change here that is not mirrored is a compile
 * error rather than a wire mismatch discovered on a kernel.
 */
#define AIRUSB_IPC_VERSION      1u

/* ipc::TransferType */
#define AIRUSB_XFER_CONTROL     0u
#define AIRUSB_XFER_BULK        1u
#define AIRUSB_XFER_INTERRUPT   2u

/* ipc::Direction */
#define AIRUSB_DIR_OUT          0u
#define AIRUSB_DIR_IN           1u

/* ipc::Flags — the guest's USBD_SHORT_TRANSFER_OK, carried abstractly so the
 * host never sees or forges a kernel constant. */
#define AIRUSB_FLAG_SHORT_OK    0x01u

#endif /* AIRUSB_PLATFORM_WINDOWS_WINDOWSUSBABI_H */
