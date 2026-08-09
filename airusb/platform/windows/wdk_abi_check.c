/*
 * AirUSB Hub — the only place the transcribed Windows constants are checked.
 *
 * `WindowsUsbAbi.h` holds a set of numbers copied out of Microsoft's headers by
 * hand. Everything above it — the speed table, the status table, their tests on
 * three platforms — proves the MAPPING is total and consistent. None of it can
 * prove that 0xC0000004 is really USBD_STATUS_STALL_PID, because on a Mac there
 * is nothing to compare against.
 *
 * This translation unit is that comparison. It includes the real WDK headers
 * and C_ASSERTs every value. It produces no code and is never linked into
 * anything; compiling it IS the test, and it can only be compiled on a machine
 * with the WDK.
 *
 * A constant that only ever exists in our own header is a constant nobody has
 * checked. Until this file has been compiled at least once, treat the tables as
 * a careful guess.
 *
 * Build (Developer Command Prompt, WDK installed):
 *   cl /nologo /c /W4 /WX ^
 *      /I"%WindowsSdkDir%Include\%WindowsSDKVersion%km" ^
 *      /I"%WindowsSdkDir%Include\%WindowsSDKVersion%shared" ^
 *      platform\windows\wdk_abi_check.c
 */

#include <ntddk.h>
#include <wdf.h>
#include <usb.h>
#include <usbdi.h>
#include <udecx.h>

#include "WindowsUsbAbi.h"

/* --- UDECX_USB_DEVICE_SPEED ---------------------------------------------
 *
 * The one this project expects to be wrong if anything is. A cast from
 * airusb::Speed sends High as SuperSpeed here, and the guest would build its
 * endpoint table for a link the device is not on.
 */
C_ASSERT(AIRUSB_UDECX_SPEED_LOW   == UdecxUsbLowSpeed);
C_ASSERT(AIRUSB_UDECX_SPEED_FULL  == UdecxUsbFullSpeed);
C_ASSERT(AIRUSB_UDECX_SPEED_HIGH  == UdecxUsbHighSpeed);
C_ASSERT(AIRUSB_UDECX_SPEED_SUPER == UdecxUsbSuperSpeed);

/* --- USBD_STATUS --------------------------------------------------------- */
C_ASSERT(AIRUSB_USBD_SUCCESS              == USBD_STATUS_SUCCESS);
C_ASSERT(AIRUSB_USBD_PENDING              == USBD_STATUS_PENDING);
C_ASSERT(AIRUSB_USBD_CRC                  == USBD_STATUS_CRC);
C_ASSERT(AIRUSB_USBD_BTSTUFF              == USBD_STATUS_BTSTUFF);
C_ASSERT(AIRUSB_USBD_DATA_TOGGLE_MISMATCH == USBD_STATUS_DATA_TOGGLE_MISMATCH);
C_ASSERT(AIRUSB_USBD_STALL_PID            == USBD_STATUS_STALL_PID);
C_ASSERT(AIRUSB_USBD_DEV_NOT_RESPONDING   == USBD_STATUS_DEV_NOT_RESPONDING);
C_ASSERT(AIRUSB_USBD_PID_CHECK_FAILURE    == USBD_STATUS_PID_CHECK_FAILURE);
C_ASSERT(AIRUSB_USBD_UNEXPECTED_PID       == USBD_STATUS_UNEXPECTED_PID);
C_ASSERT(AIRUSB_USBD_DATA_OVERRUN         == USBD_STATUS_DATA_OVERRUN);
C_ASSERT(AIRUSB_USBD_DATA_UNDERRUN        == USBD_STATUS_DATA_UNDERRUN);
C_ASSERT(AIRUSB_USBD_BUFFER_OVERRUN       == USBD_STATUS_BUFFER_OVERRUN);
C_ASSERT(AIRUSB_USBD_BUFFER_UNDERRUN      == USBD_STATUS_BUFFER_UNDERRUN);
C_ASSERT(AIRUSB_USBD_NOT_ACCESSED         == USBD_STATUS_NOT_ACCESSED);
C_ASSERT(AIRUSB_USBD_FIFO                 == USBD_STATUS_FIFO);
C_ASSERT(AIRUSB_USBD_ENDPOINT_HALTED      == USBD_STATUS_ENDPOINT_HALTED);
C_ASSERT(AIRUSB_USBD_NO_MEMORY            == USBD_STATUS_NO_MEMORY);
C_ASSERT(AIRUSB_USBD_INVALID_URB_FUNCTION == USBD_STATUS_INVALID_URB_FUNCTION);
C_ASSERT(AIRUSB_USBD_INVALID_PARAMETER    == USBD_STATUS_INVALID_PARAMETER);
C_ASSERT(AIRUSB_USBD_ERROR_BUSY           == USBD_STATUS_ERROR_BUSY);
C_ASSERT(AIRUSB_USBD_REQUEST_FAILED       == USBD_STATUS_REQUEST_FAILED);
C_ASSERT(AIRUSB_USBD_INVALID_PIPE_HANDLE  == USBD_STATUS_INVALID_PIPE_HANDLE);
C_ASSERT(AIRUSB_USBD_NO_BANDWIDTH         == USBD_STATUS_NO_BANDWIDTH);
C_ASSERT(AIRUSB_USBD_INTERNAL_HC_ERROR    == USBD_STATUS_INTERNAL_HC_ERROR);
C_ASSERT(AIRUSB_USBD_ERROR_SHORT_TRANSFER == USBD_STATUS_ERROR_SHORT_TRANSFER);
C_ASSERT(AIRUSB_USBD_CANCELED             == USBD_STATUS_CANCELED);
C_ASSERT(AIRUSB_USBD_TIMEOUT              == USBD_STATUS_TIMEOUT);
C_ASSERT(AIRUSB_USBD_DEVICE_GONE          == USBD_STATUS_DEVICE_GONE);

/* --- TransferFlags ------------------------------------------------------- */
C_ASSERT(AIRUSB_USBD_SHORT_TRANSFER_OK     == USBD_SHORT_TRANSFER_OK);
C_ASSERT(AIRUSB_USBD_TRANSFER_DIRECTION_IN == USBD_TRANSFER_DIRECTION_IN);

/* --- the two predicates, checked against Microsoft's own macros -----------
 *
 * `isError` was written as a top-TWO-bits test first, which made
 * ERROR_SHORT_TRANSFER look like a warning. USBD_ERROR is a signed-negative
 * test, so 0x8 and 0xC are both failures and the difference between them is
 * whether the endpoint halted. Assert both readings here so the header cannot
 * drift back.
 */
C_ASSERT(USBD_ERROR(AIRUSB_USBD_ERROR_SHORT_TRANSFER));
C_ASSERT(USBD_ERROR(AIRUSB_USBD_STALL_PID));
C_ASSERT(!USBD_ERROR(AIRUSB_USBD_SUCCESS));
C_ASSERT(USBD_STATUS_TYPE(AIRUSB_USBD_ERROR_SHORT_TRANSFER) != USBD_STATUS_HALTED);
C_ASSERT(USBD_STATUS_TYPE(AIRUSB_USBD_STALL_PID)            == USBD_STATUS_HALTED);
C_ASSERT(USBD_STATUS_TYPE(AIRUSB_USBD_DEVICE_GONE)          == USBD_STATUS_HALTED);

/* Nothing to link. The file exists to be compiled. */
