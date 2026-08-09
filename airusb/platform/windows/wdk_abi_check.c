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
 * Build: scripts/wdk-abi-check.ps1 on a machine with the WDK. It finds the
 * kit, the KMDF version and the UdeCx version and invokes cl.exe; there is no
 * Visual Studio project, because a project would be one more thing that can be
 * configured wrongly between here and the answer.
 */

/* The include set, and the two places a first attempt gets it wrong.
 *
 * There is no km\usbdi.h — it is in shared\ — and shared\usb.h does NOT pull
 * it in. Leave it out and the 0x8-class statuses (REQUEST_FAILED, NO_MEMORY)
 * are simply absent, which shows up as a failed C_ASSERT and reads exactly like
 * a wrong constant. It is not: the values were right and the include was
 * missing. Compiling this file is what told the difference.
 *
 * UdeCx is versioned under km\ude\1.1\, not km\ directly. */
/* Order matters, and the errors it produces when wrong all point at the WDK's
 * own headers rather than at this file — which reads like a broken kit. This is
 * the order Microsoft's own UDE sample uses:
 *
 *   usb.h / usbdi.h / usbdlib.h BEFORE wdfusb.h  (it needs the USB types)
 *   wdfusb.h BEFORE UdeCx.h                      (it needs PWDF_USB_*)
 *
 * usbdi.h is in shared\, not km\, and shared\usb.h does NOT pull it in.
 * Leaving it out makes the 0x8-class statuses vanish and the C_ASSERTs fail as
 * though the constants were wrong. They were not.
 */
#include <ntddk.h>
#include <wdf.h>
#include <usb.h>
#include <usbdi.h>
#include <usbdlib.h>
#include <wdfusb.h>
#include <UdeCx.h>

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

/* --- USBD_STATUS ---------------------------------------------------------
 *
 * Compared as ULONG on purpose. USBD_STATUS is a LONG and every 0x8… and 0xC…
 * value is NEGATIVE in it, while ours are unsigned bit patterns — so a direct
 * comparison is a sign conversion the compiler warns about (C4308) and /WX
 * turns into a failure. The claim being made is "the same bits", so say that.
 */
C_ASSERT(AIRUSB_USBD_SUCCESS              == (ULONG)USBD_STATUS_SUCCESS);
C_ASSERT(AIRUSB_USBD_PENDING              == (ULONG)USBD_STATUS_PENDING);
C_ASSERT(AIRUSB_USBD_CRC                  == (ULONG)USBD_STATUS_CRC);
C_ASSERT(AIRUSB_USBD_BTSTUFF              == (ULONG)USBD_STATUS_BTSTUFF);
C_ASSERT(AIRUSB_USBD_DATA_TOGGLE_MISMATCH == (ULONG)USBD_STATUS_DATA_TOGGLE_MISMATCH);
C_ASSERT(AIRUSB_USBD_STALL_PID            == (ULONG)USBD_STATUS_STALL_PID);
C_ASSERT(AIRUSB_USBD_DEV_NOT_RESPONDING   == (ULONG)USBD_STATUS_DEV_NOT_RESPONDING);
C_ASSERT(AIRUSB_USBD_PID_CHECK_FAILURE    == (ULONG)USBD_STATUS_PID_CHECK_FAILURE);
C_ASSERT(AIRUSB_USBD_UNEXPECTED_PID       == (ULONG)USBD_STATUS_UNEXPECTED_PID);
C_ASSERT(AIRUSB_USBD_DATA_OVERRUN         == (ULONG)USBD_STATUS_DATA_OVERRUN);
C_ASSERT(AIRUSB_USBD_DATA_UNDERRUN        == (ULONG)USBD_STATUS_DATA_UNDERRUN);
C_ASSERT(AIRUSB_USBD_BUFFER_OVERRUN       == (ULONG)USBD_STATUS_BUFFER_OVERRUN);
C_ASSERT(AIRUSB_USBD_BUFFER_UNDERRUN      == (ULONG)USBD_STATUS_BUFFER_UNDERRUN);
C_ASSERT(AIRUSB_USBD_NOT_ACCESSED         == (ULONG)USBD_STATUS_NOT_ACCESSED);
C_ASSERT(AIRUSB_USBD_FIFO                 == (ULONG)USBD_STATUS_FIFO);
C_ASSERT(AIRUSB_USBD_ENDPOINT_HALTED      == (ULONG)USBD_STATUS_ENDPOINT_HALTED);
C_ASSERT(AIRUSB_USBD_NO_MEMORY            == (ULONG)USBD_STATUS_NO_MEMORY);
C_ASSERT(AIRUSB_USBD_INVALID_URB_FUNCTION == (ULONG)USBD_STATUS_INVALID_URB_FUNCTION);
C_ASSERT(AIRUSB_USBD_INVALID_PARAMETER    == (ULONG)USBD_STATUS_INVALID_PARAMETER);
C_ASSERT(AIRUSB_USBD_ERROR_BUSY           == (ULONG)USBD_STATUS_ERROR_BUSY);
C_ASSERT(AIRUSB_USBD_REQUEST_FAILED       == (ULONG)USBD_STATUS_REQUEST_FAILED);
C_ASSERT(AIRUSB_USBD_INVALID_PIPE_HANDLE  == (ULONG)USBD_STATUS_INVALID_PIPE_HANDLE);
C_ASSERT(AIRUSB_USBD_NO_BANDWIDTH         == (ULONG)USBD_STATUS_NO_BANDWIDTH);
C_ASSERT(AIRUSB_USBD_INTERNAL_HC_ERROR    == (ULONG)USBD_STATUS_INTERNAL_HC_ERROR);
C_ASSERT(AIRUSB_USBD_ERROR_SHORT_TRANSFER == (ULONG)USBD_STATUS_ERROR_SHORT_TRANSFER);
C_ASSERT(AIRUSB_USBD_CANCELED             == (ULONG)USBD_STATUS_CANCELED);
C_ASSERT(AIRUSB_USBD_TIMEOUT              == (ULONG)USBD_STATUS_TIMEOUT);
C_ASSERT(AIRUSB_USBD_DEVICE_GONE          == (ULONG)USBD_STATUS_DEVICE_GONE);

/* --- TransferFlags ------------------------------------------------------- */
C_ASSERT(AIRUSB_USBD_SHORT_TRANSFER_OK     == (ULONG)USBD_SHORT_TRANSFER_OK);
C_ASSERT(AIRUSB_USBD_TRANSFER_DIRECTION_IN == (ULONG)USBD_TRANSFER_DIRECTION_IN);

/* --- the two predicates, checked against Microsoft's own -----------------
 *
 * `isError` was written as a top-TWO-bits test first, which made
 * ERROR_SHORT_TRANSFER look like a warning. USBD_ERROR is a signed-negative
 * test, so 0x8 and 0xC are both failures.
 *
 * The halt distinction is real but has NO macro to check it against:
 * USBD_STATUS_HALTED (0xC0000000) exists, USBD_STATUS_TYPE does not — searched
 * across the whole kit, not assumed. So the mask is written out here and
 * asserted against the one constant Microsoft does define, which is as close to
 * checked as this can get.
 */
C_ASSERT(USBD_ERROR(AIRUSB_USBD_ERROR_SHORT_TRANSFER));
C_ASSERT(USBD_ERROR(AIRUSB_USBD_STALL_PID));
C_ASSERT(!USBD_ERROR(AIRUSB_USBD_SUCCESS));
C_ASSERT((AIRUSB_USBD_ERROR_SHORT_TRANSFER & 0xC0000000u) != (ULONG)USBD_STATUS_HALTED);
C_ASSERT((AIRUSB_USBD_STALL_PID            & 0xC0000000u) == (ULONG)USBD_STATUS_HALTED);
C_ASSERT((AIRUSB_USBD_DEVICE_GONE          & 0xC0000000u) == (ULONG)USBD_STATUS_HALTED);
C_ASSERT((AIRUSB_USBD_CANCELED             & 0xC0000000u) == (ULONG)USBD_STATUS_HALTED);

/* Nothing to link. The file exists to be compiled. */
