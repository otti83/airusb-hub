/*
 * airusb.sys — the AirUSB virtual USB host, as a KMDF/UdeCx client driver.
 *
 * WHAT THIS DRIVER IS FOR, IN ONE SENTENCE
 *
 * It makes Windows enumerate a device that is plugged into a different machine,
 * by presenting a virtual USB device to the USB Device Emulation class
 * extension and forwarding every transfer to an unprivileged user-mode process
 * that owns the network.
 *
 * THE RULE THE WHOLE FILE IS ORGANISED AROUND
 *
 * **No UdeCx callback may ever wait on user mode.** Not for a transfer, not for
 * a configure, and above all not for a purge. The user-mode half is across an
 * IOCTL boundary from a process that can be slow, killed, or hostile; a
 * callback that blocks on it hands an unprivileged process the ability to wedge
 * the USB stack, and purge in particular is what a driver unload waits on.
 *
 * So: everything is answered from kernel state immediately, and the network is
 * something that later CHANGES that state. That is the same discipline
 * `VhciNetBridge` follows on Linux, for the same reason, and it is why the
 * user-mode `UdecxBridge` already exists and is already tested — this driver is
 * deliberately the thinnest half.
 *
 * TRUST
 *
 * The user-mode process is UNPRIVILEGED. Every byte it sends is hostile until
 * proven otherwise, and the proving is done by `UdecxIpc`'s decoder, which is
 * fuzzed on three platforms precisely because it cannot be fuzzed here.
 *
 * WHAT IS NOT DECIDED YET, AND MUST BE BEFORE THIS SHIPS
 *
 * A process that can call plug-in can present ARBITRARY USB identities and make
 * Windows load kernel drivers against attacker-chosen descriptors. That is a
 * local "malicious USB device" capability and it is not made safe by the host
 * being unprivileged — those are different questions. The control device needs
 * an ACL and an explicit answer to "who may plug in". See WINDOWS_IMPORTER_PLAN.
 */

#ifndef AIRUSB_PLATFORM_WINDOWS_DRIVER_AIRUSB_SYS_H
#define AIRUSB_PLATFORM_WINDOWS_DRIVER_AIRUSB_SYS_H

#include <ntddk.h>
#include <wdf.h>
#include <usb.h>
#include <usbdi.h>
#include <usbdlib.h>
#include <wdfusb.h>
#include <UdeCx.h>

#include "../WindowsUsbAbi.h"

/* The device interface user mode opens to find this driver.
 *
 * Generated once, never derived from anything. Its ACL is what decides who may
 * present an arbitrary USB device to this machine — see the file header; that
 * decision is still open and must be made before this ships. */
// {4aa7ad7b-6160-4be4-bfd3-33caa80f09ed}
DEFINE_GUID(GUID_DEVINTERFACE_AIRUSB,
    0x4aa7ad7b, 0x6160, 0x4be4, 0xbf, 0xd3, 0x33, 0xca, 0xa8, 0x0f, 0x09, 0xed);

/* --- the control interface ------------------------------------------------
 *
 * FILE_DEVICE_UNKNOWN with a function base well above Microsoft's reserved
 * range. METHOD_BUFFERED for the small records, and the two data-carrying
 * codes use DIRECT so the I/O manager probes and locks the payload and hands us
 * an MDL whose length is authoritative — see the ABI header for why there is no
 * shared arena.
 */
#define AIRUSB_IOCTL_BASE 0x800

#define AIRUSB_IOCTL_BIND \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AIRUSB_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AIRUSB_IOCTL_PLUG_IN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AIRUSB_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AIRUSB_IOCTL_PLUG_OUT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AIRUSB_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* The inverted call: user mode parks these and the driver completes one when it
 * has work. OUT_DIRECT because the reply carries the OUT payload. */
#define AIRUSB_IOCTL_FETCH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AIRUSB_IOCTL_BASE + 3, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)
/* IN_DIRECT because the completion carries the IN payload. */
#define AIRUSB_IOCTL_COMPLETE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AIRUSB_IOCTL_BASE + 4, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)

/* Bounds. Every one of them exists so an unprivileged caller cannot make the
 * kernel size an allocation from a number it supplied. */
#define AIRUSB_MAX_PAYLOAD      (1u << 20)   /* usb-storage's SuperSpeed URB   */
#define AIRUSB_MAX_RECORD       (AIRUSB_MAX_PAYLOAD + 256u)
#define AIRUSB_MAX_MANIFEST     (256u * 1024u)
#define AIRUSB_MAX_PARKED_FETCH 32u
#define AIRUSB_MAX_OUTSTANDING  64u

/* --- contexts -------------------------------------------------------------
 *
 * One session per WDFFILEOBJECT, and nothing is shared implicitly between two
 * handles: on cleanup the session atomically disconnects its device and retires
 * its requests.
 */
typedef struct _AIRUSB_CONTROLLER_CONTEXT {
    WDFDEVICE       Device;         /* the controller (root) device            */
    WDFQUEUE        FetchQueue;     /* manual: parked inverted-call requests   */
    WDFSPINLOCK     Lock;           /* guards everything below                 */

    UDECXUSBDEVICE  UsbDevice;      /* NULL until plug-in                      */
    ULONG           DeviceIncarnation;
    ULONG           SessionIncarnation;
    BOOLEAN         Bound;          /* a host has claimed this controller      */
    PFILE_OBJECT    Owner;          /* the only handle allowed to drive it     */

    ULONGLONG       NextRequestId;  /* never reused within a session           */
    ULONG           Outstanding;
} AIRUSB_CONTROLLER_CONTEXT, *PAIRUSB_CONTROLLER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(AIRUSB_CONTROLLER_CONTEXT, AirUsbControllerContext)

typedef struct _AIRUSB_ENDPOINT_CONTEXT {
    UDECXUSBENDPOINT Endpoint;
    WDFQUEUE         Queue;         /* URBs for this endpoint                  */
    UCHAR            Address;
    UCHAR            TransferType;
    ULONG            EndpointId;    /* opaque, and NOT the address: alternate
                                     * settings reuse addresses, so the address
                                     * is not an identity                      */
} AIRUSB_ENDPOINT_CONTEXT, *PAIRUSB_ENDPOINT_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(AIRUSB_ENDPOINT_CONTEXT, AirUsbEndpointContext)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD          AirUsbEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL AirUsbEvtIoDeviceControl;
EVT_WDF_FILE_CLOSE                 AirUsbEvtFileClose;

#endif /* AIRUSB_PLATFORM_WINDOWS_DRIVER_AIRUSB_SYS_H */
