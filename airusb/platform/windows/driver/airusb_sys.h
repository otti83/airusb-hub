/*
 * airusb.sys — the AirUSB virtual USB host, as a KMDF/UdeCx client driver.
 *
 * WHAT THIS DRIVER IS FOR, IN ONE SENTENCE
 *
 * It makes Windows enumerate a device that is plugged into a different machine,
 * by presenting a virtual USB device to the USB Device Emulation class
 * extension and forwarding every transfer to a user-mode service that owns the
 * network.
 *
 * THE RULE THE WHOLE FILE IS ORGANISED AROUND
 *
 * **No UdeCx callback may ever wait on user mode.** Not for a transfer, not for
 * a configure, and above all not for a purge. The user-mode half is across an
 * IOCTL boundary from a process that can be slow, killed, or hostile; a
 * callback that blocks on it hands that process the ability to wedge the USB
 * stack, and purge in particular is what a driver unload waits on.
 *
 * So: everything is answered from kernel state immediately, and the network is
 * something that later CHANGES that state. That is the same discipline
 * `VhciNetBridge` follows on Linux, for the same reason, and it is why the
 * user-mode `UdecxBridge` already exists and is already tested — this driver is
 * deliberately the thinnest half.
 *
 * SIMPLE ENDPOINTS, NOT DYNAMIC — AND THAT IS A SAFETY DECISION
 *
 * UdeCx offers two endpoint models. Dynamic endpoints require
 * `EvtUsbDeviceEndpointsConfigure`, a transaction the driver must answer while
 * creating and destroying kernel objects, and getting it wrong destroys an
 * object whose completions are still in flight. Simple endpoints are created
 * once, at plug-in, from the manifest.
 *
 * v1 takes Simple, because no exporter in this project can change a captured
 * device's configuration (P1 §4.8) — so the dynamic model would buy the ability
 * to do something the other end cannot do anyway, at the cost of the hardest
 * lifetime problem in the API. `UdecxBridge` already refuses a SET_CONFIGURATION
 * to any value but the captured one, for the same reason.
 *
 * TRUST
 *
 * The user-mode service is the AirUSB broker, and it runs as LocalSystem. That
 * is not because the protocol needs privilege — it does not — but because of
 * what PLUG_IN is: a process that can call it presents an ARBITRARY USB
 * IDENTITY to this machine and makes Windows load kernel drivers against
 * attacker-chosen descriptors. That is a local "malicious USB device"
 * capability and it is not made safe by the caller being unprivileged; those
 * are different questions. So the device object carries
 * `SDDL_DEVOBJ_SYS_ALL_ADM_ALL` — SYSTEM and Administrators, nobody else — and
 * the answer to "who may plug in" is now written down instead of open.
 *
 * Every byte the service sends is still hostile until proven otherwise, and the
 * proving is done by `UdecxIpc`'s decoder, which is fuzzed on three platforms
 * precisely because it cannot be fuzzed here.
 *
 * NOT LOADED. NOT ONCE.
 *
 * This file compiles and links. It has never been loaded on any machine, and
 * the first load must happen with somebody at the keyboard of a machine nobody
 * minds losing — see WINDOWS_IMPORTER_PLAN.md §W6 for the staged order that
 * gives a first failure ONE possible cause instead of five.
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
 * Generated once, never derived from anything. The ACL that decides who may
 * present an arbitrary USB device to this machine is applied to the device
 * OBJECT (SDDL_DEVOBJ_SYS_ALL_ADM_ALL, in AirUsbEvtDeviceAdd), because a
 * device-interface GUID is discoverable by anyone and is not itself a
 * permission. */
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
#define AIRUSB_MAX_ENDPOINTS    32u
#define AIRUSB_POOL_TAG         'sUiA'       /* 'AiUs' read back */

/* How long a UdeCx endpoint-reset may wait for the host before it is failed.
 *
 * Bounded, and failing rather than faking. A reset that reports success the
 * host never performed leaves the guest driving an endpoint that is still
 * halted, which is worse than an honest failure the guest can escalate from. */
#define AIRUSB_RESET_TIMEOUT_MS 5000
/* The sweep that enforces it. One timer for the whole driver, not one per
 * request: a timer per request is an object per request to leak. */
#define AIRUSB_SWEEP_PERIOD_MS  1000

/* --- the plug-in record ----------------------------------------------------
 *
 * Fixed header, then descriptor blobs. Every length is bounded BEFORE it is
 * used to walk anything, and the whole buffer is snapshotted into pool before
 * ANY nested length in it is read — the caller still owns the buffer the I/O
 * manager mapped, and a length read twice is a length that can change between
 * the check and the copy.
 */
#pragma pack(push, 1)
typedef struct _AIRUSB_PLUG_IN_HEADER {
    ULONG  Version;             /* must equal AIRUSB_ABI_VERSION       */
    ULONG  Speed;               /* AIRUSB_SPEED_*, from WindowsUsbAbi  */
    ULONG  DeviceDescriptorLen;
    ULONG  ConfigDescriptorLen;
    ULONG  StringBlobLen;       /* concatenated string descriptors      */
    ULONG  EndpointCount;
    ULONG  Reserved;            /* MBZ, and checked                     */
    /* UCHAR DeviceDescriptor[DeviceDescriptorLen];
     * UCHAR ConfigDescriptor[ConfigDescriptorLen];
     * UCHAR StringBlob[StringBlobLen];
     * UCHAR EndpointAddresses[EndpointCount];  */
} AIRUSB_PLUG_IN_HEADER, *PAIRUSB_PLUG_IN_HEADER;
#pragma pack(pop)

/* --- contexts -------------------------------------------------------------
 *
 * One session per WDFFILEOBJECT, and nothing is shared implicitly between two
 * handles: on cleanup the session atomically disconnects its device and retires
 * its requests.
 */

/* Where a forwarded URB is in its life.
 *
 * Exactly one transition out of Exported wins. KMDF's cancel/complete race is
 * decided by WdfRequestUnmarkCancelable: if it returns STATUS_CANCELLED the
 * cancel path already owns the request, and completing it again is a double
 * completion — a bugcheck, on the teardown path nobody tests twice. */
typedef enum _AIRUSB_REQ_STATE {
    AirUsbReqQueued = 0,
    AirUsbReqExported,
    AirUsbReqCompleting,
    AirUsbReqRetired
} AIRUSB_REQ_STATE;

typedef struct _AIRUSB_REQUEST_CONTEXT {
    LIST_ENTRY       Link;
    WDFREQUEST       Request;
    /* The controller, so a cancel can UNLINK this entry.
     *
     * A back-pointer to the ENDPOINT would be a use-after-free waiting to
     * happen — an endpoint object is destroyed by a configure or a plug-out
     * while requests for it may still be in flight. The controller context
     * lives on the WDFDEVICE and outlives every request on it, so this one is
     * safe, and it is the minimum needed: without it the cancel routine
     * completes a request while the list still holds its context, and the
     * context is freed with the request. */
    struct _AIRUSB_CONTROLLER_CONTEXT* Controller;
    ULONGLONG        RequestId;      /* ours; never reused within a session  */
    ULONG            EndpointId;     /* opaque; NOT the address              */
    UCHAR            EndpointAddress;
    UCHAR            TransferType;   /* AIRUSB_XFER_*                        */
    UCHAR            Direction;      /* 0 OUT, 1 IN                          */
    UCHAR            Flags;          /* AIRUSB_FLAG_SHORT_OK                 */
    ULONG            OfferedLength;
    ULONG            SessionIncarnation;
    ULONG            DeviceIncarnation;
    AIRUSB_REQ_STATE State;
    UCHAR            Setup[8];
} AIRUSB_REQUEST_CONTEXT, *PAIRUSB_REQUEST_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(AIRUSB_REQUEST_CONTEXT, AirUsbRequestContext)

/* A UdeCx endpoint-reset the host has not answered yet. */
typedef struct _AIRUSB_RESET_CONTEXT {
    LIST_ENTRY  Link;
    WDFREQUEST  Request;
    ULONGLONG   TicketId;
    ULONG       EndpointId;
    LARGE_INTEGER DeadlineQpc;
} AIRUSB_RESET_CONTEXT, *PAIRUSB_RESET_CONTEXT;

/* The endpoint an URB queue belongs to.
 *
 * `WdfIoQueueGetDevice` returns the CONTROLLER, not the endpoint — there is no
 * "get the endpoint from the queue" call — so the association has to be stored,
 * and a context on the queue object is where it goes. Reaching for
 * WdfIoQueueGetDevice and casting the result was the shape of the first attempt
 * at this, and it would have read a controller context as if it were an
 * endpoint one: a wrong pointer that a build cannot see and a first load
 * discovers as a bugcheck. */
typedef struct _AIRUSB_QUEUE_CONTEXT {
    struct _AIRUSB_ENDPOINT_CONTEXT* Endpoint;
} AIRUSB_QUEUE_CONTEXT, *PAIRUSB_QUEUE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(AIRUSB_QUEUE_CONTEXT, AirUsbQueueContext)

typedef struct _AIRUSB_ENDPOINT_CONTEXT {
    UDECXUSBENDPOINT Endpoint;
    WDFQUEUE         Queue;         /* URBs for this endpoint                  */
    UCHAR            Address;
    UCHAR            TransferType;
    BOOLEAN          Purging;       /* no new work is admitted while set       */
    ULONG            EndpointId;    /* opaque, and NOT the address: alternate
                                     * settings reuse addresses, so the address
                                     * is not an identity                      */
    struct _AIRUSB_CONTROLLER_CONTEXT* Controller;
} AIRUSB_ENDPOINT_CONTEXT, *PAIRUSB_ENDPOINT_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(AIRUSB_ENDPOINT_CONTEXT, AirUsbEndpointContext)

/* The teardown state machine. Running -> Stopping -> Deleted, and nothing goes
 * backwards. Every entry point checks it under the lock, so a callback that
 * arrives during teardown declines instead of racing it. */
typedef enum _AIRUSB_LIFE {
    AirUsbRunning = 0,
    AirUsbStopping,
    AirUsbDeleted
} AIRUSB_LIFE;

typedef struct _AIRUSB_CONTROLLER_CONTEXT {
    WDFDEVICE       Device;         /* the controller (root) device            */
    WDFQUEUE        FetchQueue;     /* manual: parked inverted-call requests   */
    WDFSPINLOCK     Lock;           /* guards everything below                 */
    WDFWORKITEM     TeardownWork;   /* PASSIVE_LEVEL half of plug-out          */
    WDFTIMER        Sweep;          /* bounds a reset waiting on the host      */

    UDECXUSBDEVICE  UsbDevice;      /* NULL until plug-in                      */
    ULONG           DeviceIncarnation;
    ULONG           SessionIncarnation;
    AIRUSB_LIFE     Life;
    BOOLEAN         Bound;          /* a host has claimed this controller      */
    PFILE_OBJECT    Owner;          /* the only handle allowed to drive it     */

    ULONGLONG       NextRequestId;  /* never reused within a session           */
    ULONGLONG       NextTicketId;

    /* Work the host has not collected yet, and transfers it is working on.
     * Two lists rather than one: a record waiting to be handed over and a
     * request waiting for an answer are different states with different
     * cancellation rules, and merging them is how a cancel frees the wrong one. */
    LIST_ENTRY      PendingWork;    /* AIRUSB_REQUEST_CONTEXT, state Queued    */
    ULONG           PendingCount;
    LIST_ENTRY      Exported;       /* AIRUSB_REQUEST_CONTEXT, state Exported  */
    ULONG           Outstanding;

    LIST_ENTRY      Resets;         /* AIRUSB_RESET_CONTEXT                    */

    PAIRUSB_ENDPOINT_CONTEXT Endpoints[AIRUSB_MAX_ENDPOINTS];
    ULONG                    EndpointCount;
} AIRUSB_CONTROLLER_CONTEXT, *PAIRUSB_CONTROLLER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(AIRUSB_CONTROLLER_CONTEXT, AirUsbControllerContext)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD          AirUsbEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL AirUsbEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL AirUsbEvtIoInternalDeviceControl;
EVT_WDF_FILE_CLEANUP               AirUsbEvtFileCleanup;
EVT_WDF_FILE_CLOSE                 AirUsbEvtFileClose;
EVT_WDF_WORKITEM                   AirUsbEvtTeardownWork;
EVT_WDF_TIMER                      AirUsbEvtSweep;
EVT_WDF_REQUEST_CANCEL             AirUsbEvtRequestCancel;

EVT_UDECX_WDF_DEVICE_QUERY_USB_CAPABILITY AirUsbEvtQueryUsbCapability;
EVT_UDECX_USB_DEVICE_D0_ENTRY             AirUsbEvtDeviceD0Entry;
EVT_UDECX_USB_DEVICE_D0_EXIT              AirUsbEvtDeviceD0Exit;
EVT_UDECX_USB_ENDPOINT_RESET              AirUsbEvtEndpointReset;
EVT_UDECX_USB_ENDPOINT_START              AirUsbEvtEndpointStart;
EVT_UDECX_USB_ENDPOINT_PURGE              AirUsbEvtEndpointPurge;

#endif /* AIRUSB_PLATFORM_WINDOWS_DRIVER_AIRUSB_SYS_H */
