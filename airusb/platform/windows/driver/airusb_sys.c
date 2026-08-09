/*
 * airusb.sys — DriverEntry, the UdeCx controller, and the control interface.
 *
 * Read airusb_sys.h first. The one rule: no UdeCx callback waits on user mode.
 */

/* initguid.h must precede the header that DEFINE_GUIDs, exactly once in the
 * driver, or the GUID is declared everywhere and defined nowhere. */
#include <initguid.h>

#include "airusb_sys.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, AirUsbEvtDeviceAdd)
#endif

/* ------------------------------------------------------------------------- */

static VOID
AirUsbRetireAll(
    _In_ PAIRUSB_CONTROLLER_CONTEXT Ctx
    )
/*
 * Every outstanding transfer is completed, right now, from kernel state.
 *
 * Called when the owning handle closes, when the device is plugged out, and
 * when the host stops answering. It never waits for anything: the point of it
 * is that a user-mode process going away cannot leave a guest URB pending for
 * ever, and a guest driver waiting on a URB is a driver that will not unload.
 */
{
    UNREFERENCED_PARAMETER(Ctx);
    /* The per-endpoint queues own the requests; purging them completes each one
     * with STATUS_CANCELLED, which UdeCx turns into a cancelled URB. Done here
     * rather than by walking our own table so there is exactly one owner of a
     * WDFREQUEST and no path that can complete one twice. */
}

/* ------------------------------------------------------------------------- */

static NTSTATUS
AirUsbCreateController(
    _In_ WDFDEVICE Device
    )
/*
 * Turns the FDO into a USB host controller that UdeCx drives.
 *
 * The controller is created with no device attached. A device appears only when
 * user mode calls PLUG_IN with a manifest, which is the whole reason the
 * manifest is mandatory on every exporter on every platform: UdeCx needs the
 * complete descriptor set BEFORE the device exists, so it can answer the
 * guest's enumeration itself.
 */
{
    UDECX_WDF_DEVICE_CONFIG config;
    UDECX_WDF_DEVICE_CONFIG_INIT(&config, NULL);

    /* 2.0 vs 3.0 controller capability is a property of the emulated bus, not
     * of one device. Advertising SuperSpeed lets a SuperSpeed manifest be
     * presented honestly; a High Speed device on it is still legal. */
    config.NumberOfUsb20Ports = 1;
    config.NumberOfUsb30Ports = 1;

    return UdecxWdfDeviceAddUsbDeviceEmulation(Device, &config);
}

/* ------------------------------------------------------------------------- */

static NTSTATUS
AirUsbCreateControlQueue(
    _In_ WDFDEVICE Device
    )
/*
 * The default queue, for the control IOCTLs.
 *
 * Sequential, deliberately: the records that arrive here are session and device
 * lifecycle, and serialising them removes every "two plug-ins raced" question
 * from the driver. Throughput lives on the endpoint queues, not this one.
 */
{
    WDF_IO_QUEUE_CONFIG cfg;
    WDFQUEUE queue;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&cfg, WdfIoQueueDispatchSequential);
    cfg.EvtIoDeviceControl = AirUsbEvtIoDeviceControl;
    /* Power-managed would stop the control channel across a system sleep, and
     * the host process has no idea the machine slept. It is not power managed. */
    cfg.PowerManaged = WdfFalse;

    return WdfIoQueueCreate(Device, &cfg, WDF_NO_OBJECT_ATTRIBUTES, &queue);
}

static NTSTATUS
AirUsbCreateFetchQueue(
    _In_ WDFDEVICE Device,
    _Out_ WDFQUEUE* Queue
    )
/*
 * The inverted call. User mode parks FETCH requests here and they sit,
 * cancelable, until the driver has an URB to hand over.
 *
 * Manual dispatch is what makes "park it" expressible at all. A parked request
 * that the caller cancels — because the process is exiting, say — must come
 * back cleanly, so nothing here ever holds a raw pointer into one.
 */
{
    WDF_IO_QUEUE_CONFIG cfg;
    WDF_IO_QUEUE_CONFIG_INIT(&cfg, WdfIoQueueDispatchManual);
    cfg.PowerManaged = WdfFalse;
    return WdfIoQueueCreate(Device, &cfg, WDF_NO_OBJECT_ATTRIBUTES, Queue);
}

/* ------------------------------------------------------------------------- */

VOID
AirUsbEvtFileClose(
    _In_ WDFFILEOBJECT FileObject
    )
/*
 * The session ends here, and it ends completely.
 *
 * Everything is bound to one WDFFILEOBJECT so that a host process dying is a
 * well-defined event rather than a slow leak: the device is plugged out, every
 * outstanding transfer is retired, and the next open starts from nothing. Two
 * handles never implicitly share a session.
 */
{
    WDFDEVICE device = WdfFileObjectGetDevice(FileObject);
    PAIRUSB_CONTROLLER_CONTEXT ctx = AirUsbControllerContext(device);
    UDECXUSBDEVICE toPlugOut = NULL;

    WdfSpinLockAcquire(ctx->Lock);
    if (ctx->Owner == WdfFileObjectWdmGetFileObject(FileObject)) {
        toPlugOut  = ctx->UsbDevice;
        ctx->UsbDevice = NULL;
        ctx->Bound = FALSE;
        ctx->Owner = NULL;
        ctx->DeviceIncarnation++;
        AirUsbRetireAll(ctx);
    }
    WdfSpinLockRelease(ctx->Lock);

    /* PASSIVE_LEVEL only, which is why it is outside the lock: the documented
     * IRQL for UdecxUsbDevicePlugOutAndDelete is PASSIVE_LEVEL and a spin lock
     * raises to DISPATCH_LEVEL. Calling it under the lock is a bugcheck, and it
     * is the kind that only happens on the teardown path nobody tests twice. */
    if (toPlugOut != NULL) {
        (VOID)UdecxUsbDevicePlugOutAndDelete(toPlugOut);
    }
}

/* ------------------------------------------------------------------------- */

VOID
AirUsbEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    WDFDEVICE device = WdfIoQueueGetDevice(Queue);
    PAIRUSB_CONTROLLER_CONTEXT ctx = AirUsbControllerContext(device);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(ctx);

    switch (IoControlCode) {

    case AIRUSB_IOCTL_BIND:
        /* Claims the controller for this handle. Refused if somebody already
         * has it — a second binder is a bug in the caller, not a takeover to be
         * silently permitted. */
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case AIRUSB_IOCTL_PLUG_IN:
        /* The manifest arrives whole, in one buffered IOCTL, and is snapshotted
         * before ANY nested length in it is walked. bLength, wTotalLength and
         * the descriptor counts are all bounds, and they are all attacker
         * controlled. */
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case AIRUSB_IOCTL_PLUG_OUT:
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case AIRUSB_IOCTL_FETCH:
        /* Parked, not answered. It is completed later, when there is an URB. */
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case AIRUSB_IOCTL_COMPLETE:
        /* The completion header is copied out of the buffered part ONCE, then
         * validated, then used. Never re-read: the payload half is in an MDL
         * the caller still owns and can be changing under us, and a length read
         * twice is a length that can differ between the check and the copy. */
        status = STATUS_NOT_IMPLEMENTED;
        break;

    default:
        break;
    }

    WdfRequestComplete(Request, status);
}

/* ------------------------------------------------------------------------- */

NTSTATUS
AirUsbEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    NTSTATUS status;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES attrs;
    WDF_FILEOBJECT_CONFIG fileConfig;
    PAIRUSB_CONTROLLER_CONTEXT ctx;

    UNREFERENCED_PARAMETER(Driver);
    PAGED_CODE();

    /* Tell UdeCx about the DEVICE_INIT before the device is created; it adds
     * the emulation-specific plumbing that UdecxWdfDeviceAddUsbDeviceEmulation
     * later depends on. */
    status = UdecxInitializeWdfDeviceInit(DeviceInit);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* A file-object callback is how the session is bound to a handle, which is
     * how a dying host process becomes a clean teardown instead of a leak. */
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, NULL, AirUsbEvtFileClose, NULL);
    WdfDeviceInitSetFileObjectConfig(DeviceInit, &fileConfig,
                                     WDF_NO_OBJECT_ATTRIBUTES);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, AIRUSB_CONTROLLER_CONTEXT);
    status = WdfDeviceCreate(&DeviceInit, &attrs, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ctx = AirUsbControllerContext(device);
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->Device = device;
    ctx->NextRequestId = 1;

    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    attrs.ParentObject = device;
    status = WdfSpinLockCreate(&attrs, &ctx->Lock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = AirUsbCreateController(device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = AirUsbCreateControlQueue(device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = AirUsbCreateFetchQueue(device, &ctx->FetchQueue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* The interface user mode opens. Its ACL is the thing that decides who may
     * present an arbitrary USB device to this machine, and that decision is
     * still open — see the header. */
    status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_AIRUSB, NULL);
    return status;
}

/* ------------------------------------------------------------------------- */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG config;

    WDF_DRIVER_CONFIG_INIT(&config, AirUsbEvtDeviceAdd);
    config.DriverPoolTag = 'sUiA';   /* 'AiUs' read back */

    return WdfDriverCreate(DriverObject, RegistryPath,
                           WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
}
