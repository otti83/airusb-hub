/*
 * airusb.sys — DriverEntry, the UdeCx controller, the inverted call, and the
 * lifetime that keeps a dying host process from wedging the USB stack.
 *
 * Read airusb_sys.h first. The one rule: no UdeCx callback waits on user mode.
 *
 * WHAT CHANGED, AND WHY IT IS WORTH SAYING
 *
 * The first version of this file compiled, linked, and was honest that its five
 * IOCTL bodies returned STATUS_NOT_IMPLEMENTED. An adversarial review
 * (GPT-5.6, 2026-08-09) read it against the real UdeCx contract and found that
 * the scaffold was wrong in ways a build cannot see:
 *
 *   * `UDECX_WDF_DEVICE_CONFIG_INIT(&config, NULL)` passed no USB-capability
 *     query callback. The header marks it **Required**. The first symptom would
 *     have been a controller that fails to create — not obviously a driver bug.
 *   * `AirUsbRetireAll()` was an empty function with a comment claiming every
 *     outstanding transfer was completed. Nothing was.
 *   * `EvtFileClose` was the only teardown hook. It runs after the last handle
 *     reference goes, which can be long after the process died; `EvtFileCleanup`
 *     is the one that fires when the handle closes and is where a session must
 *     end.
 *   * There were no endpoint callbacks at all — no purge, no reset, no start —
 *     and purge is what a driver unload waits on.
 *   * `UdecxUsbDevicePlugOutAndDelete` is PASSIVE_LEVEL and the teardown path
 *     ran under a spin lock.
 *
 * All five are addressed here. None of it is verified: this driver has still
 * never been loaded, and compiling is not evidence about a kernel.
 */

/* initguid.h must precede the header that DEFINE_GUIDs, exactly once in the
 * driver, or the GUID is declared everywhere and defined nowhere. */
#include <initguid.h>

#include "airusb_sys.h"

#include <wdmsec.h>     /* SDDL_DEVOBJ_SYS_ALL_ADM_ALL */

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, AirUsbEvtDeviceAdd)
#endif

/* ------------------------------------------------------------------------- */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------- */

static ULONGLONG
AirUsbNowMs(VOID)
{
    LARGE_INTEGER freq;
    const LARGE_INTEGER now = KeQueryPerformanceCounter(&freq);
    if (freq.QuadPart == 0) return 0;
    return (ULONGLONG)((now.QuadPart * 1000LL) / freq.QuadPart);
}

/* Maps an abstract result from the host onto a USBD_STATUS.
 *
 * The mapping lives HERE and not in the host, which is rule 3 of the ABI: the
 * wire carries a small abstract enum, and USBD_STATUS — including the
 * short-transfer question, which depends on a flag the GUEST set — is decided
 * by the driver. A host cannot express a status/length combination that means
 * nothing, and cannot claim a halt the device never signalled. */
static USBD_STATUS
AirUsbUsbdStatusFor(
    _In_ USHORT Result,
    _In_ UCHAR  Flags,
    _In_ ULONG  Offered,
    _In_ ULONG  Actual
    )
{
    switch (Result) {
    case 0: /* Ok */
        /* Windows makes the caller say, per URB, whether short is acceptable.
         * Linux makes short unconditionally a success. Hardcoding either
         * answer breaks somebody, so the guest's own flag decides. */
        if (Actual < Offered && (Flags & AIRUSB_FLAG_SHORT_OK) == 0)
            return (USBD_STATUS)AIRUSB_USBD_ERROR_SHORT_TRANSFER;
        return (USBD_STATUS)AIRUSB_USBD_SUCCESS;
    case 1: return (USBD_STATUS)AIRUSB_USBD_STALL_PID;
    case 2: return (USBD_STATUS)AIRUSB_USBD_CANCELED;
    case 3: return (USBD_STATUS)AIRUSB_USBD_TIMEOUT;
    case 4: return (USBD_STATUS)AIRUSB_USBD_DEVICE_GONE;
    case 5: return (USBD_STATUS)AIRUSB_USBD_DATA_OVERRUN;
    case 6: return (USBD_STATUS)AIRUSB_USBD_DATA_UNDERRUN;
    case 7: return (USBD_STATUS)AIRUSB_USBD_INTERNAL_HC_ERROR;
    case 8: return (USBD_STATUS)AIRUSB_USBD_INVALID_URB_FUNCTION;
    default:
        /* Never Ok by accident. An unknown result is a failure. */
        return (USBD_STATUS)AIRUSB_USBD_REQUEST_FAILED;
    }
}

/* ------------------------------------------------------------------------- */
/* Retiring work — the function that used to be empty                        */
/* ------------------------------------------------------------------------- */

/* Completes every outstanding and queued transfer, right now, from kernel
 * state, and NEVER waits for anything.
 *
 * The point is that a user-mode process going away cannot leave a guest URB
 * pending for ever — and a guest driver waiting on a URB is a driver that will
 * not unload.
 *
 * Called with the lock HELD; it detaches the lists under the lock and completes
 * outside it, because WdfRequestComplete on an URB may run at DISPATCH_LEVEL
 * but WdfRequestUnmarkCancelable must not be called with a spin lock that the
 * cancel routine also takes — that is a deadlock, not a style preference. */
static VOID
AirUsbRetireAllLocked(
    _In_ PAIRUSB_CONTROLLER_CONTEXT Ctx,
    _Out_ PLIST_ENTRY Detached
    )
{
    InitializeListHead(Detached);

    while (!IsListEmpty(&Ctx->PendingWork)) {
        PLIST_ENTRY e = RemoveHeadList(&Ctx->PendingWork);
        InsertTailList(Detached, e);
    }
    Ctx->PendingCount = 0;

    while (!IsListEmpty(&Ctx->Exported)) {
        PLIST_ENTRY e = RemoveHeadList(&Ctx->Exported);
        InsertTailList(Detached, e);
    }
    Ctx->Outstanding = 0;
}

/* Completes what AirUsbRetireAllLocked detached. Lock NOT held. */
static VOID
AirUsbCompleteDetached(
    _Inout_ PLIST_ENTRY Detached,
    _In_ USBD_STATUS With
    )
{
    while (!IsListEmpty(Detached)) {
        PLIST_ENTRY e = RemoveHeadList(Detached);
        PAIRUSB_REQUEST_CONTEXT rc = CONTAINING_RECORD(e, AIRUSB_REQUEST_CONTEXT, Link);

        /* The cancel/complete race, decided the one documented way. If
         * WdfRequestUnmarkCancelable returns STATUS_CANCELLED the cancel
         * routine already owns this request and WILL complete it; completing it
         * here too is a double completion. */
        const NTSTATUS um = WdfRequestUnmarkCancelable(rc->Request);
        if (um == STATUS_CANCELLED) continue;

        rc->State = AirUsbReqRetired;
        UdecxUrbSetBytesCompleted(rc->Request, 0);
        UdecxUrbComplete(rc->Request, With);
    }
}

/* Fails every parked reset. Lock NOT held; the list is detached first. */
static VOID
AirUsbFailResets(_Inout_ PLIST_ENTRY Detached)
{
    while (!IsListEmpty(Detached)) {
        PLIST_ENTRY e = RemoveHeadList(Detached);
        PAIRUSB_RESET_CONTEXT rst = CONTAINING_RECORD(e, AIRUSB_RESET_CONTEXT, Link);
        /* Failing rather than faking: a reset reported as successful that the
         * host never performed leaves the guest driving an endpoint that is
         * still halted. */
        WdfRequestComplete(rst->Request, STATUS_DEVICE_NOT_CONNECTED);
        ExFreePoolWithTag(rst, AIRUSB_POOL_TAG);
    }
}

/* ------------------------------------------------------------------------- */
/* The inverted call                                                          */
/* ------------------------------------------------------------------------- */

/* Writes one UrbRequest record into a FETCH's output buffer.
 *
 * The layout is UdecxIpc's, byte for byte. It is written by hand here rather
 * than shared with the C++ encoder because a kernel TU cannot include <vector>;
 * `tests/unit/test_udecxipc.cpp` and `tests/fuzz/fuzz_udecxipc.cpp` are what
 * keep the two spellings identical, and `wdk_abi_check.c` is what keeps the
 * constants honest. */
static NTSTATUS
AirUsbWriteUrbRecord(
    _In_ PAIRUSB_REQUEST_CONTEXT Rc,
    _Out_writes_bytes_(BufferLength) PUCHAR Buffer,
    _In_ size_t BufferLength,
    _In_reads_bytes_opt_(PayloadLength) PUCHAR Payload,
    _In_ ULONG PayloadLength,
    _Out_ size_t* Written
    )
{
    /* envelope(8) + fixed(40) + payload */
    const size_t fixed = 8u + 40u;
    size_t need;

    *Written = 0;
    if (PayloadLength > AIRUSB_MAX_PAYLOAD) return STATUS_INVALID_PARAMETER;
    need = fixed + PayloadLength;
    if (BufferLength < need) return STATUS_BUFFER_TOO_SMALL;

    RtlZeroMemory(Buffer, need);

    /* envelope: u16 version, u16 opcode, u32 bodyLen */
    Buffer[0] = (UCHAR)(AIRUSB_IPC_VERSION & 0xFF);
    Buffer[1] = (UCHAR)((AIRUSB_IPC_VERSION >> 8) & 0xFF);
    Buffer[2] = 0x01;   /* Opcode::UrbRequest */
    Buffer[3] = 0x00;
    *(ULONG UNALIGNED*)(Buffer + 4) = (ULONG)(need - 8u);

    {
        PUCHAR b = Buffer + 8;
        *(ULONGLONG UNALIGNED*)(b + 0)  = Rc->RequestId;
        *(ULONG UNALIGNED*)(b + 8)      = Rc->SessionIncarnation;
        *(ULONG UNALIGNED*)(b + 12)     = Rc->DeviceIncarnation;
        *(ULONG UNALIGNED*)(b + 16)     = Rc->EndpointId;
        *(ULONG UNALIGNED*)(b + 20)     = Rc->OfferedLength;
        b[24] = Rc->TransferType;
        b[25] = Rc->Direction;
        b[26] = Rc->EndpointAddress;
        b[27] = Rc->Flags;
        RtlCopyMemory(b + 28, Rc->Setup, 8);
        *(ULONG UNALIGNED*)(b + 36)     = PayloadLength;
        if (PayloadLength != 0 && Payload != NULL)
            RtlCopyMemory(b + 40, Payload, PayloadLength);
    }

    *Written = need;
    return STATUS_SUCCESS;
}

/* Hands one queued request to a parked FETCH, if both exist.
 *
 * Called with the lock NOT held: WdfIoQueueRetrieveNextRequest takes the
 * queue's own lock, and taking ours around it would invert two lock orders. */
static VOID
AirUsbPumpFetch(_In_ PAIRUSB_CONTROLLER_CONTEXT Ctx)
{
    for (;;) {
        WDFREQUEST fetch = NULL;
        PAIRUSB_REQUEST_CONTEXT rc = NULL;
        PUCHAR outBuf = NULL;
        size_t outLen = 0;
        size_t written = 0;
        NTSTATUS status;

        /* THE WORK IS TAKEN FIRST, then a FETCH is retrieved for it.
         *
         * The other order looks more natural and is wrong: a request retrieved
         * from a manual queue cannot be forwarded back to the queue it came
         * from, so a fetch taken speculatively and then found to have no work
         * has nowhere to go — it must be completed empty, which makes the host
         * spin. Taking the work first means the only failure is "no fetch yet",
         * and the fix for that is to put the work back at the HEAD, where its
         * endpoint ordering is preserved. */
        WdfSpinLockAcquire(Ctx->Lock);
        if (Ctx->Life == AirUsbRunning && !IsListEmpty(&Ctx->PendingWork)) {
            PLIST_ENTRY e = RemoveHeadList(&Ctx->PendingWork);
            Ctx->PendingCount--;
            rc = CONTAINING_RECORD(e, AIRUSB_REQUEST_CONTEXT, Link);
            rc->State = AirUsbReqExported;
            InsertTailList(&Ctx->Exported, &rc->Link);
            Ctx->Outstanding++;
        }
        WdfSpinLockRelease(Ctx->Lock);

        if (rc == NULL) return;               /* nothing to hand over */

        status = WdfIoQueueRetrieveNextRequest(Ctx->FetchQueue, &fetch);
        if (!NT_SUCCESS(status)) {
            /* Nobody is asking for work. Put it back at the head — USB
             * serialises per endpoint, and a transfer that loses its place is a
             * transfer reordered on a pipe that guarantees order. */
            WdfSpinLockAcquire(Ctx->Lock);
            if (rc->State == AirUsbReqExported) {
                RemoveEntryList(&rc->Link);
                if (Ctx->Outstanding != 0) Ctx->Outstanding--;
                rc->State = AirUsbReqQueued;
                InsertHeadList(&Ctx->PendingWork, &rc->Link);
                Ctx->PendingCount++;
            }
            WdfSpinLockRelease(Ctx->Lock);
            return;
        }

        status = WdfRequestRetrieveOutputBuffer(fetch, 8u + 40u, (PVOID*)&outBuf, &outLen);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(fetch, status);
            continue;
        }

        {
            PUCHAR payload = NULL;
            ULONG  payloadLen = 0;
            /* An OUT transfer's bytes go down with the request. Retrieved from
             * the URB, whose buffer the I/O manager has already probed.
             *
             * ULONG, not size_t: UdecxUrbRetrieveBuffer takes a PULONG, and
             * casting the address of a size_t to PULONG writes four bytes into
             * an eight-byte object. It happens to work on a little-endian host
             * with a zeroed variable, which is exactly the kind of bug that
             * survives review. */
            if (rc->Direction == AIRUSB_DIR_OUT && rc->OfferedLength != 0)
                (void)UdecxUrbRetrieveBuffer(rc->Request, &payload, &payloadLen);

            status = AirUsbWriteUrbRecord(rc, outBuf, outLen, payload,
                                          payloadLen, &written);
        }

        if (!NT_SUCCESS(status)) {
            /* The host's buffer is too small for this transfer. Tell it so, and
             * retire the URB rather than leaving it exported to nobody. */
            WdfRequestComplete(fetch, status);

            WdfSpinLockAcquire(Ctx->Lock);
            RemoveEntryList(&rc->Link);
            Ctx->Outstanding--;
            WdfSpinLockRelease(Ctx->Lock);

            if (WdfRequestUnmarkCancelable(rc->Request) != STATUS_CANCELLED) {
                rc->State = AirUsbReqRetired;
                UdecxUrbSetBytesCompleted(rc->Request, 0);
                UdecxUrbComplete(rc->Request, (USBD_STATUS)AIRUSB_USBD_INVALID_PARAMETER);
            }
            continue;
        }

        WdfRequestSetInformation(fetch, written);
        WdfRequestComplete(fetch, STATUS_SUCCESS);
    }
}

/* ------------------------------------------------------------------------- */
/* Cancellation                                                               */
/* ------------------------------------------------------------------------- */

VOID
AirUsbEvtRequestCancel(
    _In_ WDFREQUEST Request
    )
/*
 * The guest unlinked a URB. The cancel path OWNS this request now — KMDF has
 * already decided that, by calling us instead of letting an ordinary completion
 * win — so it completes it and nothing else may.
 */
{
    PAIRUSB_REQUEST_CONTEXT rc = AirUsbRequestContext(Request);

    /* UNLINK FIRST. The context is allocated on the WDFREQUEST, so completing
     * the request is what eventually frees it — and a list still holding its
     * LIST_ENTRY afterwards is a dangling pointer that the next teardown walks.
     * That is a use-after-free reachable by unplugging a device at the wrong
     * moment, which is to say routinely. */
    if (rc != NULL && rc->Controller != NULL) {
        PAIRUSB_CONTROLLER_CONTEXT ctx = rc->Controller;
        WdfSpinLockAcquire(ctx->Lock);
        if (rc->State == AirUsbReqQueued) {
            RemoveEntryList(&rc->Link);
            if (ctx->PendingCount != 0) ctx->PendingCount--;
        } else if (rc->State == AirUsbReqExported) {
            RemoveEntryList(&rc->Link);
            if (ctx->Outstanding != 0) ctx->Outstanding--;
        }
        rc->State = AirUsbReqRetired;
        WdfSpinLockRelease(ctx->Lock);
    }

    UdecxUrbSetBytesCompleted(Request, 0);
    UdecxUrbComplete(Request, (USBD_STATUS)AIRUSB_USBD_CANCELED);
}

/* ------------------------------------------------------------------------- */
/* UdeCx callbacks                                                            */
/* ------------------------------------------------------------------------- */

NTSTATUS
AirUsbEvtQueryUsbCapability(
    _In_ WDFDEVICE UdecxWdfDevice,
    _In_ PGUID     CapabilityType,
    _In_ ULONG     OutputBufferLength,
    _Out_writes_to_opt_(OutputBufferLength, *ResultLength) PVOID OutputBuffer,
    _Out_ PULONG   ResultLength
    )
/*
 * REQUIRED by UDECX_WDF_DEVICE_CONFIG, and the first version of this driver
 * passed NULL for it. The header says "Required" in as many words; the likely
 * first symptom would have been a controller that fails to create, which reads
 * like a broken kit rather than a missing callback.
 *
 * v1 supports no optional USB capability. Reporting NOT_SUPPORTED for every
 * one of them is a complete and correct answer — the alternative, claiming a
 * capability and then not implementing it, is the same class of mistake as
 * advertising DEVICE_RESET with no handler.
 */
{
    UNREFERENCED_PARAMETER(UdecxWdfDevice);
    UNREFERENCED_PARAMETER(CapabilityType);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);

    *ResultLength = 0;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
AirUsbEvtDeviceD0Entry(
    _In_ WDFDEVICE      UdecxWdfDevice,
    _In_ UDECXUSBDEVICE UdecxUsbDevice
    )
/*
 * The virtual device is entering D0. Local state only; nothing here waits on
 * the host or on the network, because the power path is exactly where a wait
 * stalls the whole system's resume.
 */
{
    UNREFERENCED_PARAMETER(UdecxWdfDevice);
    UNREFERENCED_PARAMETER(UdecxUsbDevice);
    return STATUS_SUCCESS;
}

NTSTATUS
AirUsbEvtDeviceD0Exit(
    _In_ WDFDEVICE                    UdecxWdfDevice,
    _In_ UDECXUSBDEVICE               UdecxUsbDevice,
    _In_ UDECX_USB_DEVICE_WAKE_SETTING WakeSetting
    )
/*
 * Leaving D0. Every guest request is retired LOCALLY and immediately.
 *
 * Not forwarded, not waited on: the machine is going to sleep, the host process
 * may be suspended before it could answer, and a URB left outstanding across a
 * suspend is one the guest is still waiting on when the system tries to resume.
 */
{
    PAIRUSB_CONTROLLER_CONTEXT ctx = AirUsbControllerContext(UdecxWdfDevice);
    LIST_ENTRY detached;

    UNREFERENCED_PARAMETER(UdecxUsbDevice);
    UNREFERENCED_PARAMETER(WakeSetting);

    WdfSpinLockAcquire(ctx->Lock);
    AirUsbRetireAllLocked(ctx, &detached);
    WdfSpinLockRelease(ctx->Lock);

    AirUsbCompleteDetached(&detached, (USBD_STATUS)AIRUSB_USBD_DEVICE_GONE);
    return STATUS_SUCCESS;
}

VOID
AirUsbEvtEndpointPurge(
    _In_ UDECXUSBENDPOINT UdecxUsbEndpoint
    )
/*
 * THE callback that must never wait on user mode.
 *
 * A driver unload waits on purge. Making a remote acknowledgement a
 * prerequisite would let a slow link — or a dead host — hold an endpoint in
 * teardown for ever, which stops the guest's driver from unloading and
 * eventually stops the machine from shutting down cleanly.
 *
 * So: stop admitting, retire everything for this endpoint from kernel state,
 * and only then say purge is complete.
 */
{
    PAIRUSB_ENDPOINT_CONTEXT ep = AirUsbEndpointContext(UdecxUsbEndpoint);
    PAIRUSB_CONTROLLER_CONTEXT ctx = ep->Controller;
    LIST_ENTRY detached;
    PLIST_ENTRY cur;

    InitializeListHead(&detached);

    WdfSpinLockAcquire(ctx->Lock);
    ep->Purging = TRUE;

    /* Both lists: a transfer waiting to be collected and one the host is
     * working on are equally the guest's to get an answer for. */
    cur = ctx->PendingWork.Flink;
    while (cur != &ctx->PendingWork) {
        PAIRUSB_REQUEST_CONTEXT rc = CONTAINING_RECORD(cur, AIRUSB_REQUEST_CONTEXT, Link);
        PLIST_ENTRY next = cur->Flink;
        if (rc->EndpointId == ep->EndpointId) {
            RemoveEntryList(cur);
            ctx->PendingCount--;
            InsertTailList(&detached, cur);
        }
        cur = next;
    }
    cur = ctx->Exported.Flink;
    while (cur != &ctx->Exported) {
        PAIRUSB_REQUEST_CONTEXT rc = CONTAINING_RECORD(cur, AIRUSB_REQUEST_CONTEXT, Link);
        PLIST_ENTRY next = cur->Flink;
        if (rc->EndpointId == ep->EndpointId) {
            RemoveEntryList(cur);
            ctx->Outstanding--;
            InsertTailList(&detached, cur);
        }
        cur = next;
    }
    WdfSpinLockRelease(ctx->Lock);

    AirUsbCompleteDetached(&detached, (USBD_STATUS)AIRUSB_USBD_CANCELED);

    /* The queue may still hold requests UdeCx has handed us but that we have
     * not seen yet. Purging it synchronously drains those; it does not wait on
     * anything outside this driver. */
    WdfIoQueuePurgeSynchronously(ep->Queue);

    UdecxUsbEndpointPurgeComplete(UdecxUsbEndpoint);
}

VOID
AirUsbEvtEndpointStart(
    _In_ UDECXUSBENDPOINT UdecxUsbEndpoint
    )
/* Admission reopens. The mirror of purge, and just as local. */
{
    PAIRUSB_ENDPOINT_CONTEXT ep = AirUsbEndpointContext(UdecxUsbEndpoint);
    PAIRUSB_CONTROLLER_CONTEXT ctx = ep->Controller;

    WdfSpinLockAcquire(ctx->Lock);
    ep->Purging = FALSE;
    WdfSpinLockRelease(ctx->Lock);

    WdfIoQueueStart(ep->Queue);
}

VOID
AirUsbEvtEndpointReset(
    _In_ UDECXUSBENDPOINT UdecxUsbEndpoint,
    _In_ WDFREQUEST       Request
    )
/*
 * Endpoint reset is NOT cancellation. It means clear the halt and restore
 * data-toggle semantics, and only the far end can do that — the toggle that
 * matters lives in the EXPORTER's host controller.
 *
 * So the request is parked, a work record goes to the host, and the sweep
 * fails it after AIRUSB_RESET_TIMEOUT_MS if no answer comes. Bounded, and
 * failing rather than faking: a reset reported as successful that nobody
 * performed leaves the guest driving an endpoint that is still halted, and the
 * guest has no way to discover that.
 */
{
    PAIRUSB_ENDPOINT_CONTEXT ep = AirUsbEndpointContext(UdecxUsbEndpoint);
    PAIRUSB_CONTROLLER_CONTEXT ctx = ep->Controller;
    PAIRUSB_RESET_CONTEXT rst;
    BOOLEAN bound;

    WdfSpinLockAcquire(ctx->Lock);
    bound = ctx->Bound && ctx->Life == AirUsbRunning;
    WdfSpinLockRelease(ctx->Lock);

    if (!bound) {
        /* No host at all. Immediate and honest. */
        WdfRequestComplete(Request, STATUS_DEVICE_NOT_CONNECTED);
        return;
    }

    rst = (PAIRUSB_RESET_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*rst), AIRUSB_POOL_TAG);
    if (rst == NULL) {
        WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }
    RtlZeroMemory(rst, sizeof(*rst));
    rst->Request    = Request;
    rst->EndpointId = ep->EndpointId;

    WdfSpinLockAcquire(ctx->Lock);
    rst->TicketId = ctx->NextTicketId++;
    rst->DeadlineQpc.QuadPart = (LONGLONG)(AirUsbNowMs() + AIRUSB_RESET_TIMEOUT_MS);
    InsertTailList(&ctx->Resets, &rst->Link);
    WdfSpinLockRelease(ctx->Lock);

    /* The host learns about it through the same inverted call everything else
     * uses. Deliberately not a second channel: one path in means one path to
     * get wrong. */
    AirUsbPumpFetch(ctx);
}

/* ------------------------------------------------------------------------- */
/* The sweep — the only clock in the driver                                   */
/* ------------------------------------------------------------------------- */

VOID
AirUsbEvtSweep(
    _In_ WDFTIMER Timer
    )
{
    WDFDEVICE device = (WDFDEVICE)WdfTimerGetParentObject(Timer);
    PAIRUSB_CONTROLLER_CONTEXT ctx = AirUsbControllerContext(device);
    const ULONGLONG now = AirUsbNowMs();
    LIST_ENTRY expired;
    PLIST_ENTRY cur;

    InitializeListHead(&expired);

    WdfSpinLockAcquire(ctx->Lock);
    cur = ctx->Resets.Flink;
    while (cur != &ctx->Resets) {
        PAIRUSB_RESET_CONTEXT rst = CONTAINING_RECORD(cur, AIRUSB_RESET_CONTEXT, Link);
        PLIST_ENTRY next = cur->Flink;
        if ((ULONGLONG)rst->DeadlineQpc.QuadPart <= now) {
            RemoveEntryList(cur);
            InsertTailList(&expired, cur);
        }
        cur = next;
    }
    WdfSpinLockRelease(ctx->Lock);

    AirUsbFailResets(&expired);
}

/* ------------------------------------------------------------------------- */
/* Endpoint URBs                                                              */
/* ------------------------------------------------------------------------- */

VOID
AirUsbEvtIoInternalDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode
    )
/*
 * A URB from the guest, on an endpoint's queue.
 *
 * It is accepted, given an id, marked cancelable and queued — and then this
 * returns. Nothing waits. The record reaches the host on the next FETCH.
 */
{
    PAIRUSB_QUEUE_CONTEXT qc = AirUsbQueueContext(Queue);
    PAIRUSB_ENDPOINT_CONTEXT ep = (qc != NULL) ? qc->Endpoint : NULL;
    PAIRUSB_CONTROLLER_CONTEXT ctx;
    PAIRUSB_REQUEST_CONTEXT rc;
    WDF_OBJECT_ATTRIBUTES attrs;
    NTSTATUS status;
    PUCHAR buffer = NULL;
    ULONG  bufferLen = 0;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (IoControlCode != IOCTL_INTERNAL_USB_SUBMIT_URB) {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }
    if (ep == NULL) {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }
    ctx = ep->Controller;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, AIRUSB_REQUEST_CONTEXT);
    status = WdfObjectAllocateContext(Request, &attrs, (PVOID*)&rc);
    if (!NT_SUCCESS(status)) {
        UdecxUrbSetBytesCompleted(Request, 0);
        UdecxUrbComplete(Request, (USBD_STATUS)AIRUSB_USBD_NO_MEMORY);
        return;
    }
    RtlZeroMemory(rc, sizeof(*rc));
    rc->Request         = Request;
    rc->Controller      = ctx;
    rc->EndpointId      = ep->EndpointId;
    rc->EndpointAddress = ep->Address;
    rc->TransferType    = ep->TransferType;
    rc->Direction       = (UCHAR)((ep->Address & 0x80u) ? 1u : 0u);
    rc->State           = AirUsbReqQueued;

    if (ep->Address == 0) {
        /* Control. The setup packet is the guest's, verbatim: it is
         * little-endian USB and must never be reinterpreted here. */
        WDF_USB_CONTROL_SETUP_PACKET setup;
        if (NT_SUCCESS(UdecxUrbRetrieveControlSetupPacket(Request, &setup))) {
            RtlCopyMemory(rc->Setup, &setup, 8);
            rc->Direction = (UCHAR)((setup.Packet.bm.Byte & 0x80u) ? 1u : 0u);
        }
    }

    if (NT_SUCCESS(UdecxUrbRetrieveBuffer(Request, &buffer, &bufferLen)))
        rc->OfferedLength = bufferLen;

    /* The guest's own USBD_SHORT_TRANSFER_OK, carried down abstractly.
     *
     * It has to be read HERE, from the URB, because it is the guest's intent
     * and neither the host nor this driver may invent it: on Windows a short
     * transfer is an error unless the caller said otherwise, and on Linux it is
     * always a success. Hardcoding either answer breaks somebody. Without this
     * the flag was zero for every transfer and every short read would have been
     * reported as ERROR_SHORT_TRANSFER — which usb-storage treats as a failed
     * command. */
    {
        PIRP irp = WdfRequestWdmGetIrp(Request);
        if (irp != NULL) {
            PURB urb = (PURB)URB_FROM_IRP(irp);
            if (urb != NULL &&
                urb->UrbHeader.Function == URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER) {
                if ((urb->UrbBulkOrInterruptTransfer.TransferFlags
                     & AIRUSB_USBD_SHORT_TRANSFER_OK) != 0)
                    rc->Flags |= AIRUSB_FLAG_SHORT_OK;
            }
        }
    }

    if (rc->OfferedLength > AIRUSB_MAX_PAYLOAD) {
        UdecxUrbSetBytesCompleted(Request, 0);
        UdecxUrbComplete(Request, (USBD_STATUS)AIRUSB_USBD_INVALID_PARAMETER);
        return;
    }

    WdfSpinLockAcquire(ctx->Lock);
    if (ctx->Life != AirUsbRunning || !ctx->Bound || ep->Purging) {
        WdfSpinLockRelease(ctx->Lock);
        UdecxUrbSetBytesCompleted(Request, 0);
        UdecxUrbComplete(Request, (USBD_STATUS)AIRUSB_USBD_DEVICE_GONE);
        return;
    }
    if (ctx->PendingCount + ctx->Outstanding >= AIRUSB_MAX_OUTSTANDING) {
        WdfSpinLockRelease(ctx->Lock);
        /* A bound queue, refused honestly. Growing without limit on behalf of a
         * host that has stopped collecting is how a kernel runs out of pool. */
        UdecxUrbSetBytesCompleted(Request, 0);
        UdecxUrbComplete(Request, (USBD_STATUS)AIRUSB_USBD_ERROR_BUSY);
        return;
    }
    rc->RequestId          = ctx->NextRequestId++;
    rc->SessionIncarnation = ctx->SessionIncarnation;
    rc->DeviceIncarnation  = ctx->DeviceIncarnation;
    WdfSpinLockRelease(ctx->Lock);

    status = WdfRequestMarkCancelableEx(Request, AirUsbEvtRequestCancel);
    if (!NT_SUCCESS(status)) {
        /* Already cancelled before we could mark it. KMDF has NOT called the
         * cancel routine in this case, so completing it here is correct and is
         * the only completion. */
        UdecxUrbSetBytesCompleted(Request, 0);
        UdecxUrbComplete(Request, (USBD_STATUS)AIRUSB_USBD_CANCELED);
        return;
    }

    WdfSpinLockAcquire(ctx->Lock);
    InsertTailList(&ctx->PendingWork, &rc->Link);
    ctx->PendingCount++;
    WdfSpinLockRelease(ctx->Lock);

    AirUsbPumpFetch(ctx);
}

/* ------------------------------------------------------------------------- */
/* Teardown                                                                   */
/* ------------------------------------------------------------------------- */

VOID
AirUsbEvtTeardownWork(
    _In_ WDFWORKITEM WorkItem
    )
/*
 * The PASSIVE_LEVEL half of plug-out.
 *
 * `UdecxUsbDevicePlugOutAndDelete` is documented PASSIVE_LEVEL and a spin lock
 * raises to DISPATCH_LEVEL, so it cannot be called from the path that took the
 * lock to detach the handle. Splitting it here is the fix; the earlier version
 * got the IRQL right by calling it outside the lock, and that was only half of
 * it — an arbitrary caller of EvtFileCleanup is not guaranteed PASSIVE_LEVEL
 * either.
 */
{
    WDFDEVICE device = (WDFDEVICE)WdfWorkItemGetParentObject(WorkItem);
    PAIRUSB_CONTROLLER_CONTEXT ctx = AirUsbControllerContext(device);
    UDECXUSBDEVICE toDelete = NULL;
    LIST_ENTRY detached;
    LIST_ENTRY resets;

    PAGED_CODE();

    WdfSpinLockAcquire(ctx->Lock);
    toDelete       = ctx->UsbDevice;
    ctx->UsbDevice = NULL;
    AirUsbRetireAllLocked(ctx, &detached);
    InitializeListHead(&resets);
    while (!IsListEmpty(&ctx->Resets)) {
        PLIST_ENTRY e = RemoveHeadList(&ctx->Resets);
        InsertTailList(&resets, e);
    }
    ctx->EndpointCount = 0;
    RtlZeroMemory(ctx->Endpoints, sizeof(ctx->Endpoints));
    if (ctx->Life == AirUsbStopping) ctx->Life = AirUsbRunning;
    WdfSpinLockRelease(ctx->Lock);

    AirUsbCompleteDetached(&detached, (USBD_STATUS)AIRUSB_USBD_DEVICE_GONE);
    AirUsbFailResets(&resets);

    if (toDelete != NULL) {
        /* After this the UdeCx object is unusable. Nothing above may touch it,
         * which is why it was detached under the lock before we got here. */
        (void)UdecxUsbDevicePlugOutAndDelete(toDelete);
    }
}

/* Starts a plug-out. Safe from any IRQL and from any callback. */
static VOID
AirUsbBeginTeardown(_In_ PAIRUSB_CONTROLLER_CONTEXT Ctx)
{
    BOOLEAN queue = FALSE;

    WdfSpinLockAcquire(Ctx->Lock);
    if (Ctx->Life == AirUsbRunning && Ctx->UsbDevice != NULL) {
        Ctx->Life = AirUsbStopping;
        Ctx->DeviceIncarnation++;
        queue = TRUE;
    }
    WdfSpinLockRelease(Ctx->Lock);

    if (queue) WdfWorkItemEnqueue(Ctx->TeardownWork);
}

VOID
AirUsbEvtFileCleanup(
    _In_ WDFFILEOBJECT FileObject
    )
/*
 * The session ends HERE, not in EvtFileClose.
 *
 * Cleanup runs when the last handle is closed; Close runs when the last
 * reference goes, which can be much later — a duplicated handle, a mapped
 * section, a pending IRP. A host process that dies must become a plug-out
 * promptly, and Close does not promise that. The earlier version used Close as
 * its only hook.
 */
{
    WDFDEVICE device = WdfFileObjectGetDevice(FileObject);
    PAIRUSB_CONTROLLER_CONTEXT ctx = AirUsbControllerContext(device);
    BOOLEAN wasOwner = FALSE;

    WdfSpinLockAcquire(ctx->Lock);
    if (ctx->Owner == WdfFileObjectWdmGetFileObject(FileObject)) {
        ctx->Bound = FALSE;
        ctx->Owner = NULL;
        ctx->SessionIncarnation++;
        wasOwner = TRUE;
    }
    WdfSpinLockRelease(ctx->Lock);

    if (wasOwner) {
        /* Parked FETCHes belong to the handle that is going away. Purging the
         * queue completes them with STATUS_CANCELLED, which is what a closing
         * process expects and what stops them outliving it. */
        WdfIoQueuePurgeSynchronously(ctx->FetchQueue);
        AirUsbBeginTeardown(ctx);
        WdfIoQueueStart(ctx->FetchQueue);
    }
}

VOID
AirUsbEvtFileClose(
    _In_ WDFFILEOBJECT FileObject
    )
/* Kept, and deliberately near-empty: cleanup already did the work. It exists so
 * that a handle which somehow reaches Close without Cleanup — which should not
 * happen — still ends the session rather than leaving it bound to nothing. */
{
    AirUsbEvtFileCleanup(FileObject);
}

/* ------------------------------------------------------------------------- */
/* Plug-in                                                                    */
/* ------------------------------------------------------------------------- */

static NTSTATUS
AirUsbCreateEndpoint(
    _In_ PAIRUSB_CONTROLLER_CONTEXT Ctx,
    _In_ UDECXUSBDEVICE UsbDevice,
    _In_ UCHAR Address,
    _In_ ULONG EndpointId
    )
{
    PUDECXUSBENDPOINT_INIT init = NULL;
    UDECX_USB_ENDPOINT_CALLBACKS callbacks;
    WDF_OBJECT_ATTRIBUTES attrs;
    WDF_IO_QUEUE_CONFIG queueCfg;
    WDFQUEUE queue = NULL;
    UDECXUSBENDPOINT endpoint = NULL;
    PAIRUSB_ENDPOINT_CONTEXT epCtx;
    NTSTATUS status;

    init = UdecxUsbSimpleEndpointInitAllocate(UsbDevice);
    if (init == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    UdecxUsbEndpointInitSetEndpointAddress(init, Address);

    /* Reset is REQUIRED. Start and purge are documented optional and are
     * anything but: purge is what a driver unload waits on, and an endpoint
     * with no purge callback is one UdeCx cannot stop. */
    UDECX_USB_ENDPOINT_CALLBACKS_INIT(&callbacks, AirUsbEvtEndpointReset);
    callbacks.EvtUsbEndpointStart = AirUsbEvtEndpointStart;
    callbacks.EvtUsbEndpointPurge = AirUsbEvtEndpointPurge;
    UdecxUsbEndpointInitSetCallbacks(init, &callbacks);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, AIRUSB_ENDPOINT_CONTEXT);
    attrs.ParentObject = UsbDevice;
    status = UdecxUsbEndpointCreate(&init, &attrs, &endpoint);
    if (!NT_SUCCESS(status)) {
        if (init != NULL) UdecxUsbEndpointInitFree(init);
        return status;
    }

    /* Parallel, not sequential: USB serialises per endpoint on the BUS, and the
     * host's own admission depth is what limits concurrency. A sequential queue
     * here would additionally serialise the hand-over, which is latency for
     * nothing. */
    WDF_IO_QUEUE_CONFIG_INIT(&queueCfg, WdfIoQueueDispatchParallel);
    queueCfg.EvtIoInternalDeviceControl = AirUsbEvtIoInternalDeviceControl;
    queueCfg.PowerManaged = WdfFalse;
    {
        WDF_OBJECT_ATTRIBUTES qattrs;
        WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&qattrs, AIRUSB_QUEUE_CONTEXT);
        qattrs.ParentObject = Ctx->Device;
        status = WdfIoQueueCreate(Ctx->Device, &queueCfg, &qattrs, &queue);
    }
    if (!NT_SUCCESS(status)) return status;

    UdecxUsbEndpointSetWdfIoQueue(endpoint, queue);

    epCtx = AirUsbEndpointContext(endpoint);
    RtlZeroMemory(epCtx, sizeof(*epCtx));
    epCtx->Endpoint     = endpoint;
    epCtx->Queue        = queue;
    epCtx->Address      = Address;
    epCtx->EndpointId   = EndpointId;
    epCtx->Controller   = Ctx;
    /* Control on ep0, bulk otherwise.
     *
     * v1 presents bulk endpoints only, which is exactly what the exporter side
     * will attach: `ExporterSession` refuses a device with an interrupt or
     * isochronous endpoint through a synchronous port, and no exporter in this
     * project has an asynchronous one yet. When that changes, the type belongs
     * in the plug-in record beside the address rather than being inferred here,
     * and this comment is the marker for where. */
    epCtx->TransferType = (UCHAR)(Address == 0 ? AIRUSB_XFER_CONTROL : AIRUSB_XFER_BULK);

    /* The queue's own back-pointer, which is how EvtIoInternalDeviceControl
     * finds the endpoint an URB arrived on. */
    AirUsbQueueContext(queue)->Endpoint = epCtx;

    if (Ctx->EndpointCount < AIRUSB_MAX_ENDPOINTS)
        Ctx->Endpoints[Ctx->EndpointCount++] = epCtx;

    return STATUS_SUCCESS;
}

static NTSTATUS
AirUsbPlugIn(
    _In_ PAIRUSB_CONTROLLER_CONTEXT Ctx,
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ size_t Length
    )
/*
 * The manifest arrives whole, in one buffered IOCTL, and is SNAPSHOTTED before
 * any nested length in it is walked. bLength, wTotalLength and the descriptor
 * counts are all bounds, and they are all attacker-controlled.
 */
{
    AIRUSB_PLUG_IN_HEADER hdr;
    PUCHAR snapshot = NULL;
    PUDECXUSBDEVICE_INIT init = NULL;
    UDECX_USB_DEVICE_STATE_CHANGE_CALLBACKS callbacks;
    UDECX_USB_DEVICE_PLUG_IN_OPTIONS options;
    WDF_OBJECT_ATTRIBUTES attrs;
    UDECXUSBDEVICE usbDevice = NULL;
    NTSTATUS status;
    size_t need;
    ULONG i;

    PAGED_CODE();

    if (Length < sizeof(hdr)) return STATUS_INVALID_PARAMETER;

    /* Copied ONCE, then used. Never re-read: the caller still owns the mapping
     * and can be changing it, so a length checked in the buffer and used from
     * the buffer are two different numbers. */
    RtlCopyMemory(&hdr, Buffer, sizeof(hdr));

    if (hdr.Version != AIRUSB_IPC_VERSION) return STATUS_REVISION_MISMATCH;
    if (hdr.Reserved != 0)                 return STATUS_INVALID_PARAMETER;
    if (hdr.DeviceDescriptorLen < 18 || hdr.DeviceDescriptorLen > 64)
        return STATUS_INVALID_PARAMETER;
    if (hdr.ConfigDescriptorLen < 9 || hdr.ConfigDescriptorLen > 65535)
        return STATUS_INVALID_PARAMETER;
    if (hdr.StringBlobLen > AIRUSB_MAX_MANIFEST) return STATUS_INVALID_PARAMETER;
    if (hdr.EndpointCount == 0 || hdr.EndpointCount > AIRUSB_MAX_ENDPOINTS)
        return STATUS_INVALID_PARAMETER;
    if (hdr.Speed > AIRUSB_UDECX_SPEED_SUPER) return STATUS_INVALID_PARAMETER;

    /* Overflow-safe: each addend is already bounded above, and the sum is
     * checked against the buffer we were actually given. */
    need = sizeof(hdr) + hdr.DeviceDescriptorLen + hdr.ConfigDescriptorLen
         + hdr.StringBlobLen + hdr.EndpointCount;
    if (Length < need) return STATUS_INVALID_PARAMETER;

    snapshot = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, need, AIRUSB_POOL_TAG);
    if (snapshot == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(snapshot, Buffer, need);

    init = UdecxUsbDeviceInitAllocate(Ctx->Device);
    if (init == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto done; }

    UdecxUsbDeviceInitSetSpeed(init, (UDECX_USB_DEVICE_SPEED)hdr.Speed);
    /* Simple, not dynamic. See the header: the exporters cannot change a
     * captured device's configuration, so the dynamic model would buy the
     * ability to do something the far end cannot do, at the cost of the hardest
     * lifetime problem in this API. */
    UdecxUsbDeviceInitSetEndpointsType(init, UdecxEndpointTypeSimple);

    UDECX_USB_DEVICE_CALLBACKS_INIT(&callbacks);
    callbacks.EvtUsbDeviceLinkPowerEntry = AirUsbEvtDeviceD0Entry;
    callbacks.EvtUsbDeviceLinkPowerExit  = AirUsbEvtDeviceD0Exit;
    UdecxUsbDeviceInitSetStateChangeCallbacks(init, &callbacks);

    {
        PUCHAR p = snapshot + sizeof(hdr);
        status = UdecxUsbDeviceInitAddDescriptor(init, p, (USHORT)hdr.DeviceDescriptorLen);
        if (!NT_SUCCESS(status)) goto done;
        p += hdr.DeviceDescriptorLen;

        status = UdecxUsbDeviceInitAddDescriptor(init, p, (USHORT)hdr.ConfigDescriptorLen);
        if (!NT_SUCCESS(status)) goto done;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    status = UdecxUsbDeviceCreate(&init, &attrs, &usbDevice);
    if (!NT_SUCCESS(status)) goto done;
    init = NULL;    /* consumed on success */

    Ctx->EndpointCount = 0;
    RtlZeroMemory(Ctx->Endpoints, sizeof(Ctx->Endpoints));
    for (i = 0; i < hdr.EndpointCount; ++i) {
        const UCHAR addr = snapshot[sizeof(hdr) + hdr.DeviceDescriptorLen
                                  + hdr.ConfigDescriptorLen + hdr.StringBlobLen + i];
        status = AirUsbCreateEndpoint(Ctx, usbDevice, addr, i + 1u);
        if (!NT_SUCCESS(status)) goto done;
    }

    UDECX_USB_DEVICE_PLUG_IN_OPTIONS_INIT(&options);
    status = UdecxUsbDevicePlugIn(usbDevice, &options);
    if (!NT_SUCCESS(status)) goto done;

    WdfSpinLockAcquire(Ctx->Lock);
    Ctx->UsbDevice = usbDevice;
    Ctx->DeviceIncarnation++;
    WdfSpinLockRelease(Ctx->Lock);
    usbDevice = NULL;

done:
    if (init != NULL)      UdecxUsbDeviceInitFree(init);
    if (usbDevice != NULL) (void)UdecxUsbDevicePlugOutAndDelete(usbDevice);
    if (snapshot != NULL)  ExFreePoolWithTag(snapshot, AIRUSB_POOL_TAG);
    return status;
}

/* ------------------------------------------------------------------------- */
/* Completion from the host                                                   */
/* ------------------------------------------------------------------------- */

static NTSTATUS
AirUsbHandleCompletion(
    _In_ PAIRUSB_CONTROLLER_CONTEXT Ctx,
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ size_t Length
    )
/*
 * The completion header is copied out of the buffer ONCE, then validated, then
 * used. Never re-read: the payload half is in an MDL the caller still owns and
 * can be changing under us, and a length read twice is a length that can differ
 * between the check and the copy.
 */
{
    ULONGLONG requestId;
    ULONG sessionInc, deviceInc, actualLength, payloadLen;
    USHORT version, opcode, result;
    PAIRUSB_REQUEST_CONTEXT found = NULL;
    PLIST_ENTRY cur;
    PUCHAR payload;

    if (Length < 8u + 24u) return STATUS_INVALID_PARAMETER;

    version = (USHORT)(Buffer[0] | (Buffer[1] << 8));
    opcode  = (USHORT)(Buffer[2] | (Buffer[3] << 8));
    if (version != AIRUSB_IPC_VERSION) return STATUS_REVISION_MISMATCH;
    if (opcode != 0x0002)              return STATUS_INVALID_PARAMETER;

    requestId    = *(ULONGLONG UNALIGNED*)(Buffer + 8);
    sessionInc   = *(ULONG UNALIGNED*)(Buffer + 16);
    deviceInc    = *(ULONG UNALIGNED*)(Buffer + 20);
    result       = (USHORT)(Buffer[24] | (Buffer[25] << 8));
    actualLength = *(ULONG UNALIGNED*)(Buffer + 28);
    payloadLen   = *(ULONG UNALIGNED*)(Buffer + 32);

    if (payloadLen > AIRUSB_MAX_PAYLOAD) return STATUS_INVALID_PARAMETER;
    if (Length < 8u + 32u + 4u + payloadLen) return STATUS_INVALID_PARAMETER;
    payload = Buffer + 8u + 36u;

    WdfSpinLockAcquire(Ctx->Lock);
    cur = Ctx->Exported.Flink;
    while (cur != &Ctx->Exported) {
        PAIRUSB_REQUEST_CONTEXT rc = CONTAINING_RECORD(cur, AIRUSB_REQUEST_CONTEXT, Link);
        if (rc->RequestId == requestId) {
            /* Identity is more than a request id. A late completion arriving
             * after a plug-out and re-plug must not land on a fresh request
             * that happens to reuse the number. */
            if (rc->SessionIncarnation != sessionInc ||
                rc->DeviceIncarnation  != deviceInc) break;
            RemoveEntryList(cur);
            Ctx->Outstanding--;
            found = rc;
            break;
        }
        cur = cur->Flink;
    }
    WdfSpinLockRelease(Ctx->Lock);

    if (found == NULL) {
        /* A completion for a request already retired. Normal after a
         * cancellation, and NOT a protocol violation — refusing it would make
         * routine cancellation look like an attack. */
        return STATUS_SUCCESS;
    }

    if (WdfRequestUnmarkCancelable(found->Request) == STATUS_CANCELLED) {
        /* The cancel path won and will complete it. Nothing to do. */
        return STATUS_SUCCESS;
    }

    if (actualLength > found->OfferedLength) {
        /* The device cannot have moved more than was asked for. This is the
         * check that stops a hostile host overrunning a buffer whose size the
         * GUEST's driver chose. A malformed completion that names a live
         * request must still RETIRE that request — merely rejecting the IOCTL
         * would leave the guest's URB hanging for ever. */
        found->State = AirUsbReqRetired;
        UdecxUrbSetBytesCompleted(found->Request, 0);
        UdecxUrbComplete(found->Request, (USBD_STATUS)AIRUSB_USBD_BUFFER_OVERRUN);
        return STATUS_INVALID_PARAMETER;
    }

    if (found->Direction == 1 && payloadLen != 0) {
        PUCHAR dst = NULL;
        ULONG  dstLen = 0;
        if (NT_SUCCESS(UdecxUrbRetrieveBuffer(found->Request, &dst, &dstLen))) {
            const ULONG n = payloadLen < dstLen ? payloadLen : dstLen;
            RtlCopyMemory(dst, payload, n);
        }
    }

    found->State = AirUsbReqRetired;
    UdecxUrbSetBytesCompleted(found->Request, actualLength);
    UdecxUrbComplete(found->Request,
                     AirUsbUsbdStatusFor(result, found->Flags,
                                         found->OfferedLength, actualLength));
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* The control interface                                                      */
/* ------------------------------------------------------------------------- */

VOID
AirUsbEvtIoDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode
    )
{
    WDFDEVICE device = WdfIoQueueGetDevice(Queue);
    PAIRUSB_CONTROLLER_CONTEXT ctx = AirUsbControllerContext(device);
    PFILE_OBJECT self = WdfFileObjectWdmGetFileObject(WdfRequestGetFileObject(Request));
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    BOOLEAN complete = TRUE;
    PVOID inBuf = NULL;
    size_t inLen = 0;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    switch (IoControlCode) {

    case AIRUSB_IOCTL_BIND:
        /* Claims the controller for this handle. Refused if somebody already
         * has it — a second binder is a bug in the caller, not a takeover to be
         * silently permitted. */
        WdfSpinLockAcquire(ctx->Lock);
        if (ctx->Life != AirUsbRunning) {
            status = STATUS_DEVICE_NOT_READY;
        } else if (ctx->Bound) {
            status = STATUS_DEVICE_BUSY;
        } else {
            ctx->Bound = TRUE;
            ctx->Owner = self;
            ctx->SessionIncarnation++;
            status = STATUS_SUCCESS;
        }
        WdfSpinLockRelease(ctx->Lock);
        break;

    case AIRUSB_IOCTL_PLUG_IN: {
        BOOLEAN mine;
        WdfSpinLockAcquire(ctx->Lock);
        mine = ctx->Bound && ctx->Owner == self && ctx->Life == AirUsbRunning
               && ctx->UsbDevice == NULL;
        WdfSpinLockRelease(ctx->Lock);
        if (!mine) { status = STATUS_INVALID_DEVICE_STATE; break; }

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(AIRUSB_PLUG_IN_HEADER),
                                               &inBuf, &inLen);
        if (!NT_SUCCESS(status)) break;
        status = AirUsbPlugIn(ctx, (PUCHAR)inBuf, inLen);
        break;
    }

    case AIRUSB_IOCTL_PLUG_OUT: {
        BOOLEAN mine;
        WdfSpinLockAcquire(ctx->Lock);
        mine = ctx->Bound && ctx->Owner == self;
        WdfSpinLockRelease(ctx->Lock);
        if (!mine) { status = STATUS_INVALID_DEVICE_STATE; break; }
        AirUsbBeginTeardown(ctx);
        status = STATUS_SUCCESS;
        break;
    }

    case AIRUSB_IOCTL_FETCH: {
        BOOLEAN mine;
        WdfSpinLockAcquire(ctx->Lock);
        mine = ctx->Bound && ctx->Owner == self && ctx->Life == AirUsbRunning;
        WdfSpinLockRelease(ctx->Lock);
        if (!mine) { status = STATUS_INVALID_DEVICE_STATE; break; }

        /* Parked, not answered. It is completed later, when there is an URB —
         * and it stays cancelable the whole time, so a host that exits gets its
         * requests back instead of leaving them in the kernel. */
        status = WdfRequestForwardToIoQueue(Request, ctx->FetchQueue);
        if (NT_SUCCESS(status)) {
            complete = FALSE;
            AirUsbPumpFetch(ctx);
        }
        break;
    }

    case AIRUSB_IOCTL_COMPLETE: {
        BOOLEAN mine;
        WdfSpinLockAcquire(ctx->Lock);
        mine = ctx->Bound && ctx->Owner == self;
        WdfSpinLockRelease(ctx->Lock);
        if (!mine) { status = STATUS_INVALID_DEVICE_STATE; break; }

        status = WdfRequestRetrieveInputBuffer(Request, 8u + 24u, &inBuf, &inLen);
        if (!NT_SUCCESS(status)) break;
        status = AirUsbHandleCompletion(ctx, (PUCHAR)inBuf, inLen);
        break;
    }

    default:
        break;
    }

    if (complete) WdfRequestComplete(Request, status);
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

    /* The capability callback is REQUIRED. Passing NULL here was the first
     * structural defect a review found in this file. */
    UDECX_WDF_DEVICE_CONFIG_INIT(&config, AirUsbEvtQueryUsbCapability);

    /* 2.0 vs 3.0 controller capability is a property of the emulated bus, not
     * of one device. Advertising SuperSpeed lets a SuperSpeed manifest be
     * presented honestly; a High Speed device on it is still legal. */
    config.NumberOfUsb20Ports = 1;
    config.NumberOfUsb30Ports = 1;

    return UdecxWdfDeviceAddUsbDeviceEmulation(Device, &config);
}

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
 *
 * FETCH is the exception and is forwarded to a manual queue immediately, so a
 * parked inverted call never blocks the sequential control path behind it.
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
    WDF_WORKITEM_CONFIG workCfg;
    WDF_TIMER_CONFIG timerCfg;
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

    /* THE ACL, and the answer to "who may present an arbitrary USB device to
     * this machine".
     *
     * A process that can call PLUG_IN makes Windows load kernel drivers against
     * descriptors it chose. That is a local malicious-device capability, and it
     * is not made safe by the caller being unprivileged — those are different
     * questions. SYSTEM and Administrators only; the broker runs as LocalSystem.
     * This was explicitly left open in the first version of the file. */
    status = WdfDeviceInitAssignSDDLString(DeviceInit, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* CLEANUP, not just Close. Cleanup fires when the handle closes; Close can
     * be much later, and a host process that dies must become a plug-out
     * promptly. */
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, NULL, AirUsbEvtFileClose,
                               AirUsbEvtFileCleanup);
    WdfDeviceInitSetFileObjectConfig(DeviceInit, &fileConfig,
                                     WDF_NO_OBJECT_ATTRIBUTES);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, AIRUSB_CONTROLLER_CONTEXT);
    status = WdfDeviceCreate(&DeviceInit, &attrs, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ctx = AirUsbControllerContext(device);
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->Device        = device;
    ctx->NextRequestId = 1;
    ctx->NextTicketId  = 1;
    ctx->Life          = AirUsbRunning;
    InitializeListHead(&ctx->PendingWork);
    InitializeListHead(&ctx->Exported);
    InitializeListHead(&ctx->Resets);

    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    attrs.ParentObject = device;
    status = WdfSpinLockCreate(&attrs, &ctx->Lock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* The PASSIVE_LEVEL half of teardown. Allocated once, at device-add time,
     * because allocating it during teardown is allocating on the path that runs
     * when things are already going wrong. */
    WDF_WORKITEM_CONFIG_INIT(&workCfg, AirUsbEvtTeardownWork);
    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    attrs.ParentObject = device;
    status = WdfWorkItemCreate(&workCfg, &attrs, &ctx->TeardownWork);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_TIMER_CONFIG_INIT_PERIODIC(&timerCfg, AirUsbEvtSweep, AIRUSB_SWEEP_PERIOD_MS);
    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    attrs.ParentObject = device;
    status = WdfTimerCreate(&timerCfg, &attrs, &ctx->Sweep);
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

    status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_AIRUSB, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    (void)WdfTimerStart(ctx->Sweep, WDF_REL_TIMEOUT_IN_MS(AIRUSB_SWEEP_PERIOD_MS));
    return STATUS_SUCCESS;
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
    config.DriverPoolTag = AIRUSB_POOL_TAG;

    return WdfDriverCreate(DriverObject, RegistryPath,
                           WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
}
