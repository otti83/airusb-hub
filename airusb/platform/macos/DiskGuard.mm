#include "DiskGuard.h"
#include "MacUsbCommon.h"

#include <atomic>
#include <set>
#include <unistd.h>

namespace airusb::macos {

namespace {

/// Whole disk ("disk4") versus slice ("disk4s1"). Only whole disks are unmounted:
/// kDADiskUnmountOptionWhole takes the slices with it, and unmounting slices
/// individually races the whole-disk unmount.
bool isWholeDisk(const std::string& bsd)
{
    if (bsd.size() <= 4 || bsd.compare(0, 4, "disk") != 0) return false;
    // Guard the scan explicitly. This runs as root and a short or unexpected BSD
    // name must not become an out-of-bounds read.
    return bsd.find('s', 4) == std::string::npos;
}

/// The boot disk is refused outright. This is a belt-and-braces check on top of
/// only ever looking at disks beneath a USB device: a Mac booted from a USB
/// drive would otherwise be a very short experiment.
bool looksLikeBootDisk(const std::string& bsd)
{
    return bsd == "disk0" || bsd.compare(0, 6, "disk0s") == 0;
}

struct UnmountCtx {
    dispatch_semaphore_t done = nullptr;
    std::atomic<bool>    ok{true};
    std::string          whyNot;
};

void unmountCallback(DADiskRef disk, DADissenterRef dissenter, void* context)
{
    auto* ctx = static_cast<UnmountCtx*>(context);
    const char* bsd = DADiskGetBSDName(disk);

    if (dissenter) {
        const DAReturn st = DADissenterGetStatus(dissenter);
        CFStringRef reason = DADissenterGetStatusString(dissenter);

        NSString* s = [NSString stringWithFormat:@"/dev/%s could not be unmounted "
                       "(0x%08X)%@%@", bsd ? bsd : "?", st,
                       reason ? @": " : @"", reason ? (__bridge NSString*)reason : @""];
        ctx->whyNot = std::string(s.UTF8String);
        ctx->ok.store(false);
        logLine("ERROR", @"%@ — is a file open on it?", s);
    } else {
        logLine("ATTACH", @"unmounted /dev/%s", bsd ? bsd : "?");
    }
    dispatch_semaphore_signal(ctx->done);
}

struct ClaimCtx {
    dispatch_semaphore_t done = nullptr;
    std::atomic<bool>    ok{true};
    std::string          whyNot;
};

void claimCallback(DADiskRef disk, DADissenterRef dissenter, void* context)
{
    auto* ctx = static_cast<ClaimCtx*>(context);
    const char* bsd = DADiskGetBSDName(disk);
    if (dissenter) {
        NSString* s = [NSString stringWithFormat:@"/dev/%s is already claimed by "
                       "another process (0x%08X)", bsd ? bsd : "?",
                       DADissenterGetStatus(dissenter)];
        ctx->whyNot = std::string(s.UTF8String);
        ctx->ok.store(false);
        logLine("ERROR", @"%@", s);
    } else {
        logLine("ATTACH", @"claimed /dev/%s", bsd ? bsd : "?");
    }
    dispatch_semaphore_signal(ctx->done);
}

/// Refuses to hand the claim to anyone else for as long as we hold it. This is
/// the mechanism behind "the claim is held for the ENTIRE lease": another process
/// politely asking for the disk gets a no, not a yes with a race attached.
DADissenterRef claimReleaseCallback(DADiskRef disk, void* context)
{
    (void)context;
    const char* bsd = DADiskGetBSDName(disk);
    logLine("ATTACH", @"refusing to release the claim on /dev/%@ — it is leased "
                       "to another machine", @(bsd ? bsd : "?"));
    return DADissenterCreate(kCFAllocatorDefault, kDAReturnBusy,
                             CFSTR("This drive is currently shared with another "
                                   "computer by AirUSB Hub."));
}

/// Denies any mount attempt on a disk we are holding. The claim already stops
/// most paths; this closes the remaining one, in which something re-registers the
/// media for matching and diskarbitrationd tries to automount it.
DADissenterRef mountApprovalCallback(DADiskRef disk, void* context)
{
    auto* names = static_cast<std::set<std::string>*>(context);
    const char* bsd = DADiskGetBSDName(disk);
    if (!bsd || !names) return nullptr;

    // Match the whole disk and its slices: "disk4" claimed means "disk4s1" must
    // not mount either.
    const std::string name(bsd);
    for (const std::string& claimed : *names) {
        if (name == claimed || name.compare(0, claimed.size() + 1, claimed + "s") == 0) {
            logLine("ATTACH", @"denied a mount attempt on /dev/%@ while leased", @(bsd));
            return DADissenterCreate(kCFAllocatorDefault, kDAReturnBusy,
                                     CFSTR("This drive is currently shared with "
                                           "another computer by AirUSB Hub."));
        }
    }
    return nullptr;
}

constexpr std::int64_t kUnmountTimeoutNs = 15LL * NSEC_PER_SEC;
constexpr std::int64_t kClaimTimeoutNs   = 10LL * NSEC_PER_SEC;

} // namespace

// ---------------------------------------------------------------------------

DiskGuard::~DiskGuard() { release(); }

Status DiskGuard::openSession()
{
    if (_session) return Status::Ok;

    _session = DASessionCreate(kCFAllocatorDefault);
    if (!_session) {
        logLine("ERROR", @"DASessionCreate failed");
        return Status::Internal;
    }

    // A dispatch queue rather than a run loop: the daemon spends its life blocked
    // on a socket read, and a run-loop-scheduled DA session would never be
    // pumped, so an automount could not be denied while a transfer was in flight.
    _queue = dispatch_queue_create("com.airusb.diskguard", DISPATCH_QUEUE_SERIAL);
    DASessionSetDispatchQueue(_session, _queue);
    return Status::Ok;
}

void DiskGuard::closeSession()
{
    if (_session) {
        DASessionSetDispatchQueue(_session, nullptr);
        CFRelease(_session);
        _session = nullptr;
    }
    _queue = nullptr;          // ARC releases the dispatch object
}

Status DiskGuard::claimAndUnmount(io_service_t device, std::string* whyNot)
{
    const auto fail = [&](Status s, const std::string& msg) {
        if (whyNot) *whyNot = msg;
        release();
        return s;
    };

    // Whole-disk unmount is one of the two operations measured to genuinely need
    // root (0xF8DA0009 kDAReturnNotPrivileged otherwise). Checked up front so the
    // failure is legible rather than arriving as a dissent.
    if (geteuid() != 0)
        return fail(Status::NotPermitted,
                    "DiskArbitration whole-disk unmount requires root");

    std::set<std::string> bsd;
    collectBsdNames(device, bsd);
    _allNames.assign(bsd.begin(), bsd.end());

    for (const std::string& b : bsd) {
        if (looksLikeBootDisk(b))
            return fail(Status::BadArgument, "refusing: " + b + " looks like the boot disk");
    }

    if (bsd.empty()) {
        // A USB device with no block media beneath it: a keyboard, a hub, a
        // serial adapter. Nothing to unmount, and nothing to claim.
        logLine("ATTACH", @"no BSD media beneath the device; no claim needed");
        return Status::Ok;
    }

    if (const Status s = openSession(); s != Status::Ok)
        return fail(s, "DASessionCreate failed");

    // ---- claim every whole disk, BEFORE unmounting ------------------------
    for (const std::string& b : bsd) {
        if (!isWholeDisk(b)) continue;

        DADiskRef disk = DADiskCreateFromBSDName(kCFAllocatorDefault, _session, b.c_str());
        if (!disk)
            return fail(Status::Internal, "DADiskCreateFromBSDName failed for " + b);

        ClaimCtx ctx;
        ctx.done = dispatch_semaphore_create(0);
        DADiskClaim(disk, kDADiskClaimOptionDefault,
                    claimReleaseCallback, nullptr,
                    claimCallback, &ctx);

        if (dispatch_semaphore_wait(ctx.done,
                dispatch_time(DISPATCH_TIME_NOW, kClaimTimeoutNs)) != 0) {
            CFRelease(disk);
            return fail(Status::Busy, "claim of " + b + " timed out");
        }
        if (!ctx.ok.load()) {
            CFRelease(disk);
            return fail(Status::ExclusivityDenied, ctx.whyNot);
        }

        _claimed.push_back(disk);              // ownership moves to _claimed
        _claimedNames.push_back(b);
    }

    // ---- deny automounts for as long as the claim is held ------------------
    //
    // The set is fully populated BEFORE the callback is registered. The callback
    // runs on the DA queue and only ever reads, so with that ordering no lock is
    // needed and none is taken — a lock here could deadlock against
    // DiskArbitration's own queue.
    _approvalNames.clear();
    for (const std::string& n : _claimedNames) _approvalNames.insert(n);
    DARegisterDiskMountApprovalCallback(_session, nullptr,
                                        mountApprovalCallback, &_approvalNames);
    _approvalRegistered = true;

    // ---- unmount -----------------------------------------------------------
    for (std::size_t i = 0; i < _claimed.size(); ++i) {
        UnmountCtx ctx;
        ctx.done = dispatch_semaphore_create(0);

        logLine("ATTACH", @"unmounting /dev/%s (whole disk)", _claimedNames[i].c_str());
        DADiskUnmount(_claimed[i], kDADiskUnmountOptionWhole, unmountCallback, &ctx);

        if (dispatch_semaphore_wait(ctx.done,
                dispatch_time(DISPATCH_TIME_NOW, kUnmountTimeoutNs)) != 0)
            return fail(Status::MountedLocally,
                        "unmount of " + _claimedNames[i] + " timed out");

        if (!ctx.ok.load()) {
            // Never force. The attach is abandoned and the drive stays exactly
            // where it was, still mounted, still the user's.
            return fail(Status::MountedLocally, ctx.whyNot);
        }
    }

    logLine("ATTACH", @"claimed and unmounted %zu whole disk(s); the claim is held "
                       "for the whole lease", _claimed.size());
    return Status::Ok;
}

void DiskGuard::release()
{
    if (!_claimed.empty())
        logLine("DETACH", @"releasing %zu disk claim(s)", _claimed.size());

    // Unregister the approval callback FIRST. Unclaiming while it is still
    // registered would leave us denying mounts of a disk we no longer hold,
    // which is how a drive ends up unmountable after a clean detach.
    if (_session && _approvalRegistered) {
        DAUnregisterApprovalCallback(_session, (void*)mountApprovalCallback,
                                     &_approvalNames);
        _approvalRegistered = false;

        // Unregistering does not promise that a callback already running has
        // finished. The queue is serial, so a synchronous no-op on it returns
        // only once anything in flight has completed — after which the set the
        // callback reads can safely be destroyed.
        if (_queue) dispatch_sync(_queue, ^{});
    }
    _approvalNames.clear();

    for (DADiskRef d : _claimed) {
        DADiskUnclaim(d);
        CFRelease(d);
    }
    _claimed.clear();
    _claimedNames.clear();

    closeSession();
}

} // namespace airusb::macos
