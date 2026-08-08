// AirUSB Hub — the mount-layer half of the exclusivity guarantee (P1 plan §7.2).
//
// The single-mount invariant needs TWO independent barriers, and this is the
// second one:
//
//   capture at the driver layer   IOUSBHostObjectInitOptionsDeviceCapture
//                                 terminates every client and driver of the device
//   claim   at the mount layer    DADiskClaim, held for the ENTIRE lease
//
// Capture alone is not enough. A naive claim -> unmount -> capture -> unclaim
// sequence leaves a window in which any event that re-registers the interfaces
// for matching lets IOUSBMassStorageDriver match and diskarbitrationd automount
// underneath a live lease — two mounted filesystems on one medium, which is the
// exact outcome the whole design exists to prevent.
//
// So the claim outlives the unmount. It is taken before the unmount, held through
// LEASED / SUSPENDED / DRAINING / ORPHANED, and released only after the device
// object has been destroyed on the way out.
//
// It never forces. If any unmount is dissented, the whole attach is abandoned and
// the disk is handed straight back. Capturing a mounted device would evict
// IOUSBMassStorageDriver out from under a filesystem holding dirty buffers, which
// is a physical yank with extra steps.

#ifndef AIRUSB_PLATFORM_MACOS_DISKGUARD_H
#define AIRUSB_PLATFORM_MACOS_DISKGUARD_H

#import <DiskArbitration/DiskArbitration.h>
#import <IOKit/IOKitLib.h>

#include "../../core/Status.h"

#include <set>
#include <string>
#include <vector>

namespace airusb::macos {

class DiskGuard {
public:
    DiskGuard() = default;
    ~DiskGuard();

    DiskGuard(const DiskGuard&)            = delete;
    DiskGuard& operator=(const DiskGuard&) = delete;

    /// Claims every whole disk beneath `device` and unmounts it.
    ///
    /// Returns:
    ///   Ok               claimed and unmounted; the caller may now capture
    ///   MountedLocally   an unmount was dissented — nothing was captured and the
    ///                    claim has already been released. `whyNot` names the
    ///                    disk, and the blocking process when DiskArbitration
    ///                    supplies it.
    ///   NotPermitted     not running as root (whole-disk unmount needs it)
    ///   BadArgument      the device backs the boot disk, which is never touched
    ///
    /// On any failure the guard unwinds completely, so the local OS keeps the
    /// drive. There is no partial state to clean up afterwards.
    Status claimAndUnmount(io_service_t device, std::string* whyNot);

    /// Releases every claim. Safe to call twice. MUST be called only after the
    /// IOUSBHostDevice has been destroyed: releasing the claim first reopens the
    /// automount window while the device is still captured.
    void release();

    bool holding() const noexcept { return !_claimed.empty(); }

    /// The whole disks that were claimed, for logging and for the evidence trail.
    const std::vector<std::string>& claimedDisks() const noexcept { return _claimedNames; }

    /// Every BSD name seen beneath the device, including slices. Used to report
    /// what was affected, not to decide what to unmount.
    const std::vector<std::string>& allBsdNames() const noexcept { return _allNames; }

private:
    Status openSession();
    void   closeSession();

    DASessionRef             _session = nullptr;
    dispatch_queue_t         _queue   = nullptr;
    std::vector<DADiskRef>   _claimed;
    std::vector<std::string> _claimedNames;
    std::vector<std::string> _allNames;
    bool                     _approvalRegistered = false;

    /// The disks the mount-approval callback must deny. It is a member rather
    /// than a global so two guards cannot share one set, and it is written only
    /// BEFORE the callback is registered and cleared only AFTER the DA queue has
    /// been drained — the callback runs on that queue and would otherwise be
    /// reading it as it was torn down.
    std::set<std::string>    _approvalNames;
};

} // namespace airusb::macos

#endif // AIRUSB_PLATFORM_MACOS_DISKGUARD_H
