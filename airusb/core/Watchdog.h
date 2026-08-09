// AirUSB Hub — THE timeout table (P1 plan §6.1)
//
// Every deadline in the system lives here, in one file, with the ordering
// relationships between them asserted. They are not independent tunables: several
// pairs must hold a specific order or the system corrupts data rather than merely
// running slowly.
//
// The two that matter most:
//
//   T_urb_ceiling_bulk < T_urb_watchdog_importer
//     The importer must NEVER time out before the exporter. Two independent
//     timeouts racing to recover a Bulk-Only Transport phase is a corruption path.
//     A cheap flash stick doing internal garbage collection legitimately takes
//     8-12 s for one WRITE(10); macOS's own SCSI timeout is 30 s+.
//
//   T_detach_importer + t_disconnect_max < T_lease_exporter
//     The exporter must not release the capture and hand the drive back to the
//     local OS while the importer still believes it owns the device. That is the
//     both-sides-mounted case the whole exclusivity design exists to prevent.

#ifndef AIRUSB_CORE_WATCHDOG_H
#define AIRUSB_CORE_WATCHDOG_H

#include <cstdint>

namespace airusb::watchdog {

using Ms = std::uint64_t;
using Us = std::uint64_t;

// --- kernel-facing, macOS IOUSBHostControllerInterface -----------------------

/// capabilities commandTimeoutThreshold = 3 -> 2^3 s, the maximum of the 2-bit
/// field. NEVER approach this. IOUSBHostCIExceptionTypeCommandTimeout is
/// unrecoverable and destroys the controller, so we take maximum headroom.
/// Cost of the large value: a genuinely deadlocked daemon stalls the OS USB stack
/// for 8 s instead of 2 s. That is a bug to fix, not a parameter to tune, and it
/// is strictly preferable to a destroyed controller.
inline constexpr Ms kCmdKernelFatal = 8000;

/// INV-CMD: the command handler allocates nothing, takes no cross-strand lock,
/// issues no syscall, and returns within this at p99.9. Asserted in CI against a
/// synthetic command trace.
inline constexpr Us kCmdHandlerBudgetUs = 200;

/// Watchdog on any command we were ever forced to defer. In the normal design no
/// such path exists; if this fires we synthesize a local failure response and log
/// a design defect rather than letting the kernel deadline expire.
inline constexpr Ms kCmdDeferredMax = 1500;

// --- transfer deadlines ------------------------------------------------------

/// Deadline on a forwarded ep0 control transfer. USB 2.0 §9.2.6 allows 5 s for
/// standard requests.
inline constexpr Ms kNetCtrl = 5000;

/// The EXPORTER's per-URB abort ceiling for bulk and control.
inline constexpr Ms kUrbCeilingBulk = 30000;

/// Importer-side safety net only. Must be strictly greater than the exporter's
/// ceiling; see the file header.
inline constexpr Ms kUrbWatchdogImporter = 45000;

/// Interrupt IN may legitimately idle forever, so there is no deadline at all.
/// This also forces IOUSBHostPipe.completionTimeout to 0 for interrupt pipes and
/// streams: the exporter cannot delegate interrupt timeouts to IOKit. They are
/// aborted only on cancel, endpoint destroy, lease loss, or detach.
inline constexpr Ms kUrbDeadlineIntr = 0;

// --- liveness ----------------------------------------------------------------

inline constexpr Ms kKeepaliveInterval = 500;   ///< PING when otherwise idle
inline constexpr Ms kKeepaliveMiss     = 1500;  ///< 3 misses -> DEGRADED (silent)
inline constexpr Ms kDetachImporter    = 6000;  ///< silence -> force port disconnect
inline constexpr Ms kDisconnectMax     = 1000;  ///< measured bound on that disconnect
inline constexpr Ms kLeaseExporter     = 20000; ///< silence -> release capture, restore
inline constexpr Ms kSuspendHold       = 600000;///< explicit SUSPEND_IO -> hold 10 min
inline constexpr Ms kDrainGraceful     = 2000;  ///< DRAINING: await completions

// --- ordering relationships (P1 plan §6.1) -----------------------------------

static_assert(kCmdDeferredMax * 4 < kCmdKernelFatal,
              "a deferred command must have 4x headroom before the kernel's fatal deadline");

static_assert(kUrbCeilingBulk < kUrbWatchdogImporter,
              "the importer must never time out before the exporter: two timeouts "
              "racing to recover a Bulk-Only Transport phase corrupts the filesystem");

static_assert(kKeepaliveMiss < kDetachImporter,
              "DEGRADED must be reachable before surprise removal");

static_assert(kDetachImporter + kDisconnectMax + 1000 < kLeaseExporter,
              "the exporter must not hand the drive back while the importer still "
              "believes it owns the device");

static_assert(kNetCtrl < kUrbCeilingBulk,
              "a control transfer must fail before the bulk ceiling fires");

static_assert(kKeepaliveInterval * 3 <= kKeepaliveMiss,
              "DEGRADED is defined as three missed keepalives");

// T_urb_ceiling_bulk (30 s) is LONGER than T_lease_exporter (20 s), and that is
// not an error in the table — it is a relationship the exporter has to honour
// in code.
//
// The lease timer asks "have we heard from the owner". An importer waiting for
// a transfer it already submitted is silent by design, so a single slow
// WRITE(10) would otherwise trip the lease and quarantine the drive mid-write
// on a peer that was never absent. `ExporterSession::pump()` therefore does not
// run the lease sweep while it owes the peer an answer; the URB ceiling bounds
// how long that can last.
//
// Asserted so that anyone who "fixes" the ordering by shortening the URB
// ceiling, or lengthening the lease, meets this note first.
static_assert(kUrbCeilingBulk > kLeaseExporter,
              "if this ever stops holding, re-read why the lease sweep is "
              "suppressed while transfers are outstanding — the suppression may "
              "no longer be needed, and removing it needs a reason, not a guess");

/// Runtime re-check, callable from a test and from daemon startup. Everything here
/// is also a static_assert; this exists so a build that somehow relaxes one gets
/// caught at launch rather than in the field.
bool assertConsistent() noexcept;

} // namespace airusb::watchdog

#endif // AIRUSB_CORE_WATCHDOG_H
