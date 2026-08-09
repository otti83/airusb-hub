// AirUSB Hub — a DESTRUCTIVE Bulk-Only Transport write prober.
//
// WHY THIS IS A SEPARATE FILE FROM BotProbe
//
// BotProbe's header promises, without qualification, that pointing it at a drive
// cannot damage its contents. That promise is worth more than the convenience of
// one class, and an opt-in flag would have turned an absolute guarantee into a
// conditional one — the kind a tired person misreads at 2am with a drive attached.
// So the writing instrument is a different type with a different name, and the
// only way to run it is to call a method whose name says what it does.
//
// WHAT IT IS FOR
//
// Until now `bulkOut` has only ever carried 31-byte CBWs. Every data phase this
// project has measured travelled device -> host. That means the exporter's WRITE
// path — host -> device, with a real payload, fragmented across records, flowing
// through the cipher and the credit controller — has never been exercised at all.
//
// It is about to be, and not gently: the Linux importer's first act after
// enumerating is to let the kernel mount a filesystem, and a filesystem writes.
// Discovering a write bug that way means discovering it as corruption on a real
// medium. This probe finds it first, deliberately, against a RAM disk in CI.
//
// WHAT IT CHECKS THAT A ROUND TRIP ALONE WOULD NOT
//
//   * that every OUT transfer left as ONE transfer of exactly the offered length,
//     which is the write-side half of OQ-1
//   * that the bytes read back are byte-identical to the bytes sent, at the LBA
//     they were sent to — a pattern keyed on both LBA and offset, so a write that
//     lands one block or one byte over is a failure rather than a coincidence
//   * that a payload larger than one record still arrives whole, because the
//     record layer has to fragment it and nothing has ever made it do so
//
// It restores what it overwrote, best effort, but a probe that is interrupted
// mid-run cannot. That is the nature of the thing; do not point it at anything
// you care about.
//
// AND THERE IS NO SAFE `startLba`. The caller in tools/ used to say 1024 was
// far enough out to hit free space rather than anything structural; measured
// against a real 32 GB stick, that drive's partition starts at LBA 128, so
// 1024 lands 896 sectors inside its exFAT metadata. Every offset is inside
// something on some medium. What makes this instrument safe to have in the tree
// is that it is a separate type from BotProbe with a method whose name says
// what it does — not the number.

#ifndef AIRUSB_DIAG_WRITEPROBE_H
#define AIRUSB_DIAG_WRITEPROBE_H

#include "BotProbe.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace airusb::diag {

struct WriteProbeResult {
    bool                 passed = false;
    std::string          failure;         ///< first failure, empty on success
    std::vector<BotStep> steps;

    std::uint64_t bytesWritten      = 0;
    std::uint32_t largestOutBytes   = 0;  ///< biggest single OUT data phase that went through
    std::uint32_t outTransfers      = 0;
    std::uint32_t mismatchedBytes   = 0;  ///< read-back bytes that differed from what was sent

    /// The write-side half of OQ-1: every OUT data phase left as exactly one
    /// transfer of the length offered. False means the layer beneath split it.
    bool outBoundariesIntact = true;

    /// Whether the original contents were put back. False after an aborted run.
    bool restored = false;

    std::string summary() const;
};

/// Writes to the medium. Read the file header before using it.
class WriteProbe {
public:
    using Trace = std::function<void(const std::string& line)>;

    struct Options {
        std::uint32_t startLba  = 0;
        std::uint32_t blockSize = 512;
        /// Block counts to exercise, in order.
        ///
        /// The last one is 128 KiB, and the size is chosen against the protocol
        /// rather than picked. 65 519 is Noise's plaintext ceiling and therefore
        /// the largest record this project can ever negotiate, so a 131 072-byte
        /// transfer has to be split across records at ANY legal record size —
        /// not merely at today's 16 640-byte default, which a 16 384-byte run
        /// slid underneath while claiming otherwise. It is also close to what
        /// usb-storage really asks for in one URB (122 880 B at high speed,
        /// 1 MiB at SuperSpeed), so the number a filesystem will produce is the
        /// number the probe produces.
        std::vector<std::uint32_t> runs { 1, 4, 32, 256 };
        bool restoreOriginal = true;
    };

    WriteProbe(IUsbDevicePort& port, const BotEndpoints& endpoints) noexcept
        : _port(port), _eps(endpoints) {}

    void setTrace(Trace t) { _trace = std::move(t); }

    /// Named so it cannot be called by accident or read as harmless.
    /// Never throws; every failure is reported in the result.
    WriteProbeResult runDestructiveWriteTest(const Options& options);

private:
    struct Outcome {
        Status        status    = Status::Ok;
        bool          ok        = false;
        std::uint8_t  cswStatus = 0xFF;
        std::uint32_t residue   = 0;
        std::vector<std::uint8_t> data;   ///< IN data, for reads
        std::string   detail;
    };

    /// READ(10) of `blocks` starting at `lba`.
    Outcome read(std::uint32_t lba, std::uint32_t blocks, std::uint32_t blockSize);

    /// WRITE(10) of `payload`, which must be a whole number of blocks.
    Outcome write(std::uint32_t lba, std::uint32_t blocks, std::uint32_t blockSize,
                  std::span<const std::uint8_t> payload);

    /// CBW, then either an OUT or an IN data phase, then the CSW.
    Outcome command(std::span<const std::uint8_t> cdb,
                    std::uint32_t dataLen,
                    bool deviceToHost,
                    std::span<const std::uint8_t> dataOut);

    void trace(const std::string& line) const { if (_trace) _trace(line); }
    void note(const char* name, const Outcome& r, const std::string& extra = {});

    IUsbDevicePort&  _port;
    BotEndpoints     _eps;
    Trace            _trace;
    std::uint32_t    _tag    = 0;
    WriteProbeResult* _result = nullptr;
};

/// The byte a correct implementation must place at (lba, offset). Keyed on both,
/// so a write that lands one block off — or one byte off — cannot match by luck.
std::uint8_t writePatternByte(std::uint32_t lba, std::uint32_t offsetInBlock) noexcept;

} // namespace airusb::diag

#endif // AIRUSB_DIAG_WRITEPROBE_H
