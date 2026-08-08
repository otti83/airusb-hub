#include "WriteProbe.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace airusb::diag {

namespace {

void wr32le(std::uint8_t* p, std::uint32_t v)
{
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

std::uint32_t rd32le(const std::uint8_t* p)
{
    return static_cast<std::uint32_t>(p[0])
         | (static_cast<std::uint32_t>(p[1]) << 8)
         | (static_cast<std::uint32_t>(p[2]) << 16)
         | (static_cast<std::uint32_t>(p[3]) << 24);
}

/// SCSI CDB fields are BIG endian. Getting this backwards addresses a different
/// part of the medium, which on a write is not a diagnostic problem.
void wr32be(std::uint8_t* p, std::uint32_t v)
{
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

#if defined(__GNUC__) || defined(__clang__)
  #define AIRUSB_WP_PRINTF_LIKE(f, a) __attribute__((format(printf, f, a)))
#else
  #define AIRUSB_WP_PRINTF_LIKE(f, a)
#endif

std::string fmt(const char* f, ...) AIRUSB_WP_PRINTF_LIKE(1, 2);
std::string fmt(const char* f, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, f);
    const int n = std::vsnprintf(buf, sizeof buf, f, ap);
    va_end(ap);
    if (n < 0) return {};
    const int capped = n < static_cast<int>(sizeof buf) ? n : static_cast<int>(sizeof buf) - 1;
    return std::string(buf, static_cast<std::size_t>(capped));
}

constexpr std::uint8_t kRead10  = 0x28;
constexpr std::uint8_t kWrite10 = 0x2A;

} // namespace

// ---------------------------------------------------------------------------

std::uint8_t writePatternByte(std::uint32_t lba, std::uint32_t offsetInBlock) noexcept
{
    // Both coordinates participate, with odd multipliers, so neither a block-level
    // nor a byte-level displacement can reproduce the same value.
    const std::uint32_t v = lba * 2654435761u + offsetInBlock * 40503u + 0xA5u;
    return static_cast<std::uint8_t>((v >> 13) ^ v);
}

std::string WriteProbeResult::summary() const
{
    std::string s = fmt("verdict=%s  outTransfers=%u largestOut=%u bytesWritten=%llu "
                        "mismatched=%u outBoundariesIntact=%s restored=%s\n",
                        passed ? "PASS" : "FAIL",
                        outTransfers, largestOutBytes,
                        static_cast<unsigned long long>(bytesWritten),
                        mismatchedBytes,
                        outBoundariesIntact ? "yes" : "no",
                        restored ? "yes" : "no");
    for (const BotStep& st : steps)
        s += fmt("  %-22s %-4s %-18s %s\n",
                 st.name.c_str(), st.passed ? "ok" : "FAIL",
                 statusName(st.status), st.detail.c_str());
    if (!passed && !failure.empty()) s += "  first failure: " + failure + "\n";
    return s;
}

// ---------------------------------------------------------------------------

void WriteProbe::note(const char* name, const Outcome& r, const std::string& extra)
{
    BotStep st;
    st.name   = name;
    st.status = r.status;
    st.passed = r.ok;
    st.detail = extra.empty() ? r.detail : extra;
    if (_result) {
        _result->steps.push_back(st);
        if (!r.ok && _result->failure.empty())
            _result->failure = fmt("%s: %s", name,
                                   st.detail.empty() ? statusName(r.status) : st.detail.c_str());
    }
}

WriteProbe::Outcome WriteProbe::command(std::span<const std::uint8_t> cdb,
                                        std::uint32_t dataLen,
                                        bool deviceToHost,
                                        std::span<const std::uint8_t> dataOut)
{
    Outcome out;

    if (cdb.empty() || cdb.size() > 16) {
        out.status = Status::BadArgument;
        out.detail = "CDB length out of range";
        return out;
    }
    if (!deviceToHost && dataOut.size() != dataLen) {
        out.status = Status::BadArgument;
        out.detail = "OUT payload does not match the declared length";
        return out;
    }

    ++_tag;

    // ---- CBW ---------------------------------------------------------------
    std::uint8_t cbw[kCbwLength] = {};
    wr32le(cbw + 0, kCbwSignature);
    wr32le(cbw + 4, _tag);
    wr32le(cbw + 8, dataLen);
    cbw[12] = (dataLen > 0 && deviceToHost) ? 0x80u : 0x00u;
    cbw[13] = 0;                                        // LUN 0
    cbw[14] = static_cast<std::uint8_t>(cdb.size());
    std::memcpy(cbw + 15, cdb.data(), cdb.size());

    std::uint32_t moved = 0;
    out.status = _port.bulkOut(_eps.bulkOut, std::span<const std::uint8_t>(cbw, kCbwLength), &moved);
    trace(fmt("CBW  tag=%u op=0x%02x len=%u dir=%s -> %s moved=%u",
              _tag, cdb[0], dataLen, deviceToHost ? "in" : "OUT",
              statusName(out.status), moved));

    if (out.status == Status::XferStall) {
        (void)_port.clearHalt(_eps.bulkOut);
        out.detail = "device stalled the CBW";
        return out;
    }
    if (out.status != Status::Ok) {
        out.detail = fmt("CBW transfer failed: %s", statusName(out.status));
        return out;
    }
    if (moved != kCbwLength) {
        if (_result) _result->outBoundariesIntact = false;
        out.status = Status::XferShort;
        out.detail = fmt("CBW went out as %u of 31 bytes — a logical transfer was split", moved);
        return out;
    }

    // ---- data ---------------------------------------------------------------
    if (dataLen > 0 && !deviceToHost) {
        // The transfer this whole file exists to exercise.
        std::uint32_t wrote = 0;
        const Status ws = _port.bulkOut(_eps.bulkOut, dataOut, &wrote);
        if (_result) {
            ++_result->outTransfers;
            if (dataLen > _result->largestOutBytes) _result->largestOutBytes = dataLen;
        }
        trace(fmt("DATA tag=%u OUT offered=%u -> %s moved=%u",
                  _tag, dataLen, statusName(ws), wrote));

        if (ws == Status::XferStall) {
            (void)_port.clearHalt(_eps.bulkOut);
            out.status = ws;
            out.detail = "device stalled the OUT data phase";
            return out;
        }
        if (ws != Status::Ok) {
            out.status = ws;
            out.detail = fmt("OUT data phase failed: %s", statusName(ws));
            return out;
        }
        if (wrote != dataLen) {
            // The write-side half of OQ-1. A short OUT is not a legal analogue of
            // a short read: the host declared the length in the CBW, so anything
            // less means the layer beneath truncated or split it.
            if (_result) _result->outBoundariesIntact = false;
            out.status = Status::XferShort;
            out.detail = fmt("OUT data went as %u of %u bytes — a logical transfer was split",
                             wrote, dataLen);
            return out;
        }
        if (_result) _result->bytesWritten += dataLen;
    } else if (dataLen > 0) {
        std::vector<std::uint8_t> data;
        const Status ds = _port.bulkIn(_eps.bulkIn, dataLen, data);
        trace(fmt("DATA tag=%u in  offered=%u -> %s got=%llu",
                  _tag, dataLen, statusName(ds),
                  static_cast<unsigned long long>(data.size())));
        if (ds == Status::XferStall) {
            (void)_port.clearHalt(_eps.bulkIn);
            out.status = ds;
            out.detail = "device stalled the IN data phase";
            return out;
        }
        if (ds != Status::Ok && ds != Status::XferShort) {
            out.status = ds;
            out.detail = fmt("IN data phase failed: %s", statusName(ds));
            return out;
        }
        out.data = std::move(data);
    }

    // ---- CSW ----------------------------------------------------------------
    std::vector<std::uint8_t> csw;
    Status cs = _port.bulkIn(_eps.bulkIn, static_cast<std::uint32_t>(kCswLength), csw);
    if (cs == Status::XferStall) {
        (void)_port.clearHalt(_eps.bulkIn);
        csw.clear();
        cs = _port.bulkIn(_eps.bulkIn, static_cast<std::uint32_t>(kCswLength), csw);
    }
    if (cs != Status::Ok && cs != Status::XferShort) {
        out.status = cs;
        out.detail = fmt("CSW read failed: %s", statusName(cs));
        return out;
    }
    if (csw.size() != kCswLength) {
        out.status = Status::XferShort;
        out.detail = fmt("CSW was %llu bytes, expected 13",
                         static_cast<unsigned long long>(csw.size()));
        return out;
    }
    if (rd32le(csw.data()) != kCswSignature) {
        out.status = Status::MalformedFrame;
        out.detail = "CSW signature wrong — the bulk IN stream is out of phase";
        return out;
    }
    if (rd32le(csw.data() + 4) != _tag) {
        out.status = Status::MalformedFrame;
        out.detail = fmt("CSW tag %u, expected %u — the phase machine is desynchronised",
                         rd32le(csw.data() + 4), _tag);
        return out;
    }

    out.residue   = rd32le(csw.data() + 8);
    out.cswStatus = csw[12];
    trace(fmt("CSW  tag=%u -> status=%u residue=%u", _tag, out.cswStatus, out.residue));

    out.ok = (out.cswStatus == 0);
    if (!out.ok) out.detail = fmt("CSW status %u", out.cswStatus);
    return out;
}

WriteProbe::Outcome WriteProbe::read(std::uint32_t lba, std::uint32_t blocks,
                                     std::uint32_t blockSize)
{
    std::uint8_t cdb[10] = {};
    cdb[0] = kRead10;
    wr32be(cdb + 2, lba);
    cdb[7] = static_cast<std::uint8_t>(blocks >> 8);
    cdb[8] = static_cast<std::uint8_t>(blocks & 0xFFu);
    return command(std::span<const std::uint8_t>(cdb, sizeof cdb),
                   blocks * blockSize, true, {});
}

WriteProbe::Outcome WriteProbe::write(std::uint32_t lba, std::uint32_t blocks,
                                      std::uint32_t blockSize,
                                      std::span<const std::uint8_t> payload)
{
    std::uint8_t cdb[10] = {};
    cdb[0] = kWrite10;
    wr32be(cdb + 2, lba);
    cdb[7] = static_cast<std::uint8_t>(blocks >> 8);
    cdb[8] = static_cast<std::uint8_t>(blocks & 0xFFu);
    return command(std::span<const std::uint8_t>(cdb, sizeof cdb),
                   blocks * blockSize, false, payload);
}

// ---------------------------------------------------------------------------

WriteProbeResult WriteProbe::runDestructiveWriteTest(const Options& options)
{
    WriteProbeResult result;
    _result = &result;
    _tag    = 0;

    const std::uint32_t blockSize = options.blockSize;
    if (blockSize == 0 || options.runs.empty()) {
        result.failure = "block size and at least one run are required";
        _result = nullptr;
        return result;
    }

    std::uint32_t maxBlocks = 0;
    for (std::uint32_t b : options.runs) if (b > maxBlocks) maxBlocks = b;

    // ---- save what we are about to destroy ---------------------------------
    const Outcome saved = read(options.startLba, maxBlocks, blockSize);
    note("SAVE_ORIGINAL", saved,
         saved.ok ? fmt("%llu bytes held for restore",
                        static_cast<unsigned long long>(saved.data.size()))
                  : std::string{});
    if (!saved.ok) { _result = nullptr; return result; }
    const std::vector<std::uint8_t> original = saved.data;

    bool allOk = true;

    for (const std::uint32_t blocks : options.runs) {
        const std::uint32_t bytes = blocks * blockSize;

        std::vector<std::uint8_t> payload(bytes);
        for (std::uint32_t b = 0; b < blocks; ++b)
            for (std::uint32_t i = 0; i < blockSize; ++i)
                payload[b * blockSize + i] = writePatternByte(options.startLba + b, i);

        const Outcome w = write(options.startLba, blocks, blockSize, payload);
        note(fmt("WRITE_10_%ublk", blocks).c_str(), w,
             w.ok ? fmt("%u bytes in one transfer", bytes) : std::string{});
        if (!w.ok) { allOk = false; break; }

        const Outcome rb = read(options.startLba, blocks, blockSize);
        if (!rb.ok) {
            note(fmt("READBACK_%ublk", blocks).c_str(), rb);
            allOk = false;
            break;
        }

        // Byte-exact, or say exactly where it first diverged. "Mostly right" is
        // the failure mode that corrupts a filesystem quietly.
        Outcome verdict = rb;
        verdict.ok = true;
        std::string detail;
        if (rb.data.size() != payload.size()) {
            verdict.ok = false;
            detail = fmt("read back %llu bytes, wrote %llu",
                         static_cast<unsigned long long>(rb.data.size()),
                         static_cast<unsigned long long>(payload.size()));
        } else {
            std::uint32_t bad = 0;
            std::size_t firstBad = 0;
            for (std::size_t i = 0; i < payload.size(); ++i) {
                if (rb.data[i] != payload[i]) {
                    if (bad == 0) firstBad = i;
                    ++bad;
                }
            }
            result.mismatchedBytes += bad;
            if (bad != 0) {
                verdict.ok = false;
                detail = fmt("%u of %llu bytes differ, first at offset %llu "
                             "(lba %u + %llu): sent 0x%02x got 0x%02x",
                             bad, static_cast<unsigned long long>(payload.size()),
                             static_cast<unsigned long long>(firstBad),
                             options.startLba + static_cast<std::uint32_t>(firstBad / blockSize),
                             static_cast<unsigned long long>(firstBad % blockSize),
                             payload[firstBad], rb.data[firstBad]);
            } else {
                detail = fmt("%u bytes identical after the round trip", bytes);
            }
        }
        note(fmt("VERIFY_%ublk", blocks).c_str(), verdict, detail);
        if (!verdict.ok) { allOk = false; break; }
    }

    // ---- put it back --------------------------------------------------------
    if (options.restoreOriginal && !original.empty()) {
        const Outcome r = write(options.startLba, maxBlocks, blockSize, original);
        note("RESTORE_ORIGINAL", r);
        result.restored = r.ok;
        if (!r.ok) allOk = false;
    }

    if (!result.outBoundariesIntact) allOk = false;
    result.passed = allOk && result.failure.empty();
    _result = nullptr;
    return result;
}

} // namespace airusb::diag
