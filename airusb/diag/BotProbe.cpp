#include "BotProbe.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace airusb::diag {

namespace {

// --- little endian, for the BOT wrappers -------------------------------------

std::uint32_t rd32le(const std::uint8_t* p) noexcept
{
    return static_cast<std::uint32_t>(p[0])
         | (static_cast<std::uint32_t>(p[1]) << 8)
         | (static_cast<std::uint32_t>(p[2]) << 16)
         | (static_cast<std::uint32_t>(p[3]) << 24);
}

void wr32le(std::uint8_t* p, std::uint32_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

// --- big endian, for the SCSI command blocks and their replies ---------------
//
// SCSI is big endian and USB is little endian, in the same 31-byte buffer. This
// is the single easiest place in the whole system to read the wrong LBA.

std::uint32_t rd32be(const std::uint8_t* p) noexcept
{
    return (static_cast<std::uint32_t>(p[0]) << 24)
         | (static_cast<std::uint32_t>(p[1]) << 16)
         | (static_cast<std::uint32_t>(p[2]) << 8)
         |  static_cast<std::uint32_t>(p[3]);
}

void wr32be(std::uint8_t* p, std::uint32_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

void wr16be(std::uint8_t* p, std::uint16_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v);
}

/// SCSI pads its ASCII fields with spaces to a fixed width. Trim them so a
/// reported product string can be compared against what the OS shows.
std::string trimmedAscii(const std::uint8_t* p, std::size_t n)
{
    std::size_t end = n;
    while (end > 0 && (p[end - 1] == ' ' || p[end - 1] == '\0')) --end;
    std::string s;
    s.reserve(end);
    for (std::size_t i = 0; i < end; ++i) {
        const std::uint8_t c = p[i];
        s.push_back((c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.');
    }
    return s;
}

// Tells GCC and Clang to type-check the arguments against the format string.
// MSVC has no equivalent attribute, so it simply gets no extra checking; the
// alternative is dropping it everywhere, which loses a real diagnostic on the
// two compilers that do support it.
#if defined(__GNUC__) || defined(__clang__)
  #define AIRUSB_PRINTF_LIKE(fmtIndex, firstArg) \
      __attribute__((format(printf, fmtIndex, firstArg)))
#else
  #define AIRUSB_PRINTF_LIKE(fmtIndex, firstArg)
#endif

std::string fmt(const char* f, ...) AIRUSB_PRINTF_LIKE(1, 2);
std::string fmt(const char* f, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, f);
    const int n = vsnprintf(buf, sizeof buf, f, ap);
    va_end(ap);
    return (n < 0) ? std::string{} : std::string(buf, static_cast<std::size_t>(n < static_cast<int>(sizeof buf) ? n : static_cast<int>(sizeof buf) - 1));
}

std::string hexHead(const std::vector<std::uint8_t>& v, std::size_t n)
{
    std::string s;
    const std::size_t count = v.size() < n ? v.size() : n;
    for (std::size_t i = 0; i < count; ++i) s += fmt("%02x ", v[i]);
    if (!s.empty()) s.pop_back();
    return s;
}

// --- SCSI opcodes used here. All read-only. ----------------------------------

enum Scsi : std::uint8_t {
    kTestUnitReady  = 0x00,
    kRequestSense   = 0x03,
    kInquiry        = 0x12,
    kReadCapacity10 = 0x25,
    kRead10         = 0x28,
};

} // namespace

// ---------------------------------------------------------------------------
// endpoint discovery
// ---------------------------------------------------------------------------

bool findBotInterface(const DeviceManifest& manifest,
                      std::uint8_t configValue,
                      BotEndpoints& out)
{
    const auto cfg = manifest.configurationByValue(configValue);
    if (cfg.empty()) return false;

    // Pass 1: find the first 08/06/50 interface. Alternate setting 0 only —
    // a BOT device has exactly one, and taking an alt setting we never selected
    // would give us endpoint addresses that are not currently active.
    bool found = false;
    std::uint8_t ifaceNum = 0;
    std::uint8_t altNum   = 0;

    forEachDescriptor(cfg, [&](std::uint8_t type, std::span<const std::uint8_t> d) {
        if (found) return false;                       // stop the walk
        if (type != kDescInterface || d.size() < 9) return true;
        if (d[5] == kMscClass && d[6] == kScsiSubclass && d[7] == kBotProtocol && d[3] == 0) {
            ifaceNum = d[2];
            altNum   = d[3];
            found    = true;
            return false;
        }
        return true;
    });

    if (!found) return false;

    // Pass 2: reuse the manifest's own endpoint parser, which already handles
    // SuperSpeed companion descriptors.
    BotEndpoints eps;
    eps.interfaceNumber = ifaceNum;
    eps.altSetting      = altNum;

    for (const EndpointModel& ep : manifest.endpointsFor(configValue, ifaceNum, altNum)) {
        if (ep.type != XferType::Bulk) continue;
        if (ep.direction() == Dir::In && eps.bulkIn == 0) {
            eps.bulkIn        = ep.address;
            eps.maxPacketSize = ep.maxPacketSize;
        } else if (ep.direction() == Dir::Out && eps.bulkOut == 0) {
            eps.bulkOut = ep.address;
        }
    }

    if (!eps.valid()) return false;
    out = eps;
    return true;
}

// ---------------------------------------------------------------------------
// one BOT command
// ---------------------------------------------------------------------------

BotProbe::CmdOutcome BotProbe::command(std::span<const std::uint8_t> cdb,
                                       std::uint32_t dataLen,
                                       std::uint32_t offerLen)
{
    CmdOutcome out;

    if (cdb.empty() || cdb.size() > 16) {
        out.status = Status::BadArgument;
        out.detail = "CDB length out of range";
        return out;
    }

    ++_tag;

    // ---- CBW ---------------------------------------------------------------
    std::uint8_t cbw[kCbwLength] = {};
    wr32le(cbw + 0, kCbwSignature);
    wr32le(cbw + 4, _tag);
    wr32le(cbw + 8, dataLen);
    cbw[12] = dataLen > 0 ? 0x80u : 0x00u;             // device -> host
    cbw[13] = 0;                                       // LUN 0
    cbw[14] = static_cast<std::uint8_t>(cdb.size());
    std::memcpy(cbw + 15, cdb.data(), cdb.size());

    std::uint32_t moved = 0;
    out.status = _port.bulkOut(_eps.bulkOut, std::span<const std::uint8_t>(cbw, kCbwLength), &moved);
    if (_result) ++_result->cbwCount;
    trace(fmt("CBW  tag=%u op=0x%02x len=%u -> %s moved=%u",
              _tag, cdb[0], dataLen, statusName(out.status), moved));

    if (out.status == Status::XferStall) {
        // A stalled CBW means the device rejected the wrapper itself. Real
        // firmware does this when the CBW is not exactly 31 bytes.
        (void)_port.clearHalt(_eps.bulkOut);
        if (_result) ++_result->stallRecoveries;
        out.detail = "device stalled the CBW — the wrapper was rejected";
        return out;
    }
    if (out.status != Status::Ok) {
        out.detail = fmt("CBW transfer failed: %s", statusName(out.status));
        return out;
    }
    if (moved != kCbwLength) {
        // The one failure this whole probe exists to catch. A CBW is a single
        // 31-byte transfer by definition; anything else means the layer beneath
        // split or truncated a logical URB (open question OQ-1).
        if (_result) _result->transferBoundariesIntact = false;
        out.status = Status::XferShort;
        out.detail = fmt("CBW went out as %u of %llu bytes — a logical transfer was split",
                         moved, static_cast<unsigned long long>(kCbwLength));
        return out;
    }

    // ---- data ---------------------------------------------------------------
    bool shortData = false;
    if (dataLen > 0) {
        std::vector<std::uint8_t> data;
        const Status ds = _port.bulkIn(_eps.bulkIn, offerLen, data);
        if (_result) ++_result->dataPhases;
        trace(fmt("DATA tag=%u offered=%u -> %s got=%llu",
                  _tag, offerLen, statusName(ds),
                  static_cast<unsigned long long>(data.size())));

        if (ds == Status::XferStall) {
            // Legal: the device is refusing the data phase and will still
            // present a CSW once the halt is cleared (BOT 1.0 §6.7.2 case 5).
            (void)_port.clearHalt(_eps.bulkIn);
            if (_result) ++_result->stallRecoveries;
            out.detail = "device stalled the data phase";
        } else if (ds != Status::Ok && ds != Status::XferShort) {
            out.status = ds;
            out.detail = fmt("data phase failed: %s", statusName(ds));
            return out;
        } else {
            // Short is not automatically wrong: a device may legitimately send
            // less than the CBW declared and account for it in the CSW residue.
            // It is only evidence of truncation if the CSW then fails to parse,
            // which is why the fact is carried forward rather than judged here.
            if (data.size() < dataLen) {
                shortData = true;
                if (_result) ++_result->shortReads;
            }
            out.data = std::move(data);
        }
    }

    // ---- CSW ----------------------------------------------------------------
    std::vector<std::uint8_t> csw;
    Status cs = _port.bulkIn(_eps.bulkIn, static_cast<std::uint32_t>(kCswLength), csw);
    if (_result) ++_result->cswCount;

    if (cs == Status::XferStall) {
        // BOT 1.0 §6.7.3: the device may stall once before the CSW. Clearing the
        // halt and reading again is the mandated recovery, not a workaround.
        (void)_port.clearHalt(_eps.bulkIn);
        if (_result) ++_result->stallRecoveries;
        csw.clear();
        cs = _port.bulkIn(_eps.bulkIn, static_cast<std::uint32_t>(kCswLength), csw);
        if (_result) ++_result->cswCount;
    }
    trace(fmt("CSW  tag=%u -> %s got=%llu [%s]",
              _tag, statusName(cs), static_cast<unsigned long long>(csw.size()),
              hexHead(csw, 13).c_str()));

    if (cs != Status::Ok && cs != Status::XferShort) {
        out.status = cs;
        out.detail = fmt("CSW transfer failed: %s", statusName(cs));
        return out;
    }
    if (csw.size() != kCswLength) {
        if (_result) _result->transferBoundariesIntact = false;
        out.status = Status::XferShort;
        out.detail = fmt("CSW came back as %llu bytes, not %llu",
                         static_cast<unsigned long long>(csw.size()),
                         static_cast<unsigned long long>(kCswLength));
        return out;
    }

    // A CSW that is not a CSW means the bulk IN stream is no longer sitting on a
    // transfer boundary. Whatever the proximate cause, a logical transfer was cut
    // or joined somewhere beneath us — which is exactly what
    // transferBoundariesIntact is claiming did not happen.
    const std::uint32_t sig = rd32le(csw.data());
    if (sig != kCswSignature) {
        if (_result) _result->transferBoundariesIntact = false;
        out.status = Status::XferProtocol;
        out.detail = fmt("CSW signature 0x%08x, expected 0x%08x — the bulk IN stream is "
                         "not aligned to a CSW boundary%s",
                         sig, kCswSignature,
                         shortData ? " (the preceding data phase came back short, so a "
                                     "logical transfer was truncated)" : "");
        return out;
    }

    const std::uint32_t echoedTag = rd32le(csw.data() + 4);
    if (echoedTag != _tag) {
        if (_result) _result->transferBoundariesIntact = false;
        out.status = Status::XferProtocol;
        out.detail = fmt("CSW tag %u, expected %u — the phase machine is desynchronised",
                         echoedTag, _tag);
        return out;
    }

    out.residue   = rd32le(csw.data() + 8);
    out.cswStatus = csw[12];
    out.ok        = (out.cswStatus == 0);
    if (!out.ok && out.detail.empty())
        out.detail = fmt("CSW status %u (%s)", out.cswStatus,
                         out.cswStatus == 1 ? "CHECK CONDITION" : "PHASE ERROR");
    return out;
}

void BotProbe::note(const char* name, const CmdOutcome& r)
{
    if (!_result) return;
    BotStep s;
    s.name   = name;
    s.status = r.status;
    s.passed = r.ok;
    s.detail = r.detail;
    _result->steps.push_back(std::move(s));
    if (!r.ok && _result->failure.empty())
        _result->failure = fmt("%s: %s", name,
                               r.detail.empty() ? statusName(r.status) : r.detail.c_str());
}

// ---------------------------------------------------------------------------
// the sequence
// ---------------------------------------------------------------------------

BotProbeResult BotProbe::run()
{
    BotProbeResult result;
    _result = &result;
    _tag    = 0;

    if (!_eps.valid()) {
        result.failure = "no usable bulk IN/OUT endpoint pair";
        _result = nullptr;
        return result;
    }

    trace(fmt("BOT  interface=%u alt=%u bulkIn=0x%02x bulkOut=0x%02x maxPacket=%u",
              _eps.interfaceNumber, _eps.altSetting, _eps.bulkIn, _eps.bulkOut,
              _eps.maxPacketSize));

    // ---- 1. GET_MAX_LUN (class request on ep0, not a BOT command) ----------
    //
    // A device with a single LUN is permitted to STALL this instead of answering
    // (BOT 1.0 §3.2). Treating that stall as a failure would reject most flash
    // drives, so it is recorded as a fact rather than an error.
    {
        SetupPacket sp;
        sp.bmRequestType = 0xA1;                        // IN | class | interface
        sp.bRequest      = 0xFE;                        // GET_MAX_LUN
        sp.wValue        = 0;
        sp.wIndex        = _eps.interfaceNumber;
        sp.wLength       = 1;

        std::vector<std::uint8_t> in;
        const Status st = _port.controlTransfer(sp, {}, in);
        trace(fmt("CTRL GET_MAX_LUN -> %s got=%llu", statusName(st),
                  static_cast<unsigned long long>(in.size())));

        BotStep s;
        s.name   = "GET_MAX_LUN";
        s.status = st;
        if (st == Status::Ok && !in.empty()) {
            result.maxLun = in[0];
            s.passed = true;
            s.detail = fmt("bMaxLUN=%u", in[0]);
        } else if (st == Status::XferStall) {
            result.maxLunStalled = true;
            s.passed = true;                            // legal: single LUN
            s.detail = "stalled — legal, means a single LUN";
            (void)_port.clearHalt(0x80);                // ep0 IN
        } else {
            s.passed = false;
            s.detail = fmt("unexpected: %s", statusName(st));
        }
        result.steps.push_back(s);
        if (!s.passed && result.failure.empty())
            result.failure = "GET_MAX_LUN: " + s.detail;
    }

    // ---- 2. TEST UNIT READY -------------------------------------------------
    {
        const std::uint8_t cdb[6] = { kTestUnitReady, 0, 0, 0, 0, 0 };
        CmdOutcome r = command(cdb, 0, 0);

        if (r.status == Status::Ok && !r.ok && r.cswStatus == 1) {
            // CHECK CONDITION on the first command is normal: many drives report
            // a pending unit-attention after enumeration. Drain it and retry once.
            const std::uint8_t sense[6] = { kRequestSense, 0, 0, 0, 18, 0 };
            const CmdOutcome sr = command(sense, 18, 18);
            if (sr.ok && sr.data.size() >= 14)
                trace(fmt("SENSE key=0x%01x asc=0x%02x ascq=0x%02x",
                          sr.data[2] & 0x0Fu, sr.data[12], sr.data[13]));
            r = command(cdb, 0, 0);
            if (r.ok) r.detail = "ready after draining one unit-attention";
        }
        note("TEST_UNIT_READY", r);
        if (!r.ok) { _result = nullptr; return result; }
    }

    // ---- 3. INQUIRY ---------------------------------------------------------
    {
        const std::uint8_t cdb[6] = { kInquiry, 0, 0, 0, 36, 0 };
        const CmdOutcome r = command(cdb, 36, 36);
        if (r.ok && r.data.size() >= 36) {
            result.peripheralDeviceType = static_cast<std::uint8_t>(r.data[0] & 0x1Fu);
            result.removableMedium      = (r.data[1] & 0x80u) != 0;
            result.vendor   = trimmedAscii(r.data.data() + 8, 8);
            result.product  = trimmedAscii(r.data.data() + 16, 16);
            result.revision = trimmedAscii(r.data.data() + 32, 4);
        }
        CmdOutcome annotated = r;
        if (r.ok) {
            if (r.data.size() < 36) {
                annotated.ok     = false;
                annotated.detail = fmt("INQUIRY returned %llu of 36 bytes",
                                       static_cast<unsigned long long>(r.data.size()));
            } else {
                annotated.detail = fmt("'%s' '%s' rev '%s' type=0x%02x removable=%s",
                                       result.vendor.c_str(), result.product.c_str(),
                                       result.revision.c_str(), result.peripheralDeviceType,
                                       result.removableMedium ? "yes" : "no");
            }
        }
        note("INQUIRY", annotated);
        if (!annotated.ok) { _result = nullptr; return result; }
    }

    // ---- 4. READ CAPACITY(10) ----------------------------------------------
    {
        const std::uint8_t cdb[10] = { kReadCapacity10, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        const CmdOutcome r = command(cdb, 8, 8);
        CmdOutcome annotated = r;
        if (r.ok) {
            if (r.data.size() < 8) {
                annotated.ok     = false;
                annotated.detail = fmt("READ CAPACITY returned %llu of 8 bytes",
                                       static_cast<unsigned long long>(r.data.size()));
            } else {
                // Byte 0..3 is the LAST LBA, not the block count. Off-by-one here
                // reads past the end of the medium on the final block.
                result.lastLba   = rd32be(r.data.data());
                result.blockSize = rd32be(r.data.data() + 4);
                annotated.detail = fmt("lastLBA=%llu blockSize=%u -> %llu blocks, %.2f GB",
                                       static_cast<unsigned long long>(result.lastLba),
                                       result.blockSize,
                                       static_cast<unsigned long long>(result.blockCount()),
                                       static_cast<double>(result.blockCount()) *
                                       static_cast<double>(result.blockSize) / 1e9);
                if (result.blockSize == 0 || result.blockSize > 65536) {
                    annotated.ok     = false;
                    annotated.detail = fmt("implausible block size %u", result.blockSize);
                }
            }
        }
        note("READ_CAPACITY_10", annotated);
        if (!annotated.ok) { _result = nullptr; return result; }
    }

    const std::uint32_t bs = result.blockSize;

    // ---- 5. READ(10) LBA 0, exact offer ------------------------------------
    {
        std::uint8_t cdb[10] = { kRead10, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        wr32be(cdb + 2, 0);                              // LBA 0
        wr16be(cdb + 7, 1);                              // one block
        const CmdOutcome r = command(cdb, bs, bs);
        CmdOutcome annotated = r;
        if (r.ok) {
            result.sector0 = r.data;
            if (r.data.size() != bs) {
                annotated.ok = false;
                annotated.detail = fmt("read %llu of %u bytes with residue %u",
                                       static_cast<unsigned long long>(r.data.size()),
                                       bs, r.residue);
            } else {
                result.sector0HasBootSignature =
                    (bs >= 512 && r.data[510] == 0x55 && r.data[511] == 0xAA);
                annotated.detail = fmt("%u bytes, residue=%u, bootsig=%s, head=[%s]",
                                       bs, r.residue,
                                       result.sector0HasBootSignature ? "55AA" : "none",
                                       hexHead(r.data, 16).c_str());
            }
        }
        note("READ_10_LBA0", annotated);
        if (!annotated.ok) { _result = nullptr; return result; }
    }

    // ---- 6. short-read fidelity --------------------------------------------
    //
    // Ask the device for one block but offer a buffer half a kilobyte larger. A
    // correct transport reports exactly one block and leaves the rest untouched.
    // A transport that pads, or that reports the offered length as the actual
    // length, corrupts every short read a filesystem ever performs.
    {
        std::uint8_t cdb[10] = { kRead10, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        wr32be(cdb + 2, 0);
        wr16be(cdb + 7, 1);
        const CmdOutcome r = command(cdb, bs, bs + 512u);
        CmdOutcome annotated = r;
        if (r.ok) {
            if (r.data.size() != bs) {
                annotated.ok = false;
                annotated.detail = fmt("offered %u, expected exactly %u back, got %llu",
                                       bs + 512u, bs,
                                       static_cast<unsigned long long>(r.data.size()));
            } else if (!result.sector0.empty() && r.data != result.sector0) {
                annotated.ok = false;
                annotated.detail = "same LBA read twice returned different data";
            } else {
                annotated.detail = fmt("offered %u, device sent %u — short read preserved",
                                       bs + 512u, bs);
            }
        }
        note("SHORT_READ_FIDELITY", annotated);
        if (!annotated.ok) { _result = nullptr; return result; }
    }

    // ---- 7. multi-block read in ONE logical transfer ------------------------
    //
    // This is the OQ-1 measurement. Four blocks is 2048 bytes, which is two
    // maximum-size SuperSpeed bulk packets plus change, so a transport that
    // fragments at the packet boundary and reports each fragment separately
    // shows up here as a short data phase with a nonzero residue.
    if (result.blockCount() >= 4) {
        std::uint8_t cdb[10] = { kRead10, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        wr32be(cdb + 2, 0);
        wr16be(cdb + 7, 4);
        const std::uint32_t want = bs * 4u;
        const CmdOutcome r = command(cdb, want, want);
        CmdOutcome annotated = r;
        if (r.ok) {
            if (r.data.size() != want) {
                annotated.ok = false;
                annotated.detail = fmt("asked for %u bytes in one transfer, got %llu "
                                       "(residue %u) — the transfer was fragmented",
                                       want,
                                       static_cast<unsigned long long>(r.data.size()),
                                       r.residue);
                result.transferBoundariesIntact = false;
            } else if (!result.sector0.empty() &&
                       !std::equal(result.sector0.begin(), result.sector0.end(), r.data.begin())) {
                annotated.ok = false;
                annotated.detail = "block 0 differs between the single-block and "
                                   "four-block reads";
            } else {
                annotated.detail = fmt("%u bytes in one transfer, residue=%u", want, r.residue);
            }
        }
        note("READ_10_MULTIBLOCK", annotated);
        if (!annotated.ok) { _result = nullptr; return result; }
    }

    result.passed = result.failure.empty() && result.transferBoundariesIntact;
    _result = nullptr;
    return result;
}

// ---------------------------------------------------------------------------

std::string BotProbeResult::summary() const
{
    std::string s;
    s += fmt("verdict=%s  cbw=%u data=%u csw=%u stallRecoveries=%u shortReads=%u "
             "boundariesIntact=%s\n",
             passed ? "PASS" : "FAIL", cbwCount, dataPhases, cswCount,
             stallRecoveries, shortReads, transferBoundariesIntact ? "yes" : "no");
    for (const BotStep& st : steps) {
        s += fmt("  %-22s %-4s %-18s %s\n", st.name.c_str(),
                 st.passed ? "ok" : "FAIL", statusName(st.status), st.detail.c_str());
    }
    if (!failure.empty()) s += fmt("  first failure: %s\n", failure.c_str());
    return s;
}

} // namespace airusb::diag
