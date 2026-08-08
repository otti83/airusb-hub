#include "ScriptedDevice.h"

#include <cstring>

namespace airusb::fakes {

namespace {

std::uint32_t rd32le(const std::uint8_t* p) noexcept
{
    return static_cast<std::uint32_t>(p[0])
         | (static_cast<std::uint32_t>(p[1]) << 8)
         | (static_cast<std::uint32_t>(p[2]) << 16)
         | (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint32_t rd32be(const std::uint8_t* p) noexcept
{
    // SCSI CDB fields are BIG endian, unlike everything else in USB. Getting this
    // backwards reads the wrong LBA and silently corrupts the wrong blocks.
    return (static_cast<std::uint32_t>(p[0]) << 24)
         | (static_cast<std::uint32_t>(p[1]) << 16)
         | (static_cast<std::uint32_t>(p[2]) << 8)
         |  static_cast<std::uint32_t>(p[3]);
}

void wr32le(std::uint8_t* p, std::uint32_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

void wr32be(std::uint8_t* p, std::uint32_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

enum Scsi : std::uint8_t {
    kTestUnitReady = 0x00,
    kRequestSense  = 0x03,
    kInquiry       = 0x12,
    kModeSense6    = 0x1A,
    kStartStopUnit = 0x1B,
    kPreventAllow  = 0x1E,
    kReadCapacity10= 0x25,
    kRead10        = 0x28,
    kWrite10       = 0x2A,
};

} // namespace

// ---------------------------------------------------------------------------

ScriptedDevice::ScriptedDevice(std::uint32_t blockCount, std::uint32_t blockSize)
    : _blockSize(blockSize), _blockCount(blockCount)
{
    _media.assign(static_cast<std::size_t>(blockCount) * blockSize, 0);

    // Mirrors the real 058f:6387 measured in P1: SuperSpeed, bMaxPacketSize0 = 9
    // (2^9 = 512), one config, one BOT interface, two 1024-byte bulk endpoints
    // with SuperSpeed companions.
    _manifest.setSpeed(Speed::Super);

    const std::uint8_t dev[18] = {
        18, kDescDevice, 0x20, 0x03, 0x00, 0x00, 0x00, 9,
        0x8f, 0x05, 0x87, 0x63, 0x02, 0x00, 1, 2, 3, 1
    };
    _manifest.setDeviceDescriptor(dev);

    const std::uint8_t cfg[44] = {
        9, kDescConfiguration, 44, 0, 1, 1, 0, 0x80, 50,
        9, kDescInterface, 0, 0, 2, 0x08, 0x06, 0x50, 0,
        7, kDescEndpoint, 0x81, 0x02, 0x00, 0x04, 0,
        6, kDescSsEndpointCompanion, 15, 0, 0, 0,
        7, kDescEndpoint, 0x02, 0x02, 0x00, 0x04, 0,
        6, kDescSsEndpointCompanion, 15, 0, 0, 0,
    };
    _manifest.addConfiguration(cfg);

    const std::uint8_t bos[5] = { 5, kDescBos, 5, 0, 0 };
    _manifest.setBos(bos);

    const std::uint16_t langs[1] = { 0x0409 };
    _manifest.setLangIds(langs);
    const std::uint8_t prod[14] = { 14, kDescString, 'A',0,'i',0,'r',0,'U',0,'S',0,'B',0 };
    _manifest.addString(2, 0x0409, prod);
}

void ScriptedDevice::fillPattern(std::uint64_t seed)
{
    std::uint64_t x = seed ? seed : 1;
    for (auto& b : _media) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        b = static_cast<std::uint8_t>(x);
    }
}

std::uint64_t ScriptedDevice::checksum() const noexcept
{
    // FNV-1a. Enough to detect a corrupted block; not a security hash.
    std::uint64_t h = 1469598103934665603ull;
    for (std::uint8_t b : _media) { h ^= b; h *= 1099511628211ull; }
    return h;
}

void ScriptedDevice::clearHalt(std::uint8_t epAddr) noexcept
{
    if (epAddr & 0x80u) _inHalted = false; else _outHalted = false;
}

void ScriptedDevice::reset() noexcept
{
    // Bulk-Only Mass Storage Reset returns the phase machine to its start but does
    // NOT clear the endpoint halts -- the host must still issue CLEAR_FEATURE on
    // both pipes. Getting this wrong makes recovery appear to work in a fake and
    // hang against real firmware.
    _phase = BotPhase::AwaitingCbw;
    _pendingIn.clear();
    _residue = 0;
    _cswStatus = 0;
}

// ---------------------------------------------------------------------------

Status ScriptedDevice::controlTransfer(const SetupPacket& s,
                                       std::span<const std::uint8_t> dataOut,
                                       std::vector<std::uint8_t>& dataIn)
{
    dataIn.clear();

    // Class requests, interface recipient: the two the BOT spec defines.
    if (s.isClass() && s.recipient() == kRcpInterface) {
        if (s.bRequest == 0xFF) { reset(); return Status::Ok; }        // BOT reset
        if (s.bRequest == 0xFE) { dataIn.assign(1, 0); return Status::Ok; }  // GET_MAX_LUN
        return Status::XferStall;
    }

    if (!s.isStandard()) return Status::XferStall;

    switch (s.bRequest) {
        case kGetStatus: {
            std::uint16_t st = 0;
            if (s.recipient() == kRcpEndpoint) {
                const std::uint8_t ep = static_cast<std::uint8_t>(s.wIndex & 0xFFu);
                const bool halted = (ep & 0x80u) ? _inHalted : _outHalted;
                st = halted ? 1u : 0u;
            }
            dataIn = { static_cast<std::uint8_t>(st & 0xFFu),
                       static_cast<std::uint8_t>(st >> 8) };
            return Status::Ok;
        }
        case kClearFeature:
            if (s.recipient() == kRcpEndpoint && s.wValue == kFeatEndpointHalt)
                clearHalt(static_cast<std::uint8_t>(s.wIndex & 0xFFu));
            return Status::Ok;
        case kSetFeature:
            if (s.recipient() == kRcpEndpoint && s.wValue == kFeatEndpointHalt) {
                const std::uint8_t ep = static_cast<std::uint8_t>(s.wIndex & 0xFFu);
                if (ep & 0x80u) _inHalted = true; else _outHalted = true;
            }
            return Status::Ok;
        case kSetConfiguration:
        case kSetInterface:
        case kSetAddress:
            return Status::Ok;
        case kGetDescriptor: {
            const std::uint8_t type  = static_cast<std::uint8_t>(s.wValue >> 8);
            const std::uint8_t index = static_cast<std::uint8_t>(s.wValue & 0xFFu);
            std::span<const std::uint8_t> blob;
            switch (type) {
                case kDescDevice:        blob = _manifest.deviceDescriptor(); break;
                case kDescConfiguration: blob = _manifest.configurationByIndex(index); break;
                case kDescBos:           blob = _manifest.bos(); break;
                case kDescString:        blob = _manifest.stringDescriptor(index, s.wIndex); break;
                default:                 return Status::XferStall;
            }
            if (blob.empty()) return Status::XferStall;
            const std::size_t n = blob.size() < s.wLength ? blob.size() : s.wLength;
            dataIn.assign(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(n));
            return Status::Ok;
        }
        default:
            (void)dataOut;
            return Status::XferStall;
    }
}

// ---------------------------------------------------------------------------

Status ScriptedDevice::handleCbw(std::span<const std::uint8_t> cbw)
{
    // A CBW that is not exactly 31 bytes is not a CBW. Real firmware stalls both
    // pipes here and waits for a reset; accepting a truncated one is how a fake
    // hides a transfer-splitting bug in the layer above.
    if (cbw.size() != kCbwLength) { _inHalted = _outHalted = true; return Status::XferStall; }
    if (rd32le(cbw.data()) != kCbwSignature) {
        _inHalted = _outHalted = true;
        return Status::XferStall;
    }

    _tag         = rd32le(cbw.data() + 4);
    _expectedLen = rd32le(cbw.data() + 8);
    _dataIn      = (cbw[12] & 0x80u) != 0;
    _cdbLen      = static_cast<std::uint8_t>(cbw[14] & 0x1Fu);
    std::memset(_cdb, 0, sizeof(_cdb));
    std::memcpy(_cdb, cbw.data() + 15, _cdbLen > 16 ? 16 : _cdbLen);

    ++_commands;
    return executeScsi();
}

Status ScriptedDevice::executeScsi()
{
    _pendingIn.clear();
    _cswStatus = 0;
    _residue   = 0;

    if (_faults.stallOnCommand == _commands) {
        if (_dataIn) _inHalted = true; else _outHalted = true;
        _cswStatus = 0x01;
        _phase = BotPhase::AwaitingCswRead;
        _residue = _expectedLen;
        return Status::XferStall;
    }
    if (_faults.checkConditionOnCommand == _commands) {
        _cswStatus = 0x01;                       // CHECK CONDITION
        _sense[0] = 0x70; _sense[2] = 0x02;      // NOT READY
        _phase = BotPhase::AwaitingCswRead;
        _residue = _expectedLen;
        return Status::Ok;
    }

    switch (_cdb[0]) {
        case kTestUnitReady:
        case kStartStopUnit:
        case kPreventAllow:
            _phase = BotPhase::AwaitingCswRead;
            return Status::Ok;

        case kRequestSense: {
            _pendingIn.assign(_sense, _sense + 18);
            _phase = BotPhase::Data;
            return Status::Ok;
        }

        case kInquiry: {
            _pendingIn.assign(36, 0);
            _pendingIn[0] = 0x00;                // direct access block device
            _pendingIn[1] = 0x80;                // removable
            _pendingIn[2] = 0x06;                // SPC-4
            _pendingIn[3] = 0x02;
            _pendingIn[4] = 31;
            std::memcpy(_pendingIn.data() + 8,  "AirUSB  ", 8);
            std::memcpy(_pendingIn.data() + 16, "Scripted Device ", 16);
            std::memcpy(_pendingIn.data() + 32, "0001", 4);
            _phase = BotPhase::Data;
            return Status::Ok;
        }

        case kModeSense6: {
            _pendingIn.assign(4, 0);
            _pendingIn[0] = 3;
            _phase = BotPhase::Data;
            return Status::Ok;
        }

        case kReadCapacity10: {
            _pendingIn.assign(8, 0);
            wr32be(_pendingIn.data(),     _blockCount - 1);   // LAST LBA, not count
            wr32be(_pendingIn.data() + 4, _blockSize);
            _phase = BotPhase::Data;
            return Status::Ok;
        }

        case kRead10: {
            const std::uint32_t lba = rd32be(_cdb + 2);
            const std::uint32_t n   = static_cast<std::uint32_t>((_cdb[7] << 8) | _cdb[8]);
            if (static_cast<std::uint64_t>(lba) + n > _blockCount) {
                _cswStatus = 0x01;
                _sense[0] = 0x70; _sense[2] = 0x05; _sense[12] = 0x21;  // LBA out of range
                _phase = BotPhase::AwaitingCswRead;
                _residue = _expectedLen;
                return Status::Ok;
            }
            const std::size_t off = static_cast<std::size_t>(lba) * _blockSize;
            std::size_t len = static_cast<std::size_t>(n) * _blockSize;
            if (_faults.shortReadOnCommand == _commands && len > _blockSize)
                len -= _blockSize;
            _pendingIn.assign(_media.begin() + static_cast<std::ptrdiff_t>(off),
                              _media.begin() + static_cast<std::ptrdiff_t>(off + len));
            _phase = BotPhase::Data;
            return Status::Ok;
        }

        case kWrite10:
            _phase = BotPhase::Data;
            return Status::Ok;

        default:
            _cswStatus = 0x01;
            _sense[0] = 0x70; _sense[2] = 0x05; _sense[12] = 0x20;   // invalid op
            _phase = BotPhase::AwaitingCswRead;
            _residue = _expectedLen;
            return Status::Ok;
    }
}

Status ScriptedDevice::bulkOut(std::span<const std::uint8_t> data, std::uint32_t* actualLen)
{
    if (actualLen) *actualLen = 0;
    if (_outHalted) return Status::XferStall;

    if (_phase == BotPhase::AwaitingCbw) {
        Status s = handleCbw(data);
        if (actualLen) *actualLen = static_cast<std::uint32_t>(data.size());
        return s;
    }

    if (_phase == BotPhase::Data && _cdb[0] == kWrite10) {
        const std::uint32_t lba = rd32be(_cdb + 2);
        const std::uint32_t n   = static_cast<std::uint32_t>((_cdb[7] << 8) | _cdb[8]);
        const std::size_t off   = static_cast<std::size_t>(lba) * _blockSize;
        const std::size_t want  = static_cast<std::size_t>(n) * _blockSize;

        if (static_cast<std::uint64_t>(lba) + n > _blockCount || data.size() > want)
            return Status::XferStall;

        std::memcpy(_media.data() + off, data.data(), data.size());
        if (actualLen) *actualLen = static_cast<std::uint32_t>(data.size());

        if (data.size() == want) {
            _phase = BotPhase::AwaitingCswRead;
        }
        return Status::Ok;
    }

    return Status::XferStall;
}

Status ScriptedDevice::bulkIn(std::uint32_t maxLen, std::vector<std::uint8_t>& out)
{
    out.clear();
    if (_inHalted) return Status::XferStall;

    if (_phase == BotPhase::Data) {
        const std::size_t n = _pendingIn.size() < maxLen ? _pendingIn.size() : maxLen;
        out.assign(_pendingIn.begin(), _pendingIn.begin() + static_cast<std::ptrdiff_t>(n));
        _pendingIn.erase(_pendingIn.begin(), _pendingIn.begin() + static_cast<std::ptrdiff_t>(n));
        if (_pendingIn.empty()) {
            _residue = _expectedLen > out.size()
                     ? _expectedLen - static_cast<std::uint32_t>(out.size()) : 0;
            _phase = BotPhase::AwaitingCswRead;
        }
        return Status::Ok;
    }

    if (_phase == BotPhase::AwaitingCswRead) {
        if (maxLen < kCswLength) return Status::XferStall;
        out.assign(kCswLength, 0);
        wr32le(out.data(),     kCswSignature);
        wr32le(out.data() + 4, _tag);
        wr32le(out.data() + 8, _residue);
        out[12] = _cswStatus;
        _phase = BotPhase::AwaitingCbw;
        return Status::Ok;
    }

    return Status::XferStall;
}

} // namespace airusb::fakes
