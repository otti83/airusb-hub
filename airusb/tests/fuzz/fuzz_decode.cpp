// libFuzzer target over decode + validate (P1 plan §8.1, P2.0).
//
// The contract this asserts is simple and absolute: for ANY byte string, the
// decode/validate path must not crash, must not read out of bounds, and must not
// allocate based on a peer-supplied length. It either produces a well-formed
// message or a Verdict naming the rule that rejected it.
//
// Build:
//   clang++ -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined \
//     tests/fuzz/fuzz_decode.cpp protocol/Codec.cpp protocol/Validate.cpp \
//     core/Status.cpp -o fuzz_decode
// Run:
//   ./fuzz_decode -max_len=4096 tests/vectors/

#include "../../protocol/Codec.h"
#include "../../protocol/Validate.h"

#include <cstddef>
#include <cstdint>
#include <span>

using namespace airusb;
using namespace airusb::protocol;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    std::span<const std::uint8_t> in(data, size);

    Limits lim;
    lim.maxRecordBytes   = wire::kRecordBytesDefault;
    lim.maxTransferBytes = wire::kTransferBytesDefault;
    lim.maxSegmentBytes  = wire::kSegmentBytesDefault;
    lim.maxIsoPackets    = 128;

    // Walk the input as a coalesced record: header, body, header, body, ...
    // exactly as RxStrand does. This exercises the "leftover bytes are fatal"
    // path as well as every per-type decoder.
    std::size_t at = 0;
    for (int guard = 0; guard < 64 && at < in.size(); ++guard) {
        Header h;
        if (!decodeHeader(in.subspan(at), h)) break;
        at += wire::kHeaderSize;

        const std::size_t available = in.size() - at;

        Verdict v = validateHeader(h, available, lim);
        if (!v.ok()) break;

        // validateHeader already established bodyLen <= available for known types.
        bool known = false;
        const std::size_t fixed = wire::fixedBodySize(h.type, &known);
        if (!known) {
            if (h.bodyLen > available) break;
            at += h.bodyLen;
            continue;
        }
        if (h.bodyLen > available || h.bodyLen < fixed) break;

        auto body = in.subspan(at, h.bodyLen);
        auto dataSection = body.subspan(fixed);

        switch (static_cast<wire::Type>(h.type)) {
            case wire::Type::Submit: {
                SubmitBody b;
                if (decodeSubmit(body, b)) {
                    Verdict sv = validateSubmit(h, b, dataSection, lim);
                    // A passing SUBMIT must satisfy the exactness rule, so the
                    // payload span implied by the body is inside the buffer.
                    if (sv.ok() && b.dir == static_cast<std::uint8_t>(wire::Dir::Out)) {
                        const std::uint64_t need =
                            static_cast<std::uint64_t>(b.isoPktCount) * wire::kIsoDescSize
                            + b.bufferLen;
                        if (need != h.totalLen) __builtin_trap();   // R4 escaped
                    }
                }
                break;
            }
            case wire::Type::Complete: {
                CompleteBody b;
                if (decodeComplete(body, b)) {
                    Verdict cv = validateComplete(h, b, dataSection, lim);
                    // R5 is the memory-safety-critical rule: if it passed, the
                    // exporter cannot claim more bytes than the importer's kernel
                    // buffer holds. Assert it actually held.
                    if (cv.ok() && b.actualLen > b.requestedLen) __builtin_trap();
                }
                break;
            }
            case wire::Type::Hello:
            case wire::Type::HelloOk: {
                HelloBody b;
                (void)decodeHello(body, b);
                break;
            }
            default:
                break;
        }

        // TLV tails must never over-read.
        (void)forEachTlv(dataSection, [](const TlvView& t) {
            (void)isValidUtf8(t.value);
            return true;
        });

        at += h.bodyLen;
    }

    return 0;
}
