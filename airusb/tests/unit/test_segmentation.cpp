// Splitting a transfer across records, and putting it back exactly.
//
// A record cannot exceed Noise's 65 519-byte plaintext ceiling and usb-storage
// asks for a megabyte in one URB, so this is not optional and not a tuning
// parameter. What makes it dangerous is that reassembly feeds a buffer which is
// then written to a disk: a gap between segments leaves uninitialised bytes in
// it, and an overlap lets a peer rewrite bytes we already accepted.
//
// So the contiguity rule here is EXACT — each segment must begin precisely where
// the last ended — and most of this file is about what happens when a peer
// declines to do that.

#include "../TestHarness.h"
#include "../../protocol/Segmentation.h"

#include <numeric>

using namespace airusb;
using namespace airusb::protocol;

namespace {

Header hdr(std::uint16_t channel, std::uint64_t requestId,
           std::uint32_t totalLen, std::uint32_t segOffset,
           bool first, bool more)
{
    Header h;
    h.type      = static_cast<std::uint8_t>(wire::Type::Complete);
    h.channel   = channel;
    h.requestId = requestId;
    h.totalLen  = totalLen;
    h.segOffset = segOffset;
    h.flags     = static_cast<std::uint8_t>((first ? wire::kFlagSegFirst : 0) |
                                            (more  ? wire::kFlagSegMore  : 0));
    return h;
}

std::vector<std::uint8_t> pattern(std::size_t n, std::uint8_t salt = 0)
{
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i)
        v[i] = static_cast<std::uint8_t>((i * 31u + salt * 7u + (i >> 8)) & 0xFF);
    return v;
}

void testPlanning()
{
    std::printf("planning the split\n");

    TEST_CASE("a transfer that fits is one segment, flagged first and final") {
        const auto p = planSegments(1000, 16384);
        CHECK_EQ(p.size(), 1u);
        CHECK_EQ(p[0].offset, 0u);
        CHECK_EQ(p[0].length, 1000u);
        CHECK(p[0].first);
        CHECK(!p[0].more);
    }

    TEST_CASE("a zero-length transfer still produces one record") {
        // It is how a host terminates a transfer that is an exact multiple of the
        // packet size. Swallowing it here would lose a real wire event.
        const auto p = planSegments(0, 16384);
        CHECK_EQ(p.size(), 1u);
        CHECK_EQ(p[0].length, 0u);
        CHECK(p[0].first);
        CHECK(!p[0].more);
    }

    TEST_CASE("a megabyte at the record ceiling splits into contiguous pieces") {
        // usb-storage on a SuperSpeed link really does ask for this.
        const std::uint32_t total = 1u << 20;
        const auto p = planSegments(total, 65519);
        CHECK(p.size() > 16u);

        std::uint32_t seen = 0;
        for (std::size_t i = 0; i < p.size(); ++i) {
            CHECK_EQ(p[i].offset, seen);
            CHECK(p[i].length <= 65519u);
            CHECK_EQ(p[i].first, i == 0);
            CHECK_EQ(p[i].more, i + 1 < p.size());
            seen += p[i].length;
        }
        CHECK_EQ(seen, total);
    }

    TEST_CASE("an exact multiple does not produce a trailing empty segment") {
        const auto p = planSegments(32768, 16384);
        CHECK_EQ(p.size(), 2u);
        CHECK_EQ(p[1].length, 16384u);
        CHECK(!p[1].more);
    }
}

void testRoundTrip()
{
    std::printf("round trip\n");

    TEST_CASE("what goes out in pieces comes back identical") {
        const std::uint32_t total = 300'000;
        const auto data = pattern(total);
        const auto plan = planSegments(total, 65519);

        Reassembler r;
        Status err = Status::Ok;
        Reassembler::Outcome o = Reassembler::Outcome::NeedMore;

        for (const SegmentPlan& s : plan) {
            const Header h = hdr(7, 42, total, s.offset, s.first, s.more);
            o = r.accept(h, std::span<const std::uint8_t>(data).subspan(s.offset, s.length), err);
            if (s.more) CHECK(o == Reassembler::Outcome::NeedMore);
        }
        CHECK(o == Reassembler::Outcome::Complete);

        const auto out = r.take(hdr(7, 42, total, 0, false, false));
        CHECK_EQ(out.size(), data.size());
        CHECK(out == data);
        CHECK_EQ(r.bytesHeld(), 0u);
        CHECK_EQ(r.inFlight(), 0u);
    }

    TEST_CASE("an unsegmented message completes immediately") {
        // No flags at all is a complete transfer of one segment, and a caller
        // should not have to special-case it.
        Reassembler r;
        Status err = Status::Ok;
        const auto data = pattern(64);
        const Header h = hdr(1, 1, 64, 0, false, false);
        CHECK(r.accept(h, data, err) == Reassembler::Outcome::Complete);
        CHECK(r.take(h) == data);
    }

    TEST_CASE("two transfers on different channels interleave without mixing") {
        Reassembler r;
        Status err = Status::Ok;
        const auto a = pattern(200, 1);
        const auto b = pattern(200, 2);

        CHECK(r.accept(hdr(1, 5, 200, 0,   true,  true), std::span(a).subspan(0, 100), err)
              == Reassembler::Outcome::NeedMore);
        CHECK(r.accept(hdr(2, 5, 200, 0,   true,  true), std::span(b).subspan(0, 100), err)
              == Reassembler::Outcome::NeedMore);
        CHECK_EQ(r.inFlight(), 2u);

        CHECK(r.accept(hdr(2, 5, 200, 100, false, false), std::span(b).subspan(100), err)
              == Reassembler::Outcome::Complete);
        CHECK(r.take(hdr(2, 5, 200, 0, false, false)) == b);

        CHECK(r.accept(hdr(1, 5, 200, 100, false, false), std::span(a).subspan(100), err)
              == Reassembler::Outcome::Complete);
        CHECK(r.take(hdr(1, 5, 200, 0, false, false)) == a);
        CHECK_EQ(r.bytesHeld(), 0u);
    }
}

void testHostilePeer()
{
    std::printf("what a hostile peer sends\n");

    TEST_CASE("a gap between segments is refused, not filled") {
        // The bytes in a gap would be uninitialised in a buffer about to be
        // written to a disk.
        Reassembler r;
        Status err = Status::Ok;
        const auto d = pattern(300);
        CHECK(r.accept(hdr(1, 1, 300, 0, true, true), std::span(d).subspan(0, 100), err)
              == Reassembler::Outcome::NeedMore);
        CHECK(r.accept(hdr(1, 1, 300, 200, false, false), std::span(d).subspan(200, 100), err)
              == Reassembler::Outcome::Rejected);
        CHECK(err == Status::MalformedFrame);
        CHECK_EQ(r.bytesHeld(), 0u);        // and the arena is released
    }

    TEST_CASE("an overlap is refused, so accepted bytes cannot be rewritten") {
        Reassembler r;
        Status err = Status::Ok;
        const auto d = pattern(300);
        CHECK(r.accept(hdr(1, 1, 300, 0, true, true), std::span(d).subspan(0, 200), err)
              == Reassembler::Outcome::NeedMore);
        CHECK(r.accept(hdr(1, 1, 300, 100, false, false), std::span(d).subspan(100, 200), err)
              == Reassembler::Outcome::Rejected);
    }

    TEST_CASE("a continuation for a transfer that never started is refused") {
        Reassembler r;
        Status err = Status::Ok;
        const auto d = pattern(100);
        CHECK(r.accept(hdr(1, 1, 200, 0, false, true), d, err)
              == Reassembler::Outcome::Rejected);
        CHECK(err == Status::MalformedFrame);
    }

    TEST_CASE("a second SEG_FIRST mid-transfer is refused") {
        Reassembler r;
        Status err = Status::Ok;
        const auto d = pattern(300);
        CHECK(r.accept(hdr(1, 1, 300, 0, true, true), std::span(d).subspan(0, 100), err)
              == Reassembler::Outcome::NeedMore);
        CHECK(r.accept(hdr(1, 1, 300, 0, true, true), std::span(d).subspan(0, 100), err)
              == Reassembler::Outcome::Rejected);
    }

    TEST_CASE("total_len changing mid-transfer is refused") {
        Reassembler r;
        Status err = Status::Ok;
        const auto d = pattern(300);
        CHECK(r.accept(hdr(1, 1, 300, 0, true, true), std::span(d).subspan(0, 100), err)
              == Reassembler::Outcome::NeedMore);
        CHECK(r.accept(hdr(1, 1, 400, 100, false, false), std::span(d).subspan(100, 100), err)
              == Reassembler::Outcome::Rejected);
    }

    TEST_CASE("a final segment short of total_len is refused, not accepted truncated") {
        // The layer above would have no way to tell a truncated transfer from a
        // complete one.
        Reassembler r;
        Status err = Status::Ok;
        const auto d = pattern(300);
        CHECK(r.accept(hdr(1, 1, 300, 0, true, true), std::span(d).subspan(0, 100), err)
              == Reassembler::Outcome::NeedMore);
        CHECK(r.accept(hdr(1, 1, 300, 100, false, false), std::span(d).subspan(100, 100), err)
              == Reassembler::Outcome::Rejected);
        CHECK(err == Status::MalformedFrame);
    }

    TEST_CASE("more bytes than declared are refused before they are appended") {
        Reassembler r;
        Status err = Status::Ok;
        const auto d = pattern(500);
        CHECK(r.accept(hdr(1, 1, 200, 0, true, true), std::span(d).subspan(0, 300), err)
              == Reassembler::Outcome::Rejected);
    }

    TEST_CASE("a transfer larger than the negotiated maximum is refused") {
        Reassembler::Limits lim;
        lim.maxTransferBytes = 1024;
        Reassembler r(lim);
        Status err = Status::Ok;
        const auto d = pattern(100);
        CHECK(r.accept(hdr(1, 1, 4096, 0, true, true), d, err)
              == Reassembler::Outcome::Rejected);
        CHECK(err == Status::LimitExceeded);
    }

    TEST_CASE("many unfinished transfers are bounded by the arena, not by the per-transfer cap") {
        // One transfer is capped. A thousand half-finished ones must be too, or
        // the cap is decorative.
        Reassembler::Limits lim;
        lim.maxTransferBytes = 100'000;
        lim.arenaBytes       = 4096;
        lim.maxInFlight      = 1000;
        Reassembler r(lim);
        Status err = Status::Ok;
        const auto d = pattern(1024);

        bool refused = false;
        for (std::uint64_t i = 0; i < 100 && !refused; ++i) {
            const Header h = hdr(1, i, 100'000, 0, true, true);
            if (r.accept(h, d, err) == Reassembler::Outcome::Rejected) refused = true;
        }
        CHECK(refused);
        CHECK(err == Status::LimitExceeded);
        CHECK(r.bytesHeld() <= lim.arenaBytes);
    }

    TEST_CASE("too many transfers in flight is refused") {
        Reassembler::Limits lim;
        lim.maxInFlight = 4;
        lim.arenaBytes  = 1u << 20;
        Reassembler r(lim);
        Status err = Status::Ok;
        const auto d = pattern(16);

        for (std::uint64_t i = 0; i < 4; ++i)
            CHECK(r.accept(hdr(1, i, 1000, 0, true, true), d, err)
                  == Reassembler::Outcome::NeedMore);
        CHECK(r.accept(hdr(1, 99, 1000, 0, true, true), d, err)
              == Reassembler::Outcome::Rejected);
        CHECK(err == Status::LimitExceeded);
    }

    TEST_CASE("an unsegmented message cannot displace a partial one") {
        Reassembler r;
        Status err = Status::Ok;
        const auto d = pattern(300);
        CHECK(r.accept(hdr(1, 1, 300, 0, true, true), std::span(d).subspan(0, 100), err)
              == Reassembler::Outcome::NeedMore);
        // Same key, no flags: accepting this would silently discard 100 bytes.
        CHECK(r.accept(hdr(1, 1, 50, 0, false, false), std::span(d).subspan(0, 50), err)
              == Reassembler::Outcome::Rejected);
    }
}

void testHousekeeping()
{
    std::printf("housekeeping\n");

    TEST_CASE("a departing channel releases its arena") {
        Reassembler r;
        Status err = Status::Ok;
        const auto d = pattern(1000);
        (void)r.accept(hdr(3, 1, 5000, 0, true, true), d, err);
        (void)r.accept(hdr(4, 1, 5000, 0, true, true), d, err);
        CHECK_EQ(r.bytesHeld(), 2000u);

        r.forgetChannel(3);
        CHECK_EQ(r.inFlight(), 1u);
        CHECK_EQ(r.bytesHeld(), 1000u);

        r.clear();
        CHECK_EQ(r.bytesHeld(), 0u);
        CHECK_EQ(r.inFlight(), 0u);
    }

    TEST_CASE("take() answers once, and only for the transfer that completed") {
        Reassembler r;
        Status err = Status::Ok;
        const auto d = pattern(64);
        const Header h = hdr(1, 1, 64, 0, false, false);
        CHECK(r.accept(h, d, err) == Reassembler::Outcome::Complete);

        CHECK(r.take(hdr(2, 9, 64, 0, false, false)).empty());   // wrong key
        CHECK_EQ(r.take(h).size(), 64u);
        CHECK(r.take(h).empty());                                 // already taken
    }
}

void testEmit()
{
    std::printf("emit, then reassemble through real record bytes\n");

    auto baseComplete = [] {
        Header h;
        h.type      = static_cast<std::uint8_t>(wire::Type::Complete);
        h.channel   = 0x0142;
        h.attachId  = 7;
        h.requestId = 99;
        h.status    = 0;
        return h;
    };

    TEST_CASE("record 0 keeps the type and fixed body; continuations are Data") {
        const std::uint32_t total = 200'000;
        const auto payload = pattern(total, 3);
        const std::vector<std::uint8_t> fixed(wire::kBodyComplete, 0xEE);
        const std::uint32_t maxSeg = 16384;

        std::vector<std::vector<std::uint8_t>> recs;
        const Status s = emitTransfer(baseComplete(), fixed, payload, maxSeg,
            [&](std::span<const std::uint8_t> r) {
                recs.emplace_back(r.begin(), r.end());
                return Status::Ok;
            });
        CHECK(s == Status::Ok);
        CHECK(recs.size() > 1u);

        Header h0;
        CHECK(decodeHeader(recs[0], h0));
        CHECK_EQ(h0.type, static_cast<std::uint8_t>(wire::Type::Complete));
        CHECK(h0.segFirst());
        CHECK(h0.segMore());
        CHECK_EQ(h0.segOffset, 0u);
        CHECK_EQ(h0.totalLen, total);
        // header + fixed body + one full segment of data
        CHECK_EQ(recs[0].size(), wire::kHeaderSize + wire::kBodyComplete + maxSeg);

        for (std::size_t i = 1; i < recs.size(); ++i) {
            Header hi;
            CHECK(decodeHeader(recs[i], hi));
            CHECK_EQ(hi.type, static_cast<std::uint8_t>(wire::Type::Data));
            CHECK(!hi.segFirst());
            CHECK_EQ(hi.status, 0u);
            CHECK_EQ(hi.totalLen, total);
        }

        // Reassemble the DATA back out of the framed records: record 0 contributes
        // the bytes after its fixed body, every continuation its whole body.
        Reassembler r;
        Status err = Status::Ok;
        Reassembler::Outcome o = Reassembler::Outcome::NeedMore;
        for (std::size_t i = 0; i < recs.size(); ++i) {
            Header hi;
            CHECK(decodeHeader(recs[i], hi));
            const std::size_t fixedLen = (i == 0) ? wire::kBodyComplete : 0;
            const auto chunk = std::span<const std::uint8_t>(recs[i])
                                  .subspan(wire::kHeaderSize + fixedLen);
            o = r.accept(hi, chunk, err);
        }
        CHECK(o == Reassembler::Outcome::Complete);
        CHECK(r.take(h0) == payload);
    }

    TEST_CASE("a transfer that fits emits exactly one record") {
        const std::vector<std::uint8_t> fixed(wire::kBodySubmit, 0);
        const auto payload = pattern(1000, 1);
        int n = 0;
        Header seen;
        Header base;
        base.type = static_cast<std::uint8_t>(wire::Type::Submit);
        emitTransfer(base, fixed, payload, 16384,
            [&](std::span<const std::uint8_t> rec) {
                ++n; decodeHeader(rec, seen); return Status::Ok;
            });
        CHECK_EQ(n, 1);
        CHECK(seen.segFirst());
        CHECK(!seen.segMore());
        CHECK_EQ(seen.totalLen, 1000u);
    }

    TEST_CASE("a zero-length transfer still emits one record") {
        const std::vector<std::uint8_t> fixed(wire::kBodySubmit, 0);
        int n = 0;
        Header seen;
        Header base;
        base.type = static_cast<std::uint8_t>(wire::Type::Submit);
        emitTransfer(base, fixed, {}, 16384,
            [&](std::span<const std::uint8_t> rec) {
                ++n; decodeHeader(rec, seen); return Status::Ok;
            });
        CHECK_EQ(n, 1);
        CHECK(seen.segFirst());
        CHECK(!seen.segMore());
        CHECK_EQ(seen.totalLen, 0u);
    }

    TEST_CASE("a send error stops the emission and propagates") {
        const std::vector<std::uint8_t> fixed(wire::kBodyComplete, 0);
        const auto payload = pattern(100'000, 2);
        int n = 0;
        const Status s = emitTransfer(baseComplete(), fixed, payload, 16384,
            [&](std::span<const std::uint8_t>) {
                ++n;
                return n >= 2 ? Status::TransportLost : Status::Ok;
            });
        CHECK(s == Status::TransportLost);
        CHECK_EQ(n, 2);      // stopped at the failing send, did not keep going
    }
}

} // namespace

int main()
{
    std::printf("test_segmentation\n");
    testPlanning();
    testRoundTrip();
    testHostilePeer();
    testHousekeeping();
    testEmit();
    TEST_MAIN_END();
}
