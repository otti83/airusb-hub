// P2.5 — record framing, egress scheduling, fault injection.

#include "../TestHarness.h"
#include "../../transport/FaultTransport.h"
#include "../../transport/FrameScheduler.h"
#include "../../transport/RecordLayer.h"
#include "../../transport/TcpTransport.h"
#include "../../protocol/Codec.h"

using namespace airusb;
using namespace airusb::transport;

namespace {

std::vector<std::uint8_t> body(std::size_t n, std::uint8_t fill)
{
    return std::vector<std::uint8_t>(n, fill);
}

void testRecordLayer()
{
    TEST_CASE("a record round-trips through a memory pipe") {
        MemoryPipe pipe;
        RecordLayer a(pipe.endpointA(), std::make_unique<NullCipher>());
        RecordLayer b(pipe.endpointB(), std::make_unique<NullCipher>());

        auto payload = body(100, 0xAB);
        CHECK_EQ(static_cast<int>(a.sendRecord(payload)), static_cast<int>(Status::Ok));

        std::vector<std::uint8_t> got;
        CHECK_EQ(static_cast<int>(b.receiveRecord(got)), static_cast<int>(Status::Ok));
        CHECK_EQ(got.size(), std::size_t{100});
        CHECK(got == payload);
    }

    TEST_CASE("records keep their boundaries when several are batched") {
        MemoryPipe pipe;
        RecordLayer a(pipe.endpointA(), std::make_unique<NullCipher>());
        RecordLayer b(pipe.endpointB(), std::make_unique<NullCipher>());

        a.sendRecord(body(10, 1));
        a.sendRecord(body(20, 2));
        a.sendRecord(body(30, 3));

        for (std::size_t expect : {std::size_t{10}, std::size_t{20}, std::size_t{30}}) {
            std::vector<std::uint8_t> got;
            CHECK_EQ(static_cast<int>(b.receiveRecord(got)), static_cast<int>(Status::Ok));
            CHECK_EQ(got.size(), expect);
        }
        std::vector<std::uint8_t> none;
        CHECK_EQ(static_cast<int>(b.receiveRecord(none)), static_cast<int>(Status::Ok));
        CHECK(none.empty());
    }

    TEST_CASE("a record split across many reads reassembles") {
        // The framing layer must not care how the bytes arrive; only that they do.
        MemoryPipe pipe;
        ManualClock clock;
        FaultConfig cfg; cfg.maxWriteChunk = 7;   // pathological fragmentation
        auto faulty = std::make_unique<FaultStream>(pipe.endpointA(), cfg, clock);
        FaultStream* fs = faulty.get();

        RecordLayer a(std::move(faulty), std::make_unique<NullCipher>());
        RecordLayer b(pipe.endpointB(), std::make_unique<NullCipher>());

        auto payload = body(500, 0x5A);
        a.sendRecord(payload);
        for (int i = 0; i < 200; ++i) { a.flush(); fs->pump(); }

        std::vector<std::uint8_t> got;
        CHECK_EQ(static_cast<int>(b.receiveRecord(got)), static_cast<int>(Status::Ok));
        CHECK_EQ(got.size(), std::size_t{500});
        CHECK(got == payload);
    }

    TEST_CASE("R1 caps the record size before the handshake") {
        MemoryPipe pipe;
        RecordLayer a(pipe.endpointA(), std::make_unique<NullCipher>());
        CHECK_EQ(a.maxRecordBytes(), wire::kHandshakeRecordMax);
        CHECK_EQ(static_cast<int>(a.sendRecord(body(wire::kHandshakeRecordMax + 1, 0))),
                 static_cast<int>(Status::LimitExceeded));

        a.setHandshakeComplete(wire::kRecordBytesDefault);
        CHECK_EQ(a.maxRecordBytes(), wire::kRecordBytesDefault);
        CHECK_EQ(static_cast<int>(a.sendRecord(body(9000, 0))), static_cast<int>(Status::Ok));
    }

    TEST_CASE("an oversized announced length is refused before buffering it") {
        // The peer says 4 GiB. We must reject on the length field alone, without
        // waiting for -- or reserving space for -- the body.
        MemoryPipe pipe;
        auto raw = pipe.endpointA();
        std::uint8_t hdr[4];
        protocol::wr_u32(hdr, 0xFFFFFFFFu);
        raw->write(hdr);

        RecordLayer b(pipe.endpointB(), std::make_unique<NullCipher>());
        std::vector<std::uint8_t> got;
        auto st = b.receiveRecord(got);
        CHECK_EQ(static_cast<int>(st), static_cast<int>(Status::LimitExceeded));
        CHECK(!b.isOpen());                    // fatal, no resync
    }

    TEST_CASE("peer close is reported, not mistaken for a stall") {
        MemoryPipe pipe;
        auto epA = pipe.endpointA();
        RecordLayer b(pipe.endpointB(), std::make_unique<NullCipher>());
        epA->close();
        std::vector<std::uint8_t> got;
        CHECK_EQ(static_cast<int>(b.receiveRecord(got)),
                 static_cast<int>(Status::TransportLost));
    }

    TEST_CASE("a partially flushed record still completes later") {
        MemoryPipe pipe;
        auto epA = pipe.endpointA();
        static_cast<MemoryPipe::Endpoint*>(epA.get())->setCapacity(64);

        RecordLayer a(std::move(epA), std::make_unique<NullCipher>());
        RecordLayer b(pipe.endpointB(), std::make_unique<NullCipher>());

        auto payload = body(400, 0x11);
        a.sendRecord(payload);
        CHECK(a.pendingTxBytes() > 0);         // did not all fit

        std::vector<std::uint8_t> got;
        for (int i = 0; i < 50 && got.empty(); ++i) {
            b.receiveRecord(got);              // drains the pipe
            a.flush();                         // lets more in
        }
        CHECK_EQ(got.size(), std::size_t{400});
    }
}

void testFrameScheduler()
{
    TEST_CASE("priority is a pure function of transfer type") {
        CHECK_EQ(static_cast<int>(priorityFor(XferType::Isochronous)),
                 static_cast<int>(Priority::Rt));
        CHECK_EQ(static_cast<int>(priorityFor(XferType::Interrupt)),
                 static_cast<int>(Priority::High));
        CHECK_EQ(static_cast<int>(priorityFor(XferType::Control)),
                 static_cast<int>(Priority::High));
        CHECK_EQ(static_cast<int>(priorityFor(XferType::Bulk)),
                 static_cast<int>(Priority::Bulk));
    }

    TEST_CASE("session control has strict priority over data") {
        FrameScheduler s;
        Frame bulk;  bulk.bytes = body(16384, 1); bulk.priority = Priority::Bulk;
        Frame ctrl;  ctrl.bytes = body(32, 2);    ctrl.priority = Priority::Control;
        s.enqueue(std::move(bulk));
        s.enqueue(std::move(ctrl));

        Frame out;
        CHECK(s.dequeue(out));
        CHECK_EQ(static_cast<int>(out.priority), static_cast<int>(Priority::Control));
    }

    TEST_CASE("an 8-byte interrupt does not wait behind a megabyte of bulk") {
        // This is the whole reason the scheduler exists. Without it the interrupt
        // completion waits for 64 bulk segments, ~8.4 ms on 1 GbE.
        FrameScheduler s;
        for (int i = 0; i < 64; ++i) {
            Frame f; f.bytes = body(16384, 0xBB); f.priority = Priority::Bulk;
            s.enqueue(std::move(f));
        }
        Frame intr; intr.bytes = body(8, 0xCC); intr.priority = Priority::High;
        s.enqueue(std::move(intr));

        int before = 0;
        Frame out;
        while (s.dequeue(out)) {
            if (out.priority == Priority::High) break;
            ++before;
        }
        CHECK_EQ(static_cast<int>(out.priority), static_cast<int>(Priority::High));
        CHECK(before <= 2);      // at most one bulk segment ahead of it
    }

    TEST_CASE("EXPEDITE jumps its own class, never across classes") {
        // Letting expedite cross classes would let expedited bulk starve control.
        FrameScheduler s;
        Frame b1; b1.bytes = body(100, 1); b1.priority = Priority::Bulk; b1.channel = 1;
        Frame b2; b2.bytes = body(100, 2); b2.priority = Priority::Bulk; b2.channel = 2;
        b2.expedite = true;
        s.enqueue(std::move(b1));
        s.enqueue(std::move(b2));

        Frame out;
        CHECK(s.dequeue(out));
        CHECK_EQ(out.channel, 2);        // expedited one first, within Bulk
    }

    TEST_CASE("an idle class banks no credit") {
        // Otherwise a silent endpoint accumulates deficit and bursts ahead of
        // everyone the moment it wakes up.
        FrameScheduler s;
        for (int i = 0; i < 10; ++i) {
            Frame f; f.bytes = body(1000, 1); f.priority = Priority::Bulk;
            s.enqueue(std::move(f));
        }
        Frame out;
        while (s.dequeue(out)) {}

        Frame rt; rt.bytes = body(1000, 2); rt.priority = Priority::Rt;
        Frame bk; bk.bytes = body(1000, 3); bk.priority = Priority::Bulk;
        s.enqueue(std::move(rt));
        s.enqueue(std::move(bk));

        int rtSeen = 0, bulkSeen = 0;
        while (s.dequeue(out)) {
            if (out.priority == Priority::Rt) ++rtSeen; else ++bulkSeen;
        }
        CHECK_EQ(rtSeen, 1);
        CHECK_EQ(bulkSeen, 1);
    }

    TEST_CASE("every enqueued frame comes back out exactly once") {
        FrameScheduler s;
        std::size_t total = 0;
        for (int i = 0; i < 200; ++i) {
            Frame f;
            f.bytes    = body(static_cast<std::size_t>(50 + i), static_cast<std::uint8_t>(i));
            f.priority = static_cast<Priority>(static_cast<std::size_t>(i) % kPriorityCount);
            total += f.bytes.size();
            s.enqueue(std::move(f));
        }
        CHECK_EQ(s.queuedFrames(), std::size_t{200});
        CHECK_EQ(s.queuedBytes(), total);

        std::size_t seen = 0, bytes = 0;
        Frame out;
        while (s.dequeue(out)) { ++seen; bytes += out.bytes.size(); }
        CHECK_EQ(seen, std::size_t{200});
        CHECK_EQ(bytes, total);
        CHECK(s.empty());
        CHECK_EQ(s.queuedBytes(), std::size_t{0});
    }

    TEST_CASE("dropChannel removes only that channel and fixes the byte count") {
        FrameScheduler s;
        for (int i = 0; i < 10; ++i) {
            Frame f; f.bytes = body(100, 1);
            f.priority = Priority::Bulk;
            f.channel  = static_cast<std::uint16_t>(i % 2);
            s.enqueue(std::move(f));
        }
        CHECK_EQ(s.dropChannel(0), std::size_t{5});
        CHECK_EQ(s.queuedFrames(), std::size_t{5});
        CHECK_EQ(s.queuedBytes(), std::size_t{500});
    }
}

void testFaultInjection()
{
    TEST_CASE("SlowPeer delays delivery without losing bytes") {
        // The INV-CMD harness: a uniform multi-second delay must not lose or
        // duplicate anything, or a failing loopback run would be ambiguous.
        MemoryPipe pipe;
        ManualClock clock;
        FaultConfig cfg; cfg.delayMs = 30000;
        auto faulty = std::make_unique<FaultStream>(pipe.endpointA(), cfg, clock);
        FaultStream* fs = faulty.get();

        RecordLayer a(std::move(faulty), std::make_unique<NullCipher>());
        RecordLayer b(pipe.endpointB(), std::make_unique<NullCipher>());

        auto payload = body(256, 0x77);
        a.sendRecord(payload);

        std::vector<std::uint8_t> got;
        fs->pump();
        b.receiveRecord(got);
        CHECK(got.empty());                    // still in flight

        clock.advanceMs(30000);
        fs->pump();
        CHECK_EQ(static_cast<int>(b.receiveRecord(got)), static_cast<int>(Status::Ok));
        CHECK_EQ(got.size(), std::size_t{256});
        CHECK(got == payload);
    }

    TEST_CASE("a mid-stream reset surfaces as TransportLost") {
        MemoryPipe pipe;
        ManualClock clock;
        FaultConfig cfg; cfg.resetAfterBytes = 100;
        auto faulty = std::make_unique<FaultStream>(pipe.endpointA(), cfg, clock);
        FaultStream* fs = faulty.get();
        RecordLayer a(std::move(faulty), std::make_unique<NullCipher>());

        a.sendRecord(body(500, 1));
        CHECK(fs->wasReset());
        CHECK(!a.isOpen());
    }

    TEST_CASE("periodic would-block stalls do not lose data") {
        MemoryPipe pipe;
        ManualClock clock;
        FaultConfig cfg; cfg.stallEveryN = 2;
        auto faulty = std::make_unique<FaultStream>(pipe.endpointA(), cfg, clock);
        RecordLayer a(std::move(faulty), std::make_unique<NullCipher>());
        RecordLayer b(pipe.endpointB(), std::make_unique<NullCipher>());

        auto payload = body(300, 0x33);
        a.sendRecord(payload);
        for (int i = 0; i < 50; ++i) a.flush();

        std::vector<std::uint8_t> got;
        CHECK_EQ(static_cast<int>(b.receiveRecord(got)), static_cast<int>(Status::Ok));
        CHECK(got == payload);
    }
}

} // namespace

int main()
{
    std::printf("test_transport\n");
    testRecordLayer();
    testFrameScheduler();
    testFaultInjection();
    TEST_MAIN_END();
}
