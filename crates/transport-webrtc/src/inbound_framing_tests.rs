//! Regression tests for docs/25 F02 — "malformed WebRTC framing wedges an ever-growing receive
//! buffer".
//!
//! These drive [`super::Reassembler`], which IS the shipped reassembly loop — the `on_message`
//! closure calls it and does nothing else. That matters: the previous version of this logic lived
//! inline inside a closure owned by the webrtc peer connection, where no test could reach it, which
//! is why a one-line `Err(_) => break` sat there uncaught through every prior review.

use super::*;
use rmt_protocol::ChannelId;

/// Collect frames into a Vec, always accepting.
fn collector(out: &mut Vec<Frame>) -> impl FnMut(Frame) -> SinkResult + '_ {
    move |f| {
        out.push(f);
        SinkResult::Accepted
    }
}

fn encoded(channel: ChannelId, payload: &[u8]) -> Vec<u8> {
    let mut b = BytesMut::new();
    Frame::new(channel, Bytes::copy_from_slice(payload)).encode(&mut b);
    b.to_vec()
}

/// THE REPRODUCTION. The review fed `07 00 00 00 00` — a complete, permanently-invalid 5-byte
/// header — then 64 KiB of further data, and measured the receive buffer at 65,541 bytes
/// (65536 + 5) with no frame ever decoding again.
#[test]
fn unknown_channel_header_is_fatal_and_buffers_nothing_further() {
    let mut acc = Reassembler::new();
    let mut got = Vec::new();

    // Channel 7 is one past ChannelId::Backstage (6), with a declared length of 0 — so it is a
    // COMPLETE frame that can never be valid. Nothing is waiting for more bytes.
    let outcome = acc.push(
        &[0x07, 0x00, 0x00, 0x00, 0x00],
        MAX_REASSEMBLY_BYTES,
        collector(&mut got),
    );
    assert_eq!(
        outcome,
        DrainOutcome::Fatal(DrainFault::HardFrameError),
        "an unknown channel must end the session, not be mistaken for a partial frame"
    );
    assert!(got.is_empty());

    // The wedge: 64 KiB of follow-on traffic. The old loop appended all of it and grew to
    // 65,541 bytes. The buffer must not be allowed to reach that.
    let flood = vec![0xAAu8; 64 * 1024];
    let _ = acc.push(&flood, MAX_REASSEMBLY_BYTES, collector(&mut got));
    assert!(
        acc.buffered() < 65_541,
        "receive buffer grew to {} bytes after a permanently-invalid header — this is the \
         docs/25 F02 wedge (the review measured 65,541)",
        acc.buffered()
    );
}

/// A wedged channel must stay wedged. Clearing the buffer on fault bounds MEMORY, but on its own it
/// leaves the channel willing to decode and deliver whatever the peer sends next — and the peer has
/// just been declared hostile. `peer_gone` does not help here: it tells the session loop to stop,
/// but it does not unregister `on_message`, which the peer connection keeps invoking.
///
/// This is the test that distinguishes the two. It was added after a mutation showed that deleting
/// the terminal check still passed every other test in this file, because the buffer-clear happened
/// to leave `buffered()` at zero either way.
#[test]
fn a_fault_is_terminal_and_a_later_valid_frame_is_not_delivered() {
    let mut acc = Reassembler::new();
    let mut got = Vec::new();

    let outcome = acc.push(
        &[0x07, 0x00, 0x00, 0x00, 0x00],
        MAX_REASSEMBLY_BYTES,
        collector(&mut got),
    );
    assert_eq!(outcome, DrainOutcome::Fatal(DrainFault::HardFrameError));

    // A perfectly well-formed frame, arriving after the fault.
    let good = encoded(ChannelId::Input, b"click");
    let after = acc.push(&good, MAX_REASSEMBLY_BYTES, collector(&mut got));
    assert_eq!(
        after,
        DrainOutcome::Fatal(DrainFault::HardFrameError),
        "a wedged channel must keep reporting its ORIGINAL fault, not re-open on valid input"
    );
    assert!(
        got.is_empty(),
        "a frame decoded AFTER the session was declared faulted reached the consumer — the fault \
         is not terminal, so a hostile peer keeps being served while teardown is in progress"
    );
    assert_eq!(acc.buffered(), 0);
}

/// A VALID channel byte with a declared length beyond what this transport will ever reassemble must
/// be refused on sight. Error classification alone does not catch this: the decoder legitimately
/// reports `Incomplete` while such a payload arrives, so without the declared-length check one
/// 5-byte header still reserves a very large buffer.
#[test]
fn declared_length_beyond_the_cap_is_refused_before_accumulating() {
    let mut acc = Reassembler::new();
    let mut got = Vec::new();
    let mut header = vec![ChannelId::Control as u8];
    header.extend_from_slice(&((MAX_REASSEMBLY_BYTES as u32) + 1).to_be_bytes());

    let outcome = acc.push(&header, MAX_REASSEMBLY_BYTES, collector(&mut got));
    assert_eq!(outcome, DrainOutcome::Fatal(DrainFault::DeclaredTooLong));
}

/// One message larger than the cap cannot be appended at all.
#[test]
fn a_single_oversized_message_cannot_exceed_the_cap() {
    let mut acc = Reassembler::new();
    let mut got = Vec::new();
    let huge = vec![0u8; MAX_REASSEMBLY_BYTES + 1];
    let outcome = acc.push(&huge, MAX_REASSEMBLY_BYTES, collector(&mut got));
    assert_eq!(outcome, DrainOutcome::Fatal(DrainFault::ReassemblyCap));
    assert_eq!(acc.buffered(), 0, "a refused message must not be buffered");
}

/// THE NEGATIVE CONTROL. Everything above asserts that bad input is rejected; without this, a
/// `Reassembler` that simply returned Fatal for every input would pass all of them. A frame
/// fragmented across several messages — exactly what `send_frame` produces above MAX_DC_MSG — must
/// still reassemble and decode.
#[test]
fn a_frame_fragmented_across_messages_still_reassembles() {
    let payload = vec![0x5Au8; 40 * 1024];
    let wire = encoded(ChannelId::Backstage, &payload);
    let mut acc = Reassembler::new();
    let mut got = Vec::new();

    for chunk in wire.chunks(MAX_DC_MSG) {
        let outcome = acc.push(chunk, MAX_REASSEMBLY_BYTES, collector(&mut got));
        assert_eq!(outcome, DrainOutcome::Ok, "a legitimate fragment must not be fatal");
    }
    assert_eq!(got.len(), 1, "the fragmented frame did not reassemble");
    assert_eq!(got[0].channel, ChannelId::Backstage);
    assert_eq!(got[0].payload.len(), payload.len());
    assert_eq!(acc.buffered(), 0, "a fully consumed frame must leave no residue");
}

/// Several whole frames in one message all drain, in order.
#[test]
fn multiple_complete_frames_in_one_message_all_drain() {
    let mut wire = encoded(ChannelId::Input, b"a");
    wire.extend_from_slice(&encoded(ChannelId::Chat, b"bb"));
    wire.extend_from_slice(&encoded(ChannelId::Control, b"ccc"));
    let mut acc = Reassembler::new();
    let mut got = Vec::new();
    assert_eq!(
        acc.push(&wire, MAX_REASSEMBLY_BYTES, collector(&mut got)),
        DrainOutcome::Ok
    );
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].channel, ChannelId::Input);
    assert_eq!(got[2].payload.as_ref(), b"ccc");
}

/// A partial frame is retained untouched, and reports Ok (not a fault) — the ordinary case.
#[test]
fn a_partial_frame_is_retained_without_fault() {
    let wire = encoded(ChannelId::Chat, b"hello");
    let mut acc = Reassembler::new();
    let mut got = Vec::new();
    let outcome = acc.push(&wire[..7], MAX_REASSEMBLY_BYTES, collector(&mut got));
    assert_eq!(outcome, DrainOutcome::Ok);
    assert!(got.is_empty());
    assert_eq!(acc.buffered(), 7, "the partial frame must be retained for the next message");
}

/// A peer sending VALID frames faster than the session loop consumes them is overload, and must
/// terminate the session rather than grow the queue. This is the second half of F02.
#[test]
fn a_full_inbound_queue_is_fatal_rather_than_unbounded() {
    let mut wire = Vec::new();
    for _ in 0..4 {
        wire.extend_from_slice(&encoded(ChannelId::Input, b"x"));
    }
    let mut acc = Reassembler::new();
    let mut accepted = 0usize;
    let outcome = acc.push(&wire, MAX_REASSEMBLY_BYTES, |_f| {
        // A queue with room for two.
        accepted += 1;
        if accepted <= 2 {
            SinkResult::Accepted
        } else {
            SinkResult::Full
        }
    });
    assert_eq!(outcome, DrainOutcome::Fatal(DrainFault::QueueOverflow));
}

/// A dropped transport is not a protocol fault and must not be reported as one.
#[test]
fn a_closed_consumer_is_not_a_fault() {
    let wire = encoded(ChannelId::Input, b"x");
    let mut acc = Reassembler::new();
    let outcome = acc.push(&wire, MAX_REASSEMBLY_BYTES, |_f| SinkResult::Closed);
    assert_eq!(outcome, DrainOutcome::ConsumerGone);
}

/// The cap must be big enough for every frame this product actually sends, or the fix is a
/// self-inflicted outage. Pins the relationship rather than the number.
#[test]
fn the_cap_admits_the_largest_legitimate_producer() {
    assert!(
        MAX_REASSEMBLY_BYTES >= 16 * (rmt_agent_core::file_transfer::MAX_CHUNK_DATA + 64),
        "the reassembly cap must comfortably exceed the largest chunked payload"
    );
    assert!(MAX_REASSEMBLY_BYTES > MAX_DC_MSG * 8);
}
