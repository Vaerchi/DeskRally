//! End-to-end pipeline test, fully in-process (no sockets, no hardware): a synthetic screen is
//! captured on the agent, sealed per-channel, moved over a LoopbackTransport, opened on the
//! controller, and verified frame-for-frame — then the controller sends input back and the
//! agent injects it into a fake sink. This proves capture → crypto → mux → transport → decode
//! integrates as one system, on any machine.

use std::sync::{Arc, Mutex};

use rmt_agent_core::platform::{InputEvent, InputSink, PlatformResult, ScreenCapturer};
use rmt_agent_core::{frame_number, ChannelId, Handshake, Role, Session, SyntheticCapturer};
use rmt_protocol::SessionId;

/// Records everything injected, so the test can assert the agent received the controller's input.
#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<InputEvent>>,
}
impl InputSink for RecordingSink {
    fn inject(&self, event: InputEvent) -> PlatformResult<()> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}

/// Establish a controller/agent key pair sharing one session id (as the signaling handshake
/// would, but in-process).
fn paired_sessions() -> (Session, Session) {
    let id = SessionId::new();
    let controller = Handshake::new(Role::Controller);
    let agent = Handshake::new(Role::Agent);
    let cpub = controller.public_bytes();
    let apub = agent.public_bytes();
    (
        Session::new(id, controller.complete(&apub)),
        Session::new(id, agent.complete(&cpub)),
    )
}

#[tokio::test]
async fn full_pipeline_video_down_and_input_up() {
    let (mut controller, mut agent) = paired_sessions();
    let (mut ctrl_link, mut agent_link) = rmt_agent_core::LoopbackTransport::pair_with_capacity(256);

    const N: u64 = 30;

    // --- Agent: capture N synthetic frames, seal on Video, send. ---
    let agent_task = tokio::spawn(async move {
        let mut cap = SyntheticCapturer::new(64, 64, 8);
        for _ in 0..N {
            let frame = cap.capture_frame(0).expect("capture");
            agent
                .send(&mut agent_link, ChannelId::Video, &frame.bytes)
                .await
                .expect("send video");
        }
        // Then receive the controller's input events and inject them.
        let sink = Arc::new(RecordingSink::default());
        for _ in 0..3 {
            let (channel, plaintext) = agent.recv(&mut agent_link).await.expect("recv input");
            assert_eq!(channel, ChannelId::Input);
            // Input events are serialized as JSON on the wire for this test.
            let ev: WireInput = serde_json::from_slice(&plaintext).expect("decode input");
            sink.inject(ev.into()).unwrap();
        }
        sink
    });

    // --- Controller: receive N video frames, verify each decrypts to the exact captured frame. ---
    for expected in 0..N {
        let (channel, plaintext) = controller.recv(&mut ctrl_link).await.expect("recv video");
        assert_eq!(channel, ChannelId::Video);
        assert_eq!(
            frame_number(&plaintext),
            Some(expected),
            "frame {expected} must decrypt intact and in order"
        );
    }

    // --- Controller: send 3 input events back. ---
    let inputs = [
        WireInput::MouseMove { x: 32768, y: 100 },
        WireInput::Key { code: 65, down: true },
        WireInput::Key { code: 65, down: false },
    ];
    for ev in &inputs {
        let bytes = serde_json::to_vec(ev).unwrap();
        controller
            .send(&mut ctrl_link, ChannelId::Input, &bytes)
            .await
            .expect("send input");
    }

    let sink = agent_task.await.unwrap();
    let got = sink.events.lock().unwrap();
    assert_eq!(got.len(), 3, "agent injected all three input events");
    assert!(matches!(got[0], InputEvent::MouseMove { x: 32768, y: 100 }));
}

/// A JSON-serializable mirror of a subset of InputEvent, so the test can put input on the wire
/// without depending on an event codec (which lives in the OS/transport layer, not the core).
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "t")]
enum WireInput {
    MouseMove { x: u16, y: u16 },
    Key { code: u32, down: bool },
}
impl From<WireInput> for InputEvent {
    fn from(w: WireInput) -> Self {
        match w {
            WireInput::MouseMove { x, y } => InputEvent::MouseMove { x, y },
            WireInput::Key { code, down } => InputEvent::Key { code, down },
        }
    }
}
