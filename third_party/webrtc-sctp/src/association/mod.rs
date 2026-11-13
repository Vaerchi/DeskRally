#[cfg(test)]
mod association_test;

mod association_internal;
mod association_stats;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::SystemTime;

use association_internal::*;
use association_stats::*;
use bytes::{Bytes, BytesMut};
use portable_atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize};
use rand::random;
use tokio::sync::{broadcast, mpsc, Mutex};
use util::Conn;

use crate::chunk::chunk_abort::ChunkAbort;
use crate::chunk::chunk_cookie_ack::ChunkCookieAck;
use crate::chunk::chunk_cookie_echo::ChunkCookieEcho;
use crate::chunk::chunk_error::ChunkError;
use crate::chunk::chunk_forward_tsn::{ChunkForwardTsn, ChunkForwardTsnStream};
use crate::chunk::chunk_heartbeat::ChunkHeartbeat;
use crate::chunk::chunk_heartbeat_ack::ChunkHeartbeatAck;
use crate::chunk::chunk_init::ChunkInit;
use crate::chunk::chunk_payload_data::{ChunkPayloadData, PayloadProtocolIdentifier};
use crate::chunk::chunk_reconfig::ChunkReconfig;
use crate::chunk::chunk_selective_ack::ChunkSelectiveAck;
use crate::chunk::chunk_shutdown::ChunkShutdown;
use crate::chunk::chunk_shutdown_ack::ChunkShutdownAck;
use crate::chunk::chunk_shutdown_complete::ChunkShutdownComplete;
use crate::chunk::chunk_type::*;
use crate::chunk::Chunk;
use crate::error::{Error, Result};
use crate::error_cause::*;
use crate::packet::Packet;
use crate::param::param_heartbeat_info::ParamHeartbeatInfo;
use crate::param::param_outgoing_reset_request::ParamOutgoingResetRequest;
use crate::param::param_reconfig_response::{ParamReconfigResponse, ReconfigResult};
use crate::param::param_state_cookie::ParamStateCookie;
use crate::param::param_supported_extensions::ParamSupportedExtensions;
use crate::param::Param;
use crate::queue::control_queue::ControlQueue;
use crate::queue::payload_queue::PayloadQueue;
use crate::queue::pending_queue::PendingQueue;
use crate::stream::*;
use crate::timer::ack_timer::*;
use crate::timer::rtx_timer::*;
use crate::util::*;

pub(crate) const RECEIVE_MTU: usize = 8192;
/// MTU for inbound packet (from DTLS)
pub(crate) const INITIAL_MTU: u32 = 1228;
/// initial MTU for outgoing packets (to DTLS)
pub(crate) const INITIAL_RECV_BUF_SIZE: u32 = 1024 * 1024;
pub(crate) const COMMON_HEADER_SIZE: u32 = 12;
pub(crate) const DATA_CHUNK_HEADER_SIZE: u32 = 16;
pub(crate) const DEFAULT_MAX_MESSAGE_SIZE: u32 = 65536;

/// other constants
pub(crate) const ACCEPT_CH_SIZE: usize = 16;

/// association state enums
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum AssociationState {
    Closed = 0,
    CookieWait = 1,
    CookieEchoed = 2,
    Established = 3,
    ShutdownAckSent = 4,
    ShutdownPending = 5,
    ShutdownReceived = 6,
    ShutdownSent = 7,
}

impl From<u8> for AssociationState {
    fn from(v: u8) -> AssociationState {
        match v {
            1 => AssociationState::CookieWait,
            2 => AssociationState::CookieEchoed,
            3 => AssociationState::Established,
            4 => AssociationState::ShutdownAckSent,
            5 => AssociationState::ShutdownPending,
            6 => AssociationState::ShutdownReceived,
            7 => AssociationState::ShutdownSent,
            _ => AssociationState::Closed,
        }
    }
}

impl fmt::Display for AssociationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            AssociationState::Closed => "Closed",
            AssociationState::CookieWait => "CookieWait",
            AssociationState::CookieEchoed => "CookieEchoed",
            AssociationState::Established => "Established",
            AssociationState::ShutdownPending => "ShutdownPending",
            AssociationState::ShutdownSent => "ShutdownSent",
            AssociationState::ShutdownReceived => "ShutdownReceived",
            AssociationState::ShutdownAckSent => "ShutdownAckSent",
        };
        write!(f, "{s}")
    }
}

/// retransmission timer IDs
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub(crate) enum RtxTimerId {
    #[default]
    T1Init,
    T1Cookie,
    T2Shutdown,
    T3RTX,
    Reconfig,
}

impl fmt::Display for RtxTimerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RtxTimerId::T1Init => "T1Init",
            RtxTimerId::T1Cookie => "T1Cookie",
            RtxTimerId::T2Shutdown => "T2Shutdown",
            RtxTimerId::T3RTX => "T3RTX",
            RtxTimerId::Reconfig => "Reconfig",
        };
        write!(f, "{s}")
    }
}

/// ack mode (for testing)
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub(crate) enum AckMode {
    #[default]
    Normal,
    NoDelay,
    AlwaysDelay,
}

impl fmt::Display for AckMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            AckMode::Normal => "Normal",
            AckMode::NoDelay => "NoDelay",
            AckMode::AlwaysDelay => "AlwaysDelay",
        };
        write!(f, "{s}")
    }
}

/// ack transmission state
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub(crate) enum AckState {
    #[default]
    Idle, // ack timer is off
    Immediate, // will send ack immediately
    Delay,     // ack timer is on (ack is being delayed)
}

impl fmt::Display for AckState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            AckState::Idle => "Idle",
            AckState::Immediate => "Immediate",
            AckState::Delay => "Delay",
        };
        write!(f, "{s}")
    }
}

/// Config collects the arguments to create_association construction into
/// a single structure
pub struct Config {
    pub net_conn: Arc<dyn Conn + Send + Sync>,
    pub max_receive_buffer_size: u32,
    pub max_message_size: u32,
    pub name: String,
}

///Association represents an SCTP association
///13.2.  Parameters Necessary per Association (i.e., the TCB)
///Peer : Tag value to be sent in every packet and is received
///Verification: in the INIT or INIT ACK chunk.
///Tag :
///
///My : Tag expected in every inbound packet and sent in the
///Verification: INIT or INIT ACK chunk.
///
///Tag :
///State : A state variable indicating what state the association
/// : is in, i.e., COOKIE-WAIT, COOKIE-ECHOED, ESTABLISHED,
/// : SHUTDOWN-PENDING, SHUTDOWN-SENT, SHUTDOWN-RECEIVED,
/// : SHUTDOWN-ACK-SENT.
///
/// No Closed state is illustrated since if a
/// association is Closed its TCB SHOULD be removed.
pub struct Association {
    name: String,
    state: Arc<AtomicU8>,
    max_message_size: Arc<AtomicU32>,
    inflight_queue_length: Arc<AtomicUsize>,
    will_send_shutdown: Arc<AtomicBool>,
    awake_write_loop_ch: Arc<mpsc::Sender<()>>,
    close_loop_ch_rx: Mutex<broadcast::Receiver<()>>,
    accept_ch_rx: Mutex<mpsc::Receiver<Arc<Stream>>>,
    net_conn: Arc<dyn Conn + Send + Sync>,
    bytes_received: Arc<AtomicUsize>,
    bytes_sent: Arc<AtomicUsize>,

    pub(crate) association_internal: Arc<Mutex<AssociationInternal>>,
}

impl Association {
    /// server accepts a SCTP stream over a conn
    pub async fn server(config: Config) -> Result<Self> {
        let (a, mut handshake_completed_ch_rx) = Association::new(config, false).await?;

        if let Some(err_opt) = handshake_completed_ch_rx.recv().await {
            if let Some(err) = err_opt {
                Err(err)
            } else {
                Ok(a)
            }
        } else {
            Err(Error::ErrAssociationHandshakeClosed)
        }
    }

    /// Client opens a SCTP stream over a conn
    pub async fn client(config: Config) -> Result<Self> {
        let (a, mut handshake_completed_ch_rx) = Association::new(config, true).await?;

        if let Some(err_opt) = handshake_completed_ch_rx.recv().await {
            if let Some(err) = err_opt {
                Err(err)
            } else {
                Ok(a)
            }
        } else {
            Err(Error::ErrAssociationHandshakeClosed)
        }
    }

    /// Shutdown initiates the shutdown sequence. The method blocks until the
    /// shutdown sequence is completed and the connection is closed, or until the
    /// passed context is done, in which case the context's error is returned.
    pub async fn shutdown(&self) -> Result<()> {
        log::debug!("[{}] closing association..", self.name);

        let state = self.get_state();
        if state != AssociationState::Established {
            return Err(Error::ErrShutdownNonEstablished);
        }

        // Attempt a graceful shutdown.
        self.set_state(AssociationState::ShutdownPending);

        if self.inflight_queue_length.load(Ordering::SeqCst) == 0 {
            // No more outstanding, send shutdown.
            self.will_send_shutdown.store(true, Ordering::SeqCst);
            let _ = self.awake_write_loop_ch.try_send(());
            self.set_state(AssociationState::ShutdownSent);
        }

        {
            let mut close_loop_ch_rx = self.close_loop_ch_rx.lock().await;
            let _ = close_loop_ch_rx.recv().await;
        }

        Ok(())
    }

    /// Close ends the SCTP Association and cleans up any state
    pub async fn close(&self) -> Result<()> {
        log::debug!("[{}] closing association..", self.name);

        let _ = self.net_conn.close().await;

        let mut ai = self.association_internal.lock().await;
        ai.close().await
    }

    async fn new(config: Config, is_client: bool) -> Result<(Self, mpsc::Receiver<Option<Error>>)> {
        let net_conn = Arc::clone(&config.net_conn);

        let (awake_write_loop_ch_tx, awake_write_loop_ch_rx) = mpsc::channel(1);
        let (accept_ch_tx, accept_ch_rx) = mpsc::channel(ACCEPT_CH_SIZE);
        let (handshake_completed_ch_tx, handshake_completed_ch_rx) = mpsc::channel(1);
        let (close_loop_ch_tx, close_loop_ch_rx) = broadcast::channel(1);
        let (close_loop_ch_rx1, close_loop_ch_rx2) =
            (close_loop_ch_tx.subscribe(), close_loop_ch_tx.subscribe());
        let awake_write_loop_ch = Arc::new(awake_write_loop_ch_tx);

        let ai = AssociationInternal::new(
            config,
            close_loop_ch_tx,
            accept_ch_tx,
            handshake_completed_ch_tx,
            Arc::clone(&awake_write_loop_ch),
        );

        let bytes_received = Arc::new(AtomicUsize::new(0));
        let bytes_sent = Arc::new(AtomicUsize::new(0));
        let name = ai.name.clone();
        let state = Arc::clone(&ai.state);
        let max_message_size = Arc::clone(&ai.max_message_size);
        let inflight_queue_length = Arc::clone(&ai.inflight_queue_length);
        let will_send_shutdown = Arc::clone(&ai.will_send_shutdown);

        let mut init = ChunkInit {
            initial_tsn: ai.my_next_tsn,
            num_outbound_streams: ai.my_max_num_outbound_streams,
            num_inbound_streams: ai.my_max_num_inbound_streams,
            initiate_tag: ai.my_verification_tag,
            advertised_receiver_window_credit: ai.max_receive_buffer_size,
            ..Default::default()
        };
        init.set_supported_extensions();

        let name1 = name.clone();
        let name2 = name.clone();

        let bytes_received1 = Arc::clone(&bytes_received);
        let bytes_sent2 = Arc::clone(&bytes_sent);

        let net_conn1 = Arc::clone(&net_conn);
        let net_conn2 = Arc::clone(&net_conn);

        let association_internal = Arc::new(Mutex::new(ai));
        let association_internal1 = Arc::clone(&association_internal);
        let association_internal2 = Arc::clone(&association_internal);

        {
            let association_internal3 = Arc::clone(&association_internal);

            let mut ai = association_internal.lock().await;
            ai.t1init = Some(RtxTimer::new(
                Arc::downgrade(&association_internal3),
                RtxTimerId::T1Init,
                MAX_INIT_RETRANS,
            ));
            ai.t1cookie = Some(RtxTimer::new(
                Arc::downgrade(&association_internal3),
                RtxTimerId::T1Cookie,
                MAX_INIT_RETRANS,
            ));
            ai.t2shutdown = Some(RtxTimer::new(
                Arc::downgrade(&association_internal3),
                RtxTimerId::T2Shutdown,
                NO_MAX_RETRANS,
            )); // retransmit forever
            ai.t3rtx = Some(RtxTimer::new(
                Arc::downgrade(&association_internal3),
                RtxTimerId::T3RTX,
                NO_MAX_RETRANS,
            )); // retransmit forever
            ai.treconfig = Some(RtxTimer::new(
                Arc::downgrade(&association_internal3),
                RtxTimerId::Reconfig,
                NO_MAX_RETRANS,
            )); // retransmit forever
            ai.ack_timer = Some(AckTimer::new(
                Arc::downgrade(&association_internal3),
                ACK_INTERVAL,
            ));
        }

        tokio::spawn(async move {
            Association::read_loop(
                name1,
                bytes_received1,
                net_conn1,
                close_loop_ch_rx1,
                association_internal1,
            )
            .await;
        });

        tokio::spawn(async move {
            Association::write_loop(
                name2,
                bytes_sent2,
                net_conn2,
                close_loop_ch_rx2,
                association_internal2,
                awake_write_loop_ch_rx,
            )
            .await;
        });

        if is_client {
            let mut ai = association_internal.lock().await;
            ai.set_state(AssociationState::CookieWait);
            ai.stored_init = Some(init);
            ai.send_init()?;
            let rto = ai.rto_mgr.get_rto();
            if let Some(t1init) = &ai.t1init {
                t1init.start(rto).await;
            }
        }

        Ok((
            Association {
                name,
                state,
                max_message_size,
                inflight_queue_length,
                will_send_shutdown,
                awake_write_loop_ch,
                close_loop_ch_rx: Mutex::new(close_loop_ch_rx),
                accept_ch_rx: Mutex::new(accept_ch_rx),
                net_conn,
                bytes_received,
                bytes_sent,
                association_internal,
            },
            handshake_completed_ch_rx,
        ))
    }

    async fn read_loop(
        name: String,
        bytes_received: Arc<AtomicUsize>,
        net_conn: Arc<dyn Conn + Send + Sync>,
        mut close_loop_ch: broadcast::Receiver<()>,
        association_internal: Arc<Mutex<AssociationInternal>>,
    ) {
        log::debug!("[{}] read_loop entered", name);

        let mut buffer = vec![0u8; RECEIVE_MTU];
        let mut done = false;
        let mut n;
        while !done {
            tokio::select! {
                _ = close_loop_ch.recv() => break,
                result = net_conn.recv(&mut buffer) => {
                    match result {
                        Ok(m) => {
                            n=m;
                        }
                        Err(err) => {
                            log::warn!("[{}] failed to read packets on net_conn: {}", name, err);
                            break;
                        }
                    }
                }
            };

            // Make a buffer sized to what we read, then copy the data we
            // read from the underlying transport. We do this because the
            // user data is passed to the reassembly queue without
            // copying.
            log::debug!("[{}] recving {} bytes", name, n);
            let inbound = Bytes::from(buffer[..n].to_vec());
            bytes_received.fetch_add(n, Ordering::SeqCst);

            {
                let mut ai = association_internal.lock().await;
                if let Err(err) = ai.handle_inbound(&inbound).await {
                    log::warn!("[{}] failed to handle_inbound: {:?}", name, err);
                    done = true;
                }
            }
        }

        {
            let mut ai = association_internal.lock().await;
            if let Err(err) = ai.close().await {
                log::warn!("[{}] failed to close association: {:?}", name, err);
            }
        }

        log::debug!("[{}] read_loop exited", name);
    }

    /// DESKRALLY PATCH. Whether a failed send is a transient ROUTE failure the association should ride
    /// out (SCTP retransmits what was lost), rather than a dead transport.
    ///
    /// Upstream closes the association on ANY send error. On Windows a route that briefly vanishes
    /// (an adapter flap, a VPN reconnect, Hyper-V virtual switches re-binding) fails a UDP send with
    /// WSAEADDRNOTAVAIL (10049), WSAENETUNREACH (10051) or WSAEHOSTUNREACH (10065), and one such failure
    /// closed every data channel and ended the remote-control session. Matched on the message because
    /// the io::Error is flattened to text by the layers above (DTLS wraps it as "io error: ...").
    ///
    /// The codes are per target: an OS error number means different things on different platforms.
    /// A transient run is also BOUNDED (see [`TransientSendBudget`]): WSAEINVAL in particular can also
    /// mean a permanently bad socket, so a run longer than [`TRANSIENT_SEND_LIMIT`] closes the
    /// association exactly as upstream would have on the first failure.
    pub(crate) fn is_transient_send_error(err: &str) -> bool {
        #[cfg(windows)]
        const CODES: &[&str] = &[
            // WSAEADDRNOTAVAIL, WSAENETUNREACH, WSAEHOSTUNREACH, and WSAEINVAL, which a UDP sendto
            // returns once the route is fully gone (lab VM: 10049 first, then 10022 until restored).
            "(os error 10049)",
            "(os error 10022)",
            "(os error 10051)",
            "(os error 10065)",
        ];
        #[cfg(target_os = "linux")]
        const CODES: &[&str] = &[
            // ENETUNREACH, EADDRNOTAVAIL, EHOSTUNREACH.
            "(os error 101)",
            "(os error 99)",
            "(os error 113)",
        ];
        #[cfg(target_os = "macos")]
        const CODES: &[&str] = &[
            // EADDRNOTAVAIL, ENETUNREACH, EHOSTUNREACH.
            "(os error 49)",
            "(os error 51)",
            "(os error 65)",
        ];
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        const CODES: &[&str] = &[];
        CODES.iter().any(|c| err.contains(c))
    }

    async fn write_loop(
        name: String,
        bytes_sent: Arc<AtomicUsize>,
        net_conn: Arc<dyn Conn + Send + Sync>,
        mut close_loop_ch: broadcast::Receiver<()>,
        association_internal: Arc<Mutex<AssociationInternal>>,
        mut awake_write_loop_ch: mpsc::Receiver<()>,
    ) {
        log::debug!("[{}] write_loop entered", name);
        let done = Arc::new(AtomicBool::new(false));
        let name = Arc::new(name);
        // DESKRALLY PATCH: the current run of transient send failures (see is_transient_send_error).
        let mut transient = TransientSendBudget::default();

        while !done.load(Ordering::Relaxed) {
            //log::debug!("[{}] gather_outbound begin", name);
            let (packets, continue_loop) = {
                let mut ai = association_internal.lock().await;
                ai.gather_outbound().await
            };
            //log::debug!("[{}] gather_outbound done with {}", name, packets.len());

            let net_conn = Arc::clone(&net_conn);
            let bytes_sent = Arc::clone(&bytes_sent);
            let name2 = Arc::clone(&name);
            let done2 = Arc::clone(&done);
            let mut buffer = None;
            for raw in packets {
                let mut buf = buffer
                    .take()
                    .unwrap_or_else(|| BytesMut::with_capacity(16 * 1024));

                // We do the marshalling work in a blocking task here for a reason:
                // If we don't tokio tends to run the write_loop and read_loop of one connection on the same OS thread
                // This means that even though we release the lock above, the read_loop isn't able to take it, simply because it is not being scheduled by tokio
                // Doing it this way, tokio schedules this work on a dedicated blocking thread, this future is suspended, and the read_loop can make progress
                match tokio::task::spawn_blocking(move || raw.marshal_to(&mut buf).map(|_| buf))
                    .await
                    .unwrap()
                {
                    Ok(mut buf) => {
                        let raw = buf.as_ref();
                        if let Err(err) = net_conn.send(raw.as_ref()).await {
                            let msg = err.to_string();
                            match transient.on_failure(Self::is_transient_send_error(&msg), std::time::Instant::now()) {
                                // DESKRALLY PATCH: keep the association; the packet is retransmitted
                                // by SCTP once the route is back.
                                TransientVerdict::Keep { failures } => {
                                    if failures == 1 || failures % 100 == 0 {
                                        log::warn!("[{}] transient send failure on net_conn (keeping the association, {} so far): {}", name2, failures, msg);
                                    }
                                }
                                // Not a route failure, or a route failure that outlasted the limit:
                                // upstream behaviour (close the association).
                                TransientVerdict::Close => {
                                    log::warn!("[{}] failed to write packets on net_conn: {}", name2, err);
                                    done2.store(true, Ordering::Relaxed);
                                    // DESKRALLY PATCH: stop at once; do not send the rest of this
                                    // batch or wait for another wake-up before closing.
                                    break;
                                }
                            }
                        } else {
                            if let Some(failures) = transient.on_success() {
                                log::info!("[{}] net_conn sends recovered after {} transient failures", name2, failures);
                            }
                            bytes_sent.fetch_add(raw.len(), Ordering::SeqCst);
                        }

                        // Reuse allocation. Have to use options, since spawn blocking can't borrow, has to take ownership.
                        buf.clear();
                        buffer = Some(buf);
                    }
                    Err(err) => {
                        log::warn!("[{}] failed to serialize a packet: {:?}", name2, err);
                    }
                }
                //log::debug!("[{}] sending {} bytes done", name, raw.len());
            }

            if !continue_loop || done.load(Ordering::Relaxed) {
                break;
            }

            // DESKRALLY PATCH: a transient-failure run ends at its deadline even if nothing wakes
            // this loop (see TransientSendBudget::deadline).
            let deadline = transient.deadline();
            //log::debug!("[{}] wait awake_write_loop_ch", name);
            tokio::select! {
                _ = awake_write_loop_ch.recv() =>{}
                _ = close_loop_ch.recv() => {
                    done.store(true, Ordering::Relaxed);
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.unwrap_or_else(std::time::Instant::now))), if deadline.is_some() => {
                    log::warn!("[{}] transient send failures outlasted {:?}; closing the association", name, TRANSIENT_SEND_LIMIT);
                    done.store(true, Ordering::Relaxed);
                }
            };
            //log::debug!("[{}] wait awake_write_loop_ch done", name);
        }

        {
            let mut ai = association_internal.lock().await;
            if let Err(err) = ai.close().await {
                log::warn!("[{}] failed to close association: {:?}", name, err);
            }
        }

        log::debug!("[{}] write_loop exited", name);
    }

    /// bytes_sent returns the number of bytes sent
    pub fn bytes_sent(&self) -> usize {
        self.bytes_sent.load(Ordering::SeqCst)
    }

    /// bytes_received returns the number of bytes received
    pub fn bytes_received(&self) -> usize {
        self.bytes_received.load(Ordering::SeqCst)
    }

    /// open_stream opens a stream
    pub async fn open_stream(
        &self,
        stream_identifier: u16,
        default_payload_type: PayloadProtocolIdentifier,
    ) -> Result<Arc<Stream>> {
        let mut ai = self.association_internal.lock().await;
        ai.open_stream(stream_identifier, default_payload_type)
    }

    /// accept_stream accepts a stream
    pub async fn accept_stream(&self) -> Option<Arc<Stream>> {
        let mut accept_ch_rx = self.accept_ch_rx.lock().await;
        accept_ch_rx.recv().await
    }

    /// max_message_size returns the maximum message size you can send.
    pub fn max_message_size(&self) -> u32 {
        self.max_message_size.load(Ordering::SeqCst)
    }

    /// set_max_message_size sets the maximum message size you can send.
    pub fn set_max_message_size(&self, max_message_size: u32) {
        self.max_message_size
            .store(max_message_size, Ordering::SeqCst);
    }

    /// set_state atomically sets the state of the Association.
    fn set_state(&self, new_state: AssociationState) {
        let old_state = AssociationState::from(self.state.swap(new_state as u8, Ordering::SeqCst));
        if new_state != old_state {
            log::debug!(
                "[{}] state change: '{}' => '{}'",
                self.name,
                old_state,
                new_state,
            );
        }
    }

    /// get_state atomically returns the state of the Association.
    fn get_state(&self) -> AssociationState {
        self.state.load(Ordering::SeqCst).into()
    }
}

/// DESKRALLY PATCH. How long a continuous run of transient send failures may last before the
/// association is closed as upstream would have closed it on the first one. Longer than any route
/// flap worth surviving, and short enough that a permanently failing socket (WSAEINVAL can mean
/// that too) cannot keep an association alive while ICE still reports Connected.
#[cfg(not(test))]
pub(crate) const TRANSIENT_SEND_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);
/// Short in tests so the write-loop deadline test runs in seconds; the logic is identical.
#[cfg(test)]
pub(crate) const TRANSIENT_SEND_LIMIT: std::time::Duration = std::time::Duration::from_millis(1500);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TransientVerdict {
    Keep { failures: u64 },
    Close,
}

/// DESKRALLY PATCH. The current run of transient send failures in one write_loop.
#[derive(Default)]
pub(crate) struct TransientSendBudget {
    since: Option<std::time::Instant>,
    failures: u64,
}

impl TransientSendBudget {
    pub(crate) fn on_failure(&mut self, transient: bool, now: std::time::Instant) -> TransientVerdict {
        if !transient {
            return TransientVerdict::Close;
        }
        let since = *self.since.get_or_insert(now);
        if now.duration_since(since) > TRANSIENT_SEND_LIMIT {
            return TransientVerdict::Close;
        }
        self.failures += 1;
        TransientVerdict::Keep { failures: self.failures }
    }

    /// When the current run must end if no send has succeeded by then. The write loop waits on this
    /// as well as on its wake-ups, so the bound holds even when nothing else wakes it (an SCTP
    /// retransmission interval can reach 60 s). `None` outside a run.
    pub(crate) fn deadline(&self) -> Option<std::time::Instant> {
        self.since.map(|s| s + TRANSIENT_SEND_LIMIT)
    }

    /// A send succeeded: ends the run, returning its failure count if there was one.
    pub(crate) fn on_success(&mut self) -> Option<u64> {
        self.since = None;
        let failures = std::mem::take(&mut self.failures);
        (failures > 0).then_some(failures)
    }
}

#[cfg(test)]
mod deskrally_transient_send_tests {
    use super::{Association, TransientSendBudget, TransientVerdict, TRANSIENT_SEND_LIMIT};
    use std::time::{Duration, Instant};

    #[cfg(windows)]
    #[test]
    fn windows_route_failures_are_transient_and_others_are_not() {
        // The exact texts the agent logged in the lab VM (DTLS wraps the io::Error twice).
        assert!(Association::is_transient_send_error(
            "io error: io error: The requested address is not valid in its context. (os error 10049)"
        ));
        assert!(Association::is_transient_send_error("io error: io error: An invalid argument was supplied. (os error 10022)"));
        assert!(Association::is_transient_send_error("A socket operation was attempted to an unreachable network. (os error 10051)"));
        // Another platform's numbers mean something else here.
        assert!(!Association::is_transient_send_error("Network is unreachable (os error 101)"));
        assert!(!Association::is_transient_send_error("conn is closed"));
        assert!(!Association::is_transient_send_error("io error: An existing connection was forcibly closed by the remote host. (os error 10054)"));
        // Prefix collisions.
        assert!(!Association::is_transient_send_error("(os error 100220)"));
        assert!(!Association::is_transient_send_error("(os error 1004)"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_route_failures_are_transient_and_others_are_not() {
        assert!(Association::is_transient_send_error("Network is unreachable (os error 101)"));
        assert!(!Association::is_transient_send_error("(os error 10049)"));
        assert!(!Association::is_transient_send_error("(os error 990)"));
        assert!(!Association::is_transient_send_error("(os error 1013)"));
    }

    use super::AssociationState;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use util::conn::Conn;

    /// A UDP conn whose sends fail with `fail_with` (an OS error code) once it is non-zero.
    struct FlakyConn {
        inner: UdpSocket,
        fail_with: AtomicI32,
    }

    #[async_trait::async_trait]
    impl Conn for FlakyConn {
        async fn connect(&self, a: std::net::SocketAddr) -> util::Result<()> { Conn::connect(&self.inner, a).await }
        async fn recv(&self, b: &mut [u8]) -> util::Result<usize> { Conn::recv(&self.inner, b).await }
        async fn recv_from(&self, b: &mut [u8]) -> util::Result<(usize, std::net::SocketAddr)> { Conn::recv_from(&self.inner, b).await }
        async fn send(&self, b: &[u8]) -> util::Result<usize> {
            match self.fail_with.load(Ordering::SeqCst) {
                0 => Conn::send(&self.inner, b).await,
                code => Err(std::io::Error::from_raw_os_error(code).into()),
            }
        }
        async fn send_to(&self, b: &[u8], t: std::net::SocketAddr) -> util::Result<usize> { Conn::send_to(&self.inner, b, t).await }
        fn local_addr(&self) -> util::Result<std::net::SocketAddr> { Conn::local_addr(&self.inner) }
        fn remote_addr(&self) -> Option<std::net::SocketAddr> { Conn::remote_addr(&self.inner) }
        async fn close(&self) -> util::Result<()> { Conn::close(&self.inner).await }
        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) { self }
    }

    #[cfg(windows)]
    const ROUTE_ERROR: i32 = 10022; // WSAEINVAL, as seen in the lab VM
    #[cfg(target_os = "linux")]
    const ROUTE_ERROR: i32 = 101; // ENETUNREACH
    #[cfg(target_os = "macos")]
    const ROUTE_ERROR: i32 = 51; // ENETUNREACH
    #[cfg(windows)]
    const FATAL_ERROR: i32 = 10054; // WSAECONNRESET: not a route failure
    #[cfg(not(windows))]
    const FATAL_ERROR: i32 = 104; // ECONNRESET on linux; any non-listed code serves

    const PPI: crate::chunk::chunk_payload_data::PayloadProtocolIdentifier =
        crate::chunk::chunk_payload_data::PayloadProtocolIdentifier::Binary;

    /// An established client/server pair over loopback UDP, the client's sends routed through
    /// FlakyConn, and one stream on which a message has already been delivered.
    async fn flaky_pair() -> (Association, Association, Arc<FlakyConn>, Arc<crate::stream::Stream>) {
        let udp1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp1.connect(udp2.local_addr().unwrap()).await.unwrap();
        udp2.connect(udp1.local_addr().unwrap()).await.unwrap();
        let flaky = Arc::new(FlakyConn { inner: udp1, fail_with: AtomicI32::new(0) });
        let server = tokio::spawn(async move {
            Association::server(crate::association::Config {
                net_conn: Arc::new(udp2), max_receive_buffer_size: 0, max_message_size: 0, name: "server".to_owned(),
            }).await
        });
        let client = Association::client(crate::association::Config {
            net_conn: flaky.clone(), max_receive_buffer_size: 0, max_message_size: 0, name: "client".to_owned(),
        }).await.expect("client association");
        let server = server.await.unwrap().expect("server association");
        let s = client.open_stream(1, PPI).await.unwrap();
        s.write_sctp(&bytes::Bytes::from_static(b"before"), PPI).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_ne!(client.get_state(), AssociationState::Closed, "premise: the association is up");
        (client, server, flaky, s)
    }

    /// Poll until the association is Closed or `within` passes; returns when it closed.
    async fn closed_within(a: &Association, t0: std::time::Instant, within: std::time::Duration) -> Option<std::time::Duration> {
        while t0.elapsed() < within {
            if a.get_state() == AssociationState::Closed {
                return Some(t0.elapsed());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        None
    }

    /// The bound must hold with NO further wake-up: one failed send, then silence. Before the deadline
    /// arm the run was only re-checked on the next failed send (the next retransmission: ~3 s here,
    /// up to 60 s in the field), so the association outlived TRANSIENT_SEND_LIMIT.
    #[tokio::test]
    async fn a_failing_run_closes_the_association_at_the_deadline_without_another_wakeup() {
        let (client, _server, flaky, s) = flaky_pair().await;
        flaky.fail_with.store(ROUTE_ERROR, Ordering::SeqCst);
        let t0 = std::time::Instant::now();
        s.write_sctp(&bytes::Bytes::from_static(b"during"), PPI).await.unwrap();

        // Kept while the run is young: the patch's whole point.
        tokio::time::sleep(TRANSIENT_SEND_LIMIT / 2).await;
        assert_ne!(client.get_state(), AssociationState::Closed, "closed before the transient limit");

        let closed_at = closed_within(&client, t0, TRANSIENT_SEND_LIMIT + std::time::Duration::from_secs(5))
            .await
            .expect("a failing run never closed the association");
        assert!(closed_at <= TRANSIENT_SEND_LIMIT + std::time::Duration::from_millis(600),
            "closed at {closed_at:?}, well after the {TRANSIENT_SEND_LIMIT:?} limit");
    }

    /// A send error that is NOT a route failure closes the association at once, as upstream did:
    /// not after the rest of the batch, and not at the next wake-up (the next retransmission).
    #[tokio::test]
    async fn a_fatal_send_error_closes_the_association_without_waiting_for_a_wakeup() {
        let (client, _server, flaky, s) = flaky_pair().await;
        flaky.fail_with.store(FATAL_ERROR, Ordering::SeqCst);
        let t0 = std::time::Instant::now();
        s.write_sctp(&bytes::Bytes::from_static(b"during"), PPI).await.unwrap();
        let closed_at = closed_within(&client, t0, std::time::Duration::from_secs(5))
            .await
            .expect("a fatal send error never closed the association");
        assert!(closed_at <= std::time::Duration::from_millis(500),
            "closed at {closed_at:?}: it waited for another wake-up");
    }

    #[test]
    fn a_non_transient_failure_closes_at_once() {
        let mut b = TransientSendBudget::default();
        assert_eq!(b.on_failure(false, Instant::now()), TransientVerdict::Close);
    }

    #[test]
    fn a_transient_run_is_kept_until_the_limit_then_closed() {
        let mut b = TransientSendBudget::default();
        let t0 = Instant::now();
        assert_eq!(b.on_failure(true, t0), TransientVerdict::Keep { failures: 1 });
        assert_eq!(b.on_failure(true, t0 + TRANSIENT_SEND_LIMIT), TransientVerdict::Keep { failures: 2 });
        assert_eq!(b.on_failure(true, t0 + TRANSIENT_SEND_LIMIT + Duration::from_millis(1)), TransientVerdict::Close);
    }

    #[test]
    fn a_success_starts_a_fresh_run() {
        let mut b = TransientSendBudget::default();
        let t0 = Instant::now();
        b.on_failure(true, t0);
        b.on_failure(true, t0 + Duration::from_secs(1));
        assert_eq!(b.on_success(), Some(2));
        assert_eq!(b.on_success(), None);
        // The new run is measured from its own first failure, not from t0.
        let t1 = t0 + TRANSIENT_SEND_LIMIT + Duration::from_secs(5);
        assert_eq!(b.on_failure(true, t1), TransientVerdict::Keep { failures: 1 });
        assert_eq!(b.on_failure(true, t1 + TRANSIENT_SEND_LIMIT), TransientVerdict::Keep { failures: 2 });
    }
}
