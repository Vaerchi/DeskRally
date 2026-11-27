//! docs/73 2.2.2-2.2.5, build step (c): the host's side of request-for-control, kept free of the
//! session loop so it can be tested without a transport.
//!
//! * [`handle_inbound`] routes one viewer message to the hub entry point and says what the session loop
//!   must do next (answer the announce, run the hand job, tell the holder a hand-off is already running).
//!   Every reply to the requester is a hub directive queued under `core`; nothing here answers it directly.
//! * [`wire_of`] turns one routed [`Directive`] into the control message or the audit action the SESSION
//!   LOOP puts on its own transport / seals into its own chain, in queue order. The loop calls it for every
//!   `HandoffOutbound::Request`.
//!
//! The feature gate (`input_request_v1`) is checked here: with it off the announce is dropped, nobody ever
//! becomes request-capable, and the hub therefore queues nothing for anyone.

#![cfg_attr(not(windows), allow(dead_code))]

use std::time::Instant;

use rmt_agent::backstage::audit::{AuditAction, InputRequestAuditOutcome};
use rmt_agent_core::control::{ControlMessage, InputRequestOutcome, InputRequestState};
use uuid::Uuid;

use crate::input_request::{
    AuditRecord, Directive, HolderMsg, Outcome, Refusal, ReqState, RequesterMsg, Resolved, WithdrawReason,
};
use crate::shared_capture::{AcceptGate, AnswerResult, InputArbiterHub};

/// What the session loop does with one routed directive.
#[derive(Debug, Clone)]
pub(crate) enum Wire {
    /// Send on this session's control channel.
    Control(ControlMessage),
    /// Seal into THIS session's audit chain and send the sealed event on THIS transport.
    Seal(AuditAction),
}

fn state_wire(s: ReqState) -> InputRequestState {
    match s {
        ReqState::PendingDelivery => InputRequestState::PendingDelivery,
        ReqState::Shown => InputRequestState::Shown,
        ReqState::AcceptedInFlight => InputRequestState::AcceptedInFlight,
    }
}

fn outcome_wire(o: Outcome) -> InputRequestOutcome {
    match o {
        Outcome::Granted => InputRequestOutcome::Granted,
        Outcome::Declined => InputRequestOutcome::Declined,
        Outcome::Expired => InputRequestOutcome::Expired,
        Outcome::Undelivered => InputRequestOutcome::Undelivered,
        Outcome::Cancelled => InputRequestOutcome::Cancelled,
        Outcome::Replaced => InputRequestOutcome::Replaced,
        Outcome::HolderChanged => InputRequestOutcome::HolderChanged,
        Outcome::AlreadySatisfied => InputRequestOutcome::AlreadySatisfied,
        Outcome::Failed => InputRequestOutcome::Failed,
        Outcome::Ineligible => InputRequestOutcome::Ineligible,
    }
}

fn audit_outcome(o: Outcome) -> InputRequestAuditOutcome {
    match o {
        Outcome::Granted => InputRequestAuditOutcome::Granted,
        Outcome::Declined => InputRequestAuditOutcome::Declined,
        Outcome::Expired => InputRequestAuditOutcome::Expired,
        Outcome::Undelivered => InputRequestAuditOutcome::Undelivered,
        Outcome::Cancelled => InputRequestAuditOutcome::Cancelled,
        Outcome::Replaced => InputRequestAuditOutcome::Replaced,
        Outcome::HolderChanged => InputRequestAuditOutcome::HolderChanged,
        Outcome::AlreadySatisfied => InputRequestAuditOutcome::AlreadySatisfied,
        Outcome::Failed => InputRequestAuditOutcome::Failed,
        Outcome::Ineligible => InputRequestAuditOutcome::Ineligible,
    }
}

fn resolved_wire(r: Resolved) -> InputRequestOutcome {
    match r {
        Resolved::Outcome(o) => outcome_wire(o),
        Resolved::Refusal(Refusal::Ineligible) => InputRequestOutcome::Ineligible,
        Resolved::Refusal(Refusal::NoHolder) => InputRequestOutcome::NoHolder,
        Resolved::Refusal(Refusal::Busy) => InputRequestOutcome::Busy,
        Resolved::Refusal(Refusal::RateLimited) => InputRequestOutcome::RateLimited,
        Resolved::Refusal(Refusal::Capacity) => InputRequestOutcome::Capacity,
        Resolved::Refusal(Refusal::UnsupportedHolder) => InputRequestOutcome::UnsupportedHolder,
        Resolved::Unknown => InputRequestOutcome::Unknown,
    }
}

/// The audit action for one routed audit record.
pub(crate) fn audit_action_of(record: &AuditRecord) -> AuditAction {
    match *record {
        AuditRecord::Requested { request_id, ids, epoch } => AuditAction::InputControlRequested {
            request_id,
            requester_session: ids.requester_session,
            requester_technician: ids.requester_technician,
            holder_session: ids.holder_session,
            holder_technician: ids.holder_technician,
            epoch,
        },
        AuditRecord::Closed { request_id, ids, epoch, outcome } => AuditAction::InputControlRequestClosed {
            request_id,
            requester_session: ids.requester_session,
            requester_technician: ids.requester_technician,
            holder_session: ids.holder_session,
            holder_technician: ids.holder_technician,
            epoch,
            outcome: audit_outcome(outcome),
        },
    }
}

/// Turn one routed directive into what the session loop sends. `sid_of` resolves an arbiter handle to the
/// signaling session id the viewers use; a prompt whose requester has already left yields `None` (the hub
/// withdraws it separately), so the prompt is never sent for a requester nobody can name.
pub(crate) fn wire_of(d: &Directive, sid_of: impl Fn(u64) -> Option<String>) -> Option<Wire> {
    match d {
        Directive::ToRequester { msg: RequesterMsg::Pending { client_request_id, request_id, state }, .. } => {
            Some(Wire::Control(ControlMessage::InputControlRequestPending {
                client_request_id: client_request_id.to_string(),
                request_id: request_id.to_string(),
                state: state_wire(*state),
            }))
        }
        Directive::ToRequester { msg: RequesterMsg::Result { client_request_id, request_id, outcome }, .. } => {
            Some(Wire::Control(ControlMessage::InputControlRequestResult {
                client_request_id: client_request_id.to_string(),
                request_id: request_id.map(|r| r.to_string()),
                outcome: resolved_wire(*outcome),
            }))
        }
        Directive::ToHolder { msg: HolderMsg::Requested { request_id, from, expires_in_ms }, .. } => {
            let from_session = sid_of(*from)?;
            Some(Wire::Control(ControlMessage::InputControlRequested {
                request_id: request_id.to_string(),
                from_session,
                expires_in_ms: *expires_in_ms,
            }))
        }
        Directive::ToHolder { msg: HolderMsg::Withdrawn { request_id, reason }, .. } => {
            let reason = match reason {
                WithdrawReason::Outcome(o) => outcome_wire(*o),
                WithdrawReason::RequesterLeft => InputRequestOutcome::RequesterLeft,
                WithdrawReason::Unknown => InputRequestOutcome::Unknown,
            };
            Some(Wire::Control(ControlMessage::InputControlRequestWithdrawn {
                request_id: request_id.to_string(),
                reason,
            }))
        }
        Directive::Audit { record, .. } => Some(Wire::Seal(audit_action_of(record))),
    }
}

/// What the session loop must do after [`handle_inbound`].
#[derive(Debug)]
pub(crate) enum Inbound<P> {
    /// Nothing more: dropped, or the hub queued every reply itself.
    Nothing,
    /// Send this control message to THIS session (the answer to the announce).
    Reply(ControlMessage),
    /// The accept was CONSUMED: run `SharedCapture::hand_input_control_for_request(handle, request_id,
    /// deadline)` off the loop, holding `permits` until it returns.
    SpawnHand { request_id: Uuid, deadline: Instant, permits: P },
    /// The hand slot or the machine permit was busy: tell the holder (the existing "busy" error text).
    HolderBusy,
}

/// One session's view for [`handle_inbound`].
pub(crate) struct InboundCtx<'a> {
    pub hub: &'a InputArbiterHub,
    /// This session's own arbiter handle; never taken from a message.
    pub handle: u64,
    /// The `input_request_v1` feature gate.
    pub request_v1: bool,
    pub observer: bool,
}

/// Route one viewer message of the request-for-control set. `acquire` takes the holder's `HandSlot` and the
/// machine permit (BEFORE consumption, as for a plain hand); it is called only for an accept, and a `None`
/// means one of them is busy. Any other message returns `Nothing`.
pub(crate) fn handle_inbound<P>(
    ctx: &InboundCtx<'_>,
    msg: &ControlMessage,
    now: Instant,
    acquire: impl FnOnce() -> Option<P>,
) -> Inbound<P> {
    if !ctx.request_v1 {
        // Feature off: no advertisement, no state, no reply of any kind (a reply could be undecodable
        // by an older console, and an audit record could be undecodable by an older control plane).
        tracing::debug!(handle = ctx.handle, "input request: dropped (input_request_v1 is off)");
        return Inbound::Nothing;
    }
    let parse = |s: &str| Uuid::parse_str(s).ok();
    match msg {
        ControlMessage::InputRequestCapable {} => {
            ctx.hub.set_request_capable(ctx.handle);
            Inbound::Reply(ControlMessage::InputRequestAvailable { available: !ctx.observer })
        }
        ControlMessage::RequestInputControl { client_request_id, retry } => {
            if let Some(id) = parse(client_request_id) {
                ctx.hub.request_input(ctx.handle, id, *retry, now);
            }
            Inbound::Nothing
        }
        ControlMessage::WithdrawInputControlRequest { client_request_id } => {
            if let Some(id) = parse(client_request_id) {
                ctx.hub.withdraw_request(ctx.handle, id, now);
            }
            Inbound::Nothing
        }
        ControlMessage::InputControlPromptShown { request_id } => {
            if let Some(id) = parse(request_id) {
                ctx.hub.prompt_shown(ctx.handle, id, now);
            }
            Inbound::Nothing
        }
        ControlMessage::AnswerInputControlRequest { request_id, accept } => {
            let Some(id) = parse(request_id) else { return Inbound::Nothing };
            // The slot and the permit are taken BEFORE consumption; a decline needs neither.
            let held = if *accept { acquire() } else { None };
            let gate = if !*accept || held.is_some() { AcceptGate::Held } else { AcceptGate::Unavailable };
            match ctx.hub.answer_request(ctx.handle, id, *accept, gate, now) {
                AnswerResult::Consumed { request_id, deadline } => match held {
                    Some(permits) => Inbound::SpawnHand { request_id, deadline, permits },
                    // Cannot happen: Consumed needs `Held`, and an accept holds both. Never run a hand
                    // without its permits.
                    None => {
                        tracing::error!("input request: consumed without permits; aborting");
                        ctx.hub.abort_request(request_id, now);
                        Inbound::Nothing
                    }
                },
                AnswerResult::FailedBusy => Inbound::HolderBusy,
                AnswerResult::Declined | AnswerResult::Ignored | AnswerResult::Withdrawn | AnswerResult::NoEffect => {
                    Inbound::Nothing
                }
            }
        }
        _ => Inbound::Nothing,
    }
}

#[cfg(test)]
#[path = "request_wire_tests.rs"]
mod tests;
