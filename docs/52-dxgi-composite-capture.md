# 52 — Composite capture from persistent per-output DXGI duplications

Status: **DESIGN ACCEPTED by Codex at round 5** (13 findings over rounds 1-4, all taken; see §9). Implementation next. Target: agent 1.3.11. Owner: developer Claude. 2026-10-25.

## 1. Why

The multi-monitor "canvas" stream is the only capture path production uses (the helper is locked to
it), and today every canvas frame is ONE GDI `BitBlt` of the whole virtual desktop
(`FollowingCapturer::capture_composite` → `CaptureLoop::capture_virtual_desktop` →
`GdiCapturer::capture_rect`).

Measured (docs: memory `gdi-composite-capture-is-the-cpu-cost`, 2026-10-24):

| machine | per canvas frame | note |
|---|---|---|
| the RTX 3060 test system, RTX 3060, 2 monitors, 3840x1080 | 52.8 ms (1.3.9) → 34.6 ms (1.3.10 cached surface) | `BitBlt` alone 36 ms, ~8 ms of it a fixed per-call GPU→CPU sync |
| lab VM, 1024x768, no GPU, idle | ~45 ms | `BitBlt` ~40 ms per call whatever the size |

1.3.10 makes capture run only as fast as viewers ask and drops hidden viewers to 1 fps, but a
visible session on a two-monitor box still needs ~35 ms per frame against a 33 ms budget at 30 fps:
one core, all session long, **even when nothing on screen moves** — GDI cannot tell an idle screen
from a busy one.

DXGI Desktop Duplication (DDA) is the opposite on both counts: the GPU does the composition, a frame
costs a few ms of CPU (copy + map of what changed), and an idle screen produces no frames at all.

## 2. What went wrong before (constraints this design must respect)

1. **"View all" was black on multi-monitor boxes** (memory `multi-monitor-capture-by-rect`): the old
   composite captured monitor 0 then 1 through ONE `DxgiCapturer`, which tears down and recreates its
   single duplication whenever the output changes, and **a fresh duplication's first frame is blank**
   (`LastPresentTime == 0`). → This design keeps one PERSISTENT duplication per output and never
   reads a blank first frame as a picture.
2. **The stitch had the wrong geometry** (a left-to-right strip). → This design places each output at
   its true virtual-desktop offset; the canvas is exactly the virtual-desktop rect the GDI composite
   blits today, which is what `MOUSEEVENTF_VIRTUALDESK` normalises against and what
   `monitor_canvas::layout()` / the `BroadcastCapturer` geometry check expect.
3. **DDA yields only on CHANGE** (memory `idle-case-needs-an-explicit-answer`): an idle screen must
   be "no news", never a fall-through to another tier, never a blank frame.
4. **`DuplicateOutput` is adapter-bound**: the D3D device must live on the adapter owning the output
   (the RTX 3060 test system has an RTX 3060, an Intel UHD 750 and a "Meta Virtual Monitor"). → One device per
   adapter, shared by that adapter's outputs.
5. **Indirect displays have no DXGI output** (DisplayLink/USB docks/Miracast, possibly virtual
   monitors). → Such a monitor's region keeps being served by GDI (`BitBlt` of just its rect).
6. **Monitor ids are GDI-positional and addressed by RECT** (the "blink" was two tiers disagreeing
   about which panel an id meant). → A DXGI output serves a canvas region only when its
   `DesktopCoordinates` equal a GDI monitor rect EXACTLY (`match_output_rect`); otherwise GDI serves
   that region.
7. **WGC poisons `SetThreadDesktop`.** DDA does not (measured: `dxgi_leaves_the_thread_able_to_switch_desktops`).
   WGC stays out.
8. **DDA cannot read the secure desktop, and returns black as a SUCCESS under RDP.** → Secure desktop
   and remote sessions keep today's GDI composite, unchanged.
9. **On the lab VM, DDA yields NO frames unless a Hyper-V console is attached**, while
   `DuplicateOutput` still succeeds (memory `know-what-the-vm-cannot-prove`). A silent DDA failure
   would freeze the picture → the GDI self-check in §4.5.
10. **Privacy mode and the presence pill rely on `WDA_EXCLUDEFROMCAPTURE`.** DDA is documented to
    honour display affinity like `BitBlt` does, but this is the product's privacy guarantee →
    acceptance must prove it on DDA (§7), and a failure there blocks the release.

**Measured on the RTX 3060 test system, 2026-10-25** (`agent_host monitors --all-tiers`, read-only): two
1920x1080 monitors at (0,0) and (1920,0), BOTH DXGI outputs on the RTX 3060 with rects equal to the
GDI rects; DXGI and GDI captures of the static monitor are byte-identical (sig `e9d033ab181f3e2a`),
which is what seeding (§4.2) relies on; the "Meta Virtual Monitor" adapter drives no display; the
current GDI composite costs 38 ms warm. Multi-adapter and indirect displays are NOT present here and
stay unproven on hardware (unit-tested only).

## 3. Scope

- **In:** the canvas (composite) capture on the Default desktop of a console session.
- **Unchanged:** secure desktop (Winlogon, UAC, lock screen) and RDP → today's GDI composite;
  per-monitor (pinned, non-canvas) capture → today's `CaptureLoop` chain; input; encoding; the wire.
- **Not in:** cursor drawing, move rects, rotated outputs via DDA (served by GDI, §4.1), WGC.
- **Cursor, qualified:** neither path DRAWS the pointer (GDI blits without `CAPTUREBLT`, DDA's pointer
  shape is never read). A *software* cursor that Windows composes into the desktop image (common in
  VMs, some drivers) appears in BOTH paths' pixels alike. Acceptance checks that the VM stream shows
  the same cursor behaviour on DDA as on GDI.

## 4. Design

### 4.1 Components

A new `DxgiCanvas` (new module `dxgi_canvas.rs`) owned by `CaptureLoop`, built lazily on the first
canvas capture on a non-secure, non-remote desktop:

```
DxgiCanvas
  rect: (vx, vy, vw, vh)            // the virtual-desktop rect, same as capture_virtual_desktop's
  canvas: Vec<u8>                   // vw*vh*4 BGRA, persistent, the last composed picture
  devices: Vec<AdapterDevice>       // one D3D11 device+context per adapter LUID in use
  regions: Vec<Region>              // one per GDI monitor rect, in GDI positional order
  changed: bool                     // canvas differs from the last frame handed out
  last_gdi_check: Instant

Region
  rect (virtual-desktop coords) and its canvas offset
  valid: bool                       // the canvas holds a real picture for this region
  last_good: Instant                // last time this region's pixels were CONFIRMED current (§4.2)
  source: Dxgi { device idx, output, dupl, staging, desc, mismatch_strikes, recreate_failures,
                 dda_image: Vec<u8>,   // the region as DDA last delivered it (or as seeded);
                                       // never overwritten by a self-check repair (§4.5)
                 quarantined: bool }   // presented from GDI while DDA is only CHECKED (§4.5)
        | Gdi  { reason }            // indirect display, rotated output, rect/size/format mismatch,
                                     // repeated failure, self-check demotion
```

The monitor table comes from the CHECKED enumeration (`enumerate_monitors_checked`): a partial or
failed enumeration builds no canvas (the GDI composite runs), never a canvas with missing regions.

`DxgiCanvas::new` enumerates GDI monitors (authoritative), resolves each rect to a DXGI output with
`match_output_rect`, and creates the duplication on the owning adapter's device. Every creation
(first or after a loss) re-reads the output's `DXGI_OUTDUPL_DESC` and checks: `Rotation == IDENTITY`,
`ModeDesc` width/height equal to the region rect, format `DXGI_FORMAT_B8G8R8A8_UNORM`. A monitor with
no matching output, any of those checks failing, or `DuplicateOutput` failing becomes a `Gdi` region.
Every acquired texture's description is checked against the region (size, format) before copying;
a mismatch drops the duplication and counts a recreate failure. If NO region is `Dxgi`, the canvas is not built and
the caller keeps the existing GDI composite (§4.6).

### 4.2 One canvas capture

```
for each Dxgi region:
    if no duplication: (re)create it (§4.1 checks); on failure recreate_failures += 1
                       (3 in a row -> region becomes Gdi), and treat this call as for a Gdi region
    if !valid: GDI-blit the region's rect; ONLY on success copy it into the canvas AND dda_image,
               valid = true, last_good = now, changed = true
    AcquireNextFrame(timeout 0)
      WAIT_TIMEOUT           -> nothing new for this region
      ok, LastPresentTime==0 -> no new image (pointer-only or the first acquire): nothing (ReleaseFrame)
      ok, image              -> check desc; CopyResource -> staging; Map; copy rows into dda_image
                                and, unless quarantined, into the canvas at the region offset (row
                                pitch respected); Unmap; ReleaseFrame; if not quarantined:
                                valid = true, changed = true
      ACCESS_LOST            -> drop this duplication; next call recreates it and re-seeds (valid = false)
      DEVICE_REMOVED/RESET   -> drop the ADAPTER's device, every duplication and staging texture on it;
                                all its regions valid = false; next call rebuilds and re-seeds them
      other error            -> as ACCESS_LOST and recreate_failures += 1
for each Gdi region AND each quarantined Dxgi region:
                     GDI-blit its rect; on success copy in, valid = true, last_good = now,
                     changed = true; on failure keep its last pixels, count a degraded-region failure
self-check (§4.5) when due (it is what refreshes a Dxgi region's last_good)
publishable = every region valid AND every region's last_good within 5 s
if !publishable:          THIS CALL ONLY: publish a whole-desktop GDI composite frame instead (today's
                          path), counted as "fallback frame"; the canvas is KEPT and recovery
                          continues on the next call (a lost duplication is recreated and its region
                          re-seeded at the start of that call, so an ordinary ACCESS_LOST recovers
                          within one paced interval). If the canvas has not been publishable
                          continuously for 5 s, it is dropped and the GDI composite serves until the
                          next desktop switch rebuilds it ("demoted"), logged at warn with the reason.
                          A region that cannot be confirmed current never publishes beside healthy
                          ones: the fallback frame is a fresh whole-desktop GDI picture.
else if a join is pending (§4.3) or changed:
                          publish the complete canvas; changed = false; acknowledge the join snapshot
else:                     "no news"
```

- **Health is separate from validity.** `valid` says the canvas has real pixels for a region;
  `last_good` says they were confirmed current recently: by a successful GDI blit for a Gdi region,
  and by a successful self-check (§4.5) for a Dxgi region. Telemetry counts produced / unchanged /
  not-ready / degraded-region failures separately, including failures of regions in a published
  canvas.
- **Seeding solves the blank first frame**: a new duplication's region is filled by one successful
  GDI blit before anything is published, so a still desktop shows its real picture immediately; from
  then on DDA updates it. A failed seed leaves the region invalid and nothing is published for it. GDI and DDA
  read the same pixels (measured byte-identical on the build box, memory `multi-monitor-capture-by-rect`).
- **Timeout 0**: the producer already paces to the viewers' demand (1.3.10); a capture call never
  waits on an idle output. Total cost of an idle call = N non-blocking `AcquireNextFrame`s.
- **First version copies the WHOLE output on change** (one `CopyResource` + one map). Dirty-rect
  partial readback is a measured follow-up (§8), not a starting assumption.
- **Gaps** in the bounding rect (monitors of different heights) stay black, as the GDI blit of an
  off-screen area returns today.

### 4.3 Idle, and a viewer joining an idle stream

An idle desktop: every region times out → `changed == false` → "no news". The shared producer
then broadcasts nothing; each session's capture pull sees no frame within its wait and the session
keep-alive re-sends its last frame exactly as it does for any capture miss today (keep-alive floor
for visible viewers, nothing for background ones). The shared producer treats "no news" as NOT a
failure and keeps its pacing (it already stamps `last_canvas_frame` before every attempt).

**A viewer that joins (or reconnects to) an idle stream has no last frame**, and with "no news" the
producer would never send it one. So every join forces one fresh, complete publication — never a
cached one, so it can never show a desktop the machine has since left:

- `SharedCapture::subscribe()` creates the receiver FIRST, then increments a `joins: AtomicU64`.
  Every subscription counts, however briefly the previous viewers were gone, so no gap can be
  missed (the counter, not `receiver_count()`, is what the producer watches).
- The producer reads a SNAPSHOT of `joins` before each capture and, only after a successful
  publication (canvas or fallback frame), records that snapshot as served; a subscription racing the
  publication moves the counter past the snapshot and stays pending for the next slot.
- At its next paced slot the producer sees `joins` moved, and the capture call runs exactly as any
  capture does: it polls the desktop follower first (a switch invalidates and rebuilds, re-seeding
  every region), acquires every region, self-checks if due — and then publishes the complete
  canvas even when nothing changed, provided every region is valid and healthy (§4.2). The new
  receiver already exists, so it gets that frame; existing viewers get one duplicate frame.
- Across a period with no viewers the producer captured nothing; the canvas may be behind. The
  forced capture brings it current: DDA hands over the accumulated latest image of any output that
  changed (or `ACCESS_LOST` after a desktop switch in between, which re-seeds), an unchanged output
  is current by definition, and a desktop-name change is caught by the follower poll.
- If the canvas cannot publish this call, the fallback frame (§4.2) is a fresh whole-desktop GDI
  picture and serves the join, so a joining viewer is never left waiting.

Tests: idle disconnect/reconnect with a producer-observed zero-receiver interval and no desktop
change (gets a frame); disconnect, desktop switch and resubscribe entirely between two producer
iterations (gets the current desktop); lock and UAC with every viewer gone, then reconnect (gets the
secure desktop, never the old Default image); a second viewer joining an idle stream.

### 4.4 Desktop switches, mode changes, topology

- A desktop switch already calls `CaptureLoop::invalidate()` (FollowingCapturer); it drops the
  whole `DxgiCanvas`. On the secure desktop the GDI composite runs (unchanged); on the way back a new
  canvas is built and seeded.
- `ACCESS_LOST` on a region (mode change, full-screen exclusive app, the desktop switch racing the
  poll) → that region alone is rebuilt and re-seeded next call.
- A monitor-table change (hotplug, resolution) ends the session today via the topology guard; the
  canvas is also rebuilt when the GDI table it was built from differs from the current one.

### 4.5 Self-check against a silent or wrong DDA (the frozen-picture risk)

Every 2 s, EVERY Dxgi region is GDI-blitted and compared over ALL its pixels (RGB, alpha ignored)
with that region's **`dda_image`** — what DDA itself last delivered (or the seed) — immediately
after that call's DDA acquire for the region. The comparison is with the SOURCE, not with the
presented canvas, so a repair can never make a broken duplication look healthy. Frame ARRIVAL plays
no part in the verdict: a duplication that keeps delivering stale or black images is judged by its
content exactly like one that delivers nothing.

- GDI blit failed → the check counts as failed; `last_good` is not refreshed (so 5 s of failed checks
  drop the canvas to the GDI composite, §4.2).
- Equal → `mismatch_strikes = 0`, `last_good = now`.
- Different → the GDI pixels are written into the CANVAS at once (`changed = true`), `last_good =
  now`, `mismatch_strikes += 1`, and the region is **quarantined**: from the next call on it is
  PRESENTED from GDI (blitted every call, like a Gdi region) while DDA keeps being acquired into
  `dda_image` only. A duplication delivering stale or black images can therefore never overwrite a
  repair. `dda_image` is left as DDA delivered it.
- While quarantined, the 2 s check keeps comparing GDI with `dda_image`: equal → `mismatch_strikes = 0`
  and the quarantine is lifted (DDA presentation resumes); different → `mismatch_strikes += 1`.
- 3 consecutive mismatches → the region becomes `Gdi` for the rest of this canvas's life, logged at
  `warn` with the output name and the differing-pixel fraction.
- Recovery bound: no published frame shows a wrong region for longer than the 2 s check interval, and
  never again after the repair; a broken duplication is demoted within 6 s.

Examples the tests pin: (a) DDA silently stops; the desktop changes once; the next check repairs and
quarantines (strike 1); because `dda_image` still holds the pre-change picture, the next two checks on
a now-still desktop mismatch again (strikes 2, 3) → demoted at 6 s. (b) DDA keeps delivering a stale
or black image between checks: after the first repair no published frame regresses (the region is
presented from GDI). (c) A busy screen mismatches once by timing, then DDA catches up: the next check
is equal and DDA presentation resumes.

Recovery bound: a silently frozen or wrong region is repaired within 2 s and demoted within 6 s.
A screen that changes between the two reads (video, a scrolling log) can also mismatch; the cost of
that false demotion is GDI cost for that region until the next desktop switch, never a wrong picture.
The acceptance runs measure how often that happens under continuous motion (§7).

Cost: one GDI blit of each DDA region every 2 s plus a full compare (~2 ms per 1080p region) —
on the RTX 3060 test system about 40 ms of work per 2 s, ~2 % of one core.

### 4.6 Selection and escape hatch

`CaptureLoop::capture_virtual_desktop(secure, remote)`: secure or remote → GDI composite (today).
Otherwise `DxgiCanvas` if it can be built, else GDI composite. The tier log line distinguishes
`dxgi-canvas` from `gdi-composite`, and the "shared capture rate" debug line gains the per-region
sources.

Escape hatch: `"canvas_capture": "gdi"` in the agent's `config.json` (read by the helper at start,
like every other `HelperConfig` field; any other value or absence = DDA). Restarting the RmtAgent
service applies it. For a field problem the deployment session can set it on one machine without a
release. An environment variable was rejected: the service spawns the helper into the user session
with its own environment block, so a service-environment value is not guaranteed to reach it.

### 4.7 Threading

Everything runs on the `FollowingCapturer` thread (the desktop-bound thread that also injects input),
as DXGI capture does today for pinned monitors. DDA does not affect `SetThreadDesktop`
(measured). No new threads.

## 5. Changes outside the new module

1. `FollowingCapturer::capture_composite` passes `secure`/`remote` (computed as `capture_frame` does)
   and maps "no news" to a distinct error, e.g. `PlatformError::NoNewFrame` — or a new
   `ScreenCapturer` result — that the shared producer does not count as a failure and does not
   busy-retry; it waits for the next paced slot as for a broadcast.
2. `shared_capture::capture_thread`: on "no news" do not broadcast; `CaptureStats` counts
   produced / unchanged / failed separately (so the telemetry shows idle as idle, not as failures).
3. `SharedCapture::subscribe` bumps a `joins` counter after creating the receiver; the producer makes one
   forced complete publication per moved counter (§4.3). `BroadcastCapturer` and the session loop are
   unchanged (a missing frame is already handled by the keep-alive once the session has one).
4. `HelperConfig` gains `canvas_capture` (§4.6).

## 6. Expected cost (to be MEASURED, not trusted)

the RTX 3060 test system, 2 monitors 1920x1080 on the RTX 3060, 30 fps demand:
- busy screen: per changed output ~1 ms GPU copy + ~3 ms map/readback of 8 MB + ~2 ms canvas
  copy-out of 16 MB → roughly 5–9 ms per frame vs 35 ms; ~20 % of a core instead of 100 %.
- idle screen: 2 non-blocking acquires per paced slot → under 1 % of a core (plus the 2 s self-check).

## 7. Verification plan

- **Unit:** region placement into the canvas (offsets, negative origins, different heights), row
  pitch, seeding, no-news vs changed, ACCESS_LOST → rebuild + reseed, strike logic, Gdi regions, the
  escape hatch, the producer's handling of "no news". A fake duplication source behind a trait makes
  these deterministic.
- **Real hardware, read-only, no session:** a new `agent_host canvas-bench --secs N` subcommand on
  the RTX 3060 test system (reads the screen, draws nothing, injects nothing, saves no image unless asked):
  per-region source, frames produced, mean/max ms, process CPU time, and a GDI-vs-canvas
  fingerprint comparison of the final picture. Run idle and while something moves. This is the only
  multi-monitor + multi-adapter hardware available; the VM has one output.
- **VM, release-blocking (the VM's DDA is real Desktop Duplication on the Hyper-V adapter; console
  attached unless stated):**
  - streaming on the MSI-installed build; an idle desktop shows the real picture at once (seeding);
  - **a second viewer joining an idle stream, and a reconnect, get the picture** (forced publication on join, §4.3, including the between-iterations and lock/UAC cases);
  - **privacy transitions**: enable privacy mode during a session, disable it, enable it before a
    viewer joins, and toggle it across a desktop switch and back; the presence pill appearing,
    moving and closing — in every state the stream shows the desktop and never the overlay or the
    pill (the guest chat window is deliberately NOT excluded and must still appear), the real display is black while privacy is on, and no
    overlay pixels survive in the cached canvas afterwards (checked with a stream screenshot after
    each transition);
  - the secure desktop still streams (GDI) and coming back resumes DDA with a re-seed;
  - ACCESS_LOST without a desktop switch (a full-screen app, a resolution change) recovers to DDA
    within one paced interval, with GDI fallback frames meanwhile;
  - the console DETACHED (DDA silent) and a forced stale-image fault (test build) → the self-check
    repairs within 2 s and demotes within 6 s, and the picture keeps updating;
  - continuous motion for 5 minutes: count self-check mismatches and demotions;
  - the cursor looks the same on DDA as on GDI;
  - the escape hatch: `canvas_capture: gdi` + service restart → the tier line says `gdi-composite`.
- **Canary promotion gate:** privacy mode and the presence pill observed correct on a PHYSICAL-GPU
  machine running DDA before 1.3.11 goes beyond canary.
- **the RTX 3060 test system** runs only the read-only `canvas-bench` (no overlays, no input on the benchmark system,
  a standing rule); privacy on physical-GPU DDA is first exercised by the canary. Stated as a gap,
  not as proven.
- **Codex:** this design, then the implementation.

## 8. Follow-ups, deliberately not in the first version

- Re-promoting a demoted region back to DDA without waiting for a desktop switch. **Done at canvas
  granularity in 1.3.12 (§12):** a canvas with every region on GDI is dropped and retried with a
  backoff. Per-region re-promotion inside a mixed canvas is still open.

- Dirty-rect partial readback (`CopySubresourceRegion` per dirty rect) if the measured full-output
  readback is significant.
- Encoding only changed regions / VP8 at canvas size is unchanged.
- Hardware encoding.
- WGC on its own thread for RDP.

## 9. Review constraints and validation gates

Review established the following final contracts:
- An unpublishable capture serves whole-desktop GDI while retaining the canvas and retrying
  recovery each call; demotion requires 5 s continuously unpublishable. Join snapshots are
  acknowledged only after publication. Tests cover ACCESS_LOST recovery and failed seed retry.
- Every subscription forces a fresh complete publication, including joins between iterations;
  cached replay must not expose history after a viewer-free gap or starve idle reconnects.
- A mismatch quarantines DDA; resume only after validation. Judge `dda_image`, not repaired
  canvas pixels. Test silent DDA followed by one change and a still image.
- Compare every region's full pixels every 2 s. Frame arrival alone cannot reset stale strikes;
  repair immediately and demote after three. These 2 s/6 s bounds apply while capture runs.
- Track per-region validity and `last_good`; never publish invalid regions. Bound degraded
  failures at 5 s before composite GDI fallback.
- Recover adapter-wide on device loss and check descriptors, size, format and adapter LUID.
  Per-output captures can show transient seams because they are not synchronized.
- Privacy transitions require VM tests; physical-GPU privacy remains a canary promotion gate.
  Cursor limitations remain in §3; the escape hatch is `config.json`.

## 10. Implementation notes: what hardware changed (2026-10-25)

Measured with `agent_host canvas-bench` on the RTX 3060 test system (2 x 1920x1080 on the RTX 3060, a live and
constantly-updating desktop: an editor and a terminal).

**The self-check needed to tolerate motion.** As first written (§4.5), a check compared ONE GDI read
with DDA's last image; on a constantly changing screen that mismatched by timing and demoted a healthy
monitor within 6 s, making the canvas cost as much as GDI (57 % vs 42 % of a core). A first fix
(checks only at "quiet" moments, health refreshed by content-changing DDA images) was REJECTED by the
implementation review (round 1): motion elsewhere could exempt a frozen area indefinitely, and DDA
activity must never stand in for validation. What replaced it, and is implemented now:

1. **Two-read validation, every 2 s, motion or not.** If a first GDI read equals DDA's own image, the
   region is valid. Otherwise DDA gets up to 50 ms to deliver the frame it may be behind on, and GDI is
   read a SECOND time. A pixel that differs between the two GDI reads is genuinely moving and is not
   judged this round; every STABLE pixel must equal DDA's image, else it is a fault (repair at once,
   quarantine, re-check at the next call, demote after 3). This catches a frozen area beside motion, a
   stale or black image, and alternating wrong images over a stable screen. Moving pixels are not judged by
   VALUE, but a live duplication must itself be CHANGING where the screen moves: if most moving
   pixels are unchanged in DDA's image since the last check (no new frames, or the same black image
   repeated, over video), that is a fault too (implementation review round 2). A frozen duplication
   over motion is caught at the first check; a repeated black image at the second (its first
   appearance IS a change), so repair is within two check intervals and demotion right after, inside
   the 6 s bound. Leaving quarantine needs a check with NO moving pixels: a moving pixel's DDA value
   was never confirmed, so it is not republished. And because a moving pixel's DDA value can never be
   confirmed, every check PRESENTS the newest GDI read for every moving pixel (implementation review
   round 3): a live duplication overwrites it with its next frame anyway, while a duplication frozen on
   only a SUBSET of a moving area is repaired at every check, so no moving pixel is ever stale for
   longer than one check interval (2 s), whatever DDA does. In fact every PASSED check synchronises
   the whole presented region with what it validated (implementation review round 4): stable pixels
   with their validated value, moving pixels with the newest GDI read (the fast path: DDA's image,
   which equalled the screen). No earlier repair can outlive a passed check, and health is refreshed
   only with those pixels actually in the canvas. Rows are compared first, so an idle region that is
   already right still reports "no news".
2. **Health comes only from a passed check (DDA regions) or a successful GDI presentation (GDI and
   quarantined regions)**, never from DDA activity.
3. **Leaving quarantine copies DDA's complete validated image into the canvas.**
4. **Errors from the grace acquire take the same path as any acquire error** (duplication loss;
   adapter-wide device loss).
5. **The canvas is rebuilt when the monitor table changes** inside the same bounds (re-read at most
   once a second), not only when the bounds change.
6. **Only changed areas are copied** (§8's follow-up, pulled in): dirty rects plus move-rect
   DESTINATIONS from the acquired texture (the complete current image, so this is exact); a whole-region
   copy when there is no metadata or more than half changed. Measured A/B on the same desktop: 26-27 %
   of a core with it vs 40-61 % with full copies.
7. Rotation: IDENTITY only (UNSPECIFIED is GDI too). `ReleaseFrame` reporting the duplication lost is
   propagated.

Result after these (two 15 s runs, 30 fps demand, the same busy desktop, ~40 DDA frames/s):

| path | ms per call (mean) | CPU (one core) | checks / mismatches / demotions |
|---|---|---|---|
| GDI composite (1.3.10) | 51.4-51.8 | 45 % | - |
| DXGI canvas | 10.2-12.8 | 28-33 % | 16-21 / 0-1 / 0 per run (7 runs) |
| production path (`FollowingCapturer`, 10 s) | - | 29 % | 273 frames, 0 errors |

**Five-minute continuous run** (Codex's required continuous-motion gate; TIP 6b79069b, the same busy
desktop, 30 fps demand): 8369 calls, 8309 frames, 299 checks, **1 mismatch, 0 demotions, 0 fallbacks**,
10.0 ms per call, **28 % of a core** against the GDI composite's 55.5 ms and **45 %** over the same five
minutes; 100.000 % identical pixels at the end (raw output:
reval-20261014/release-agent-1310/canvas-bench-5min-6b79069b.txt).

The final canvas matched a GDI composite read on 99.999-100 % of pixels. On a quieter desktop a third
to a half of the calls were "no news" (25-27 % of a core). An IDLE screen costs no DDA copies by
construction; it is not measurable on this busy desktop.

## 11. VM validation summary (§7)

Windows 11 test VM (Hyper-V adapter, one 1024x768 output), the candidate binary swapped into the MSI
1.3.10 install with the console attached and a test control plane.
"Stream screenshot" = `RequestScreenshot`, which encodes the newest frame the stream produced (the canvas).

| §7 item | run | result |
|---|---|---|
| streaming; idle desktop at once | X1 | tier `dxgi-canvas`; idle screen 262 no-news/10 s, 5 ms per call, 13 % busy |
| second viewer joins an IDLE stream; reconnect | X6 | A, B (joined at +15 s) and C (after both left) each got a keyframe at 1024x768 in their first second |
| privacy on/off in session | X4 | real display black while on; stream = desktop, no overlay, no pill |
| privacy before a viewer joins | X7 p2 | B's first frame = desktop, no overlay or pill; real display black with only the pill |
| privacy across a desktop switch (Ctrl+Alt+Del, Esc) | X7 p1 | SAS screen streamed (GDI); back on Default the canvas rebuilt while blanked and showed no overlay; after unblank the stream screenshot shows the plain desktop on inspection (no overlay pixels survive; its PNG size equals the baseline's, which is consistent but not proof) |
| presence pill | X3, X7 | visible on the real display, never in the stream |
| lock, sign-in, unlock (secure desktop + return to DDA) | X5 | lock curtain → Winlogon (`gdi-composite`) → password typed through the agent → unlocked → canvas rebuilt on `dxgi` |
| mode change (1024x768 → 1280x800 → back) | X8 | the session ends by design (8c339d71, topology change); the canvas rebuilt at 1280x800, and the reconnect after the restore rebuilt at 1024x768 on `dxgi` with the right picture |
| DDA SILENT while the screen moves (local test build, never committed: `RMT_TEST_DDA_SILENT_AFTER_S`) | X9 | silence at ~20:34:18.2 → quarantined at +1.3 s, demoted to `gdi(self-check)` at +1.5 s; stream screenshots 10 s apart show the ticker current to ~0.15 s |
| cursor parity | X10 | neither tier draws the pointer (the viewer renders it); the DXGI and GDI frames differ only in the taskbar clock (68 pixels) |
| escape hatch | X10 | `"canvas_capture":"gdi"` + restart → "config canvas_capture=gdi" and tier `gdi-composite`; restoring the config → `dxgi-canvas` |
| continuous motion (a 10 Hz ticker), 10 minutes | X11 | 0 demotions; 13 quarantines in ~300 checks, each lifted at the next call (35-110 ms); steady stream 19.1 frames/s (16-23) over the 304 s collection |

Observed and correct, not designed for: on the **lock-screen curtain** (still the Default desktop),
DDA disagreed with the screen and the region was served by GDI within 0.3 s (three checks at
successive calls); unlocking passes through Winlogon, so the canvas is rebuilt on DDA afterwards.

The VM's quarantines under motion are the stale rule catching DDA one frame behind a fast repaint on
a slow guest (the RTX 3060 test system: 1 in 299 checks over five minutes); a quarantine serves GDI for one call.

What these runs do NOT prove (Codex implementation round 6, ACCEPT for canary, no finding): X8 shows
topology termination and reconnect, not in-session ACCESS_LOST recovery; X9 shows handling of an
injected silent duplication, not a real console detach nor a repeated-stale-image fault (those are
unit-tested); UAC was not exercised separately from the Winlogon path; the cause of the X11
quarantines is inferred. Not provable in the VM at all: privacy on PHYSICAL-GPU DDA (the gate before
1.3.11 goes beyond canary, §7) and multi-adapter.

## 12. Canvas retry: sleeping monitors (1.3.12)

**Found on the RTX 3060 test system 2026-10-26** (1.3.11 code, read-only canvas-bench): with the monitors ASLEEP
(display idle timeout), Desktop Duplication delivers no frames while GDI still reads a changing
screen. The self-check correctly moved both regions to `gdi(self-check)`, but the canvas then stayed
alive with every region on GDI until the next desktop switch, and that costs MORE than the plain GDI
composite (two per-monitor reads: 51.2 ms per call and 41 % of a core, against one virtual-desktop
blit at 35.3 ms and 34 %). A technician connecting at night to a machine whose monitors sleep, the
common unattended case, would leave the agent there for days. The picture was never wrong.

**Change (FollowingCapturer only; the canvas logic is unchanged):** a canvas whose regions are ALL on
GDI after a served frame, a canvas that demotes itself, and a failed build are dropped (every
duplication released) and the single-blit GDI composite serves. A new canvas is built after 30 s,
doubling to 10 min; the backoff starts over only after one canvas keeps a region at exactly `dxgi`
for 60 s continuously (Frame and NoNews count, a call that cannot publish interrupts it, and any
discard or rebuild clears it); a desktop switch forgets everything. A rebuilt canvas takes exactly
the build-time path above (GDI seed, self-check), so no unvalidated DDA pixel is trusted on the way
back. Mixed canvases are kept as before.

CanvasRetry is pure and unit-tested; nine rule mutants were killed. Health must be
observed on both Frame and NoNews outcomes and reset when a canvas is replaced.

**Evidence:**
- the RTX 3060 test system, monitors asleep, production path (`canvas-bench --following`, 100 s): built → both
  regions GDI → dropped (retry 30 s) → GDI composite → rebuilt → dropped (retry 60 s); 36 % of a
  core.
- Lab VM (X13/X14, candidate b20a6397, 1-minute display timeout, 10 Hz ticker): asleep, the canvas
  dropped and retried after 30, 60, 120 and 240 s; after a mouse move through the agent woke the
  display, the next rebuild (22:46:20) stayed on `dxgi` for the rest of the run (~3 min), with only
  the usual brief quarantines under motion.
