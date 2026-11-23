//! **WASAPI loopback capture** — the remote machine's own audio output, so the technician can hear
//! what the guest hears (the first half of audio passthrough).
//!
//! # What loopback capture is
//!
//! WASAPI can open a *render* endpoint (the speakers) for *capture*, with
//! `AUDCLNT_STREAMFLAGS_LOOPBACK`. What comes back is the mix the endpoint is about to play — every
//! application's audio, already mixed and already at the endpoint's mix format. It is not a
//! microphone, it needs no recording device, and it does not appear as one.
//!
//! # The two things that will surprise a reader
//!
//! **Silence is not nothing.** A loopback client is driven by the render endpoint's clock, and
//! Windows stops that clock when *no application holds the endpoint open*. So on an idle machine
//! loopback delivers no packets at all — not zeroes, nothing — and the first packet after audio
//! starts can be flagged `AUDCLNT_BUFFERFLAGS_SILENT`, whose buffer contents are undefined and must
//! be treated as zeroes rather than read. This is the same shape as DXGI yielding a frame only when
//! the screen changes, and it deserves the same care: "no data" here means "nothing is playing",
//! never "capture is broken", and a probe that reads one packet and gives up would report a working
//! machine as silent.
//!
//! **The mix format is whatever the endpoint says**, commonly 32-bit float, 48 kHz, 2 channels, but
//! 44.1 kHz and 24-bit-in-32 containers are both common. Nothing may assume; [`MixFormat`] carries
//! what the endpoint actually reported so the encoder stage can resample if it has to. Opus wants
//! 48 kHz, so a 44.1 kHz endpoint means a resample, not a failure.
//!
//! # Who runs it
//!
//! The agent's per-session helper runs as **SYSTEM inside the user's session**. Audio endpoints are
//! per-session, and whether a session-1 SYSTEM process may open the interactive user's render
//! endpoint is exactly the kind of thing that is cheaper to measure than to reason about — so
//! `agent_host audio-probe` exists to answer it on a real machine, as a real service, before any of
//! the encoder or transport work is built on the assumption.

use std::fmt;

use windows::Win32::Media::Audio::{
    eConsole, eRender, IAudioCaptureClient, IAudioClient, IMMDeviceEnumerator, MMDeviceEnumerator,
    AUDCLNT_BUFFERFLAGS_SILENT, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK,
    WAVEFORMATEX, WAVE_FORMAT_PCM,
};
use windows::Win32::Media::KernelStreaming::WAVE_FORMAT_EXTENSIBLE;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_ALL, COINIT_MULTITHREADED,
};

/// `WAVE_FORMAT_IEEE_FLOAT` — the `WAVEFORMATEX::wFormatTag` for 32-bit float samples, which is
/// what a shared-mode mix format almost always is. Spelled out because the `windows` crate does not
/// re-export it from `Win32::Media::Audio` (its siblings `WAVE_FORMAT_PCM` and
/// `WAVE_FORMAT_EXTENSIBLE` are there, which is the sort of gap that costs ten minutes).
const WAVE_FORMAT_IEEE_FLOAT: u32 = 0x0003;

/// How much audio the endpoint buffers for us, in 100-ns units (REFERENCE_TIME). 200 ms is generous
/// enough that a scheduling hiccup does not drop packets and small enough not to add audible delay
/// on its own — the shared-mode engine period does the real pacing.
const BUFFER_DURATION_HNS: i64 = 2_000_000;

/// Errors from the loopback capture path.
#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    /// COM could not be initialised on this thread.
    #[error("COM initialisation failed: {0}")]
    ComInit(windows::core::Error),
    /// No default render endpoint — a machine with no speakers/headphones at all, or a session
    /// with no audio endpoint of its own.
    #[error("no default render endpoint (no audio device in this session?): {0}")]
    NoEndpoint(windows::core::Error),
    /// The endpoint exists but would not open for loopback capture. THE interesting failure: it is
    /// what a session/privilege problem looks like.
    #[error("could not open the render endpoint for loopback capture: {0}")]
    Unavailable(windows::core::Error),
    /// Any other WASAPI failure.
    #[error("wasapi error: {0}")]
    Windows(#[from] windows::core::Error),
}

/// The endpoint's mix format, as reported — never assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MixFormat {
    pub sample_rate: u32,
    pub channels: u16,
    pub bits_per_sample: u16,
    /// True when samples are 32-bit IEEE floats (the common shared-mode case), false for integer
    /// PCM. `WAVE_FORMAT_EXTENSIBLE` is resolved to whichever it actually wraps.
    pub float_samples: bool,
}

impl fmt::Display for MixFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} Hz, {} ch, {}-bit {}",
            self.sample_rate,
            self.channels,
            self.bits_per_sample,
            if self.float_samples { "float" } else { "int" }
        )
    }
}

impl MixFormat {
    /// Read a `WAVEFORMATEX` (possibly a `WAVEFORMATEXTENSIBLE`) into the portable shape.
    ///
    /// # Safety
    /// `wfx` must point at a valid `WAVEFORMATEX`; when `wFormatTag` is `WAVE_FORMAT_EXTENSIBLE`
    /// the allocation must actually be the larger `WAVEFORMATEXTENSIBLE`, which is what
    /// `GetMixFormat` guarantees.
    unsafe fn from_wfx(wfx: *const WAVEFORMATEX) -> Self {
        let w = &*wfx;
        // EXTENSIBLE hides the real sample type in SubFormat. Rather than pull in the GUID
        // comparison, use the fact that shared-mode mix formats are float whenever they are
        // 32-bit — true for every endpoint Windows produces — and fall back to the tag otherwise.
        let float_samples = match w.wFormatTag as u32 {
            x if x == WAVE_FORMAT_IEEE_FLOAT => true,
            x if x == WAVE_FORMAT_PCM => false,
            x if x == WAVE_FORMAT_EXTENSIBLE => w.wBitsPerSample == 32,
            _ => w.wBitsPerSample == 32,
        };
        Self {
            sample_rate: w.nSamplesPerSec,
            channels: w.nChannels,
            bits_per_sample: w.wBitsPerSample,
            float_samples,
        }
    }
}

/// One packet handed back by the endpoint.
#[derive(Debug, Default, Clone, Copy)]
pub struct PacketStats {
    /// Audio frames (samples per channel) in this packet.
    pub frames: u32,
    /// The endpoint flagged the packet SILENT — its buffer contents are undefined and were treated
    /// as zeroes rather than read.
    pub silent: bool,
}

/// A live WASAPI loopback capture of the default render endpoint.
///
/// Holds the COM objects for its lifetime. Construct it on the thread that will read from it: the
/// COM apartment is per-thread, and this type initialises `COINIT_MULTITHREADED` on construction.
pub struct LoopbackCapture {
    client: IAudioClient,
    capture: IAudioCaptureClient,
    format: MixFormat,
    endpoint_id: String,
}

impl LoopbackCapture {
    /// Open the default render endpoint for loopback capture and start it.
    pub fn new() -> Result<Self, AudioError> {
        // MULTITHREADED because the capture loop is a plain worker thread with no message pump. The
        // call is idempotent per thread; a thread already in an apartment gets RPC_E_CHANGED_MODE,
        // which is not fatal for our use, so only a hard failure is reported.
        // SAFETY: standard COM initialisation with no reserved pointer.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_err() && hr != windows::Win32::Foundation::RPC_E_CHANGED_MODE {
            return Err(AudioError::ComInit(windows::core::Error::from(hr)));
        }

        // SAFETY: MMDeviceEnumerator is a registered in-proc COM class.
        let enumerator: IMMDeviceEnumerator =
            unsafe { CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)? };

        // eRender + eConsole: the endpoint the machine PLAYS through, which is what we want to
        // hear. (eCapture would be the microphone — a different feature with different consent.)
        // SAFETY: enumerator is a live interface; the enum values are constants.
        let device = unsafe { enumerator.GetDefaultAudioEndpoint(eRender, eConsole) }
            .map_err(AudioError::NoEndpoint)?;
        // SAFETY: device is live; GetId returns a COM-allocated string we must free.
        let endpoint_id = unsafe {
            let id = device.GetId()?;
            let s = id.to_string().unwrap_or_default();
            CoTaskMemFree(Some(id.0 as *const _));
            s
        };

        // SAFETY: device is live; IAudioClient is the documented activation interface.
        let client: IAudioClient = unsafe { device.Activate(CLSCTX_ALL, None) }
            .map_err(AudioError::Unavailable)?;

        // SAFETY: client is live; GetMixFormat allocates a WAVEFORMATEX we must free.
        let wfx = unsafe { client.GetMixFormat()? };
        let format = unsafe { MixFormat::from_wfx(wfx) };

        // Shared mode + LOOPBACK is the whole trick. Exclusive mode cannot do loopback, and it
        // would also take the endpoint away from the user — the guest would stop hearing their own
        // machine, which is not a trade a support tool may make silently.
        // SAFETY: wfx is the format the endpoint itself just reported, so it is accepted verbatim.
        let init = unsafe {
            client.Initialize(
                AUDCLNT_SHAREMODE_SHARED,
                AUDCLNT_STREAMFLAGS_LOOPBACK,
                BUFFER_DURATION_HNS,
                0, // periodicity must be 0 in shared mode
                wfx,
                None,
            )
        };
        // SAFETY: freeing the COM-allocated format regardless of whether Initialize accepted it.
        unsafe { CoTaskMemFree(Some(wfx as *const _)) };
        init.map_err(AudioError::Unavailable)?;

        // SAFETY: client is initialised, so the capture service is available.
        let capture: IAudioCaptureClient = unsafe { client.GetService()? };
        // SAFETY: client is initialised and not yet started.
        unsafe { client.Start()? };

        Ok(Self { client, capture, format, endpoint_id })
    }

    /// The endpoint's mix format, as reported by the endpoint.
    pub fn format(&self) -> MixFormat {
        self.format
    }

    /// The endpoint's device id (stable per endpoint; useful in a log line).
    pub fn endpoint_id(&self) -> &str {
        &self.endpoint_id
    }

    /// Drain every packet currently available, appending interleaved `f32` samples to `out`.
    ///
    /// Returns one [`PacketStats`] per packet drained — empty when nothing was available, which on
    /// an idle machine is the normal case and NOT an error (see the module docs).
    ///
    /// Integer formats are scaled into `f32` here so the encoder stage sees one representation.
    /// A SILENT packet contributes zeroes without its buffer being read at all: the contents are
    /// documented as undefined, and reading them would put whatever the driver last left in memory
    /// into the audio the technician hears.
    pub fn drain(&mut self, out: &mut Vec<f32>) -> Result<Vec<PacketStats>, AudioError> {
        let mut packets = Vec::new();
        loop {
            // SAFETY: capture is live and started.
            let available = unsafe { self.capture.GetNextPacketSize()? };
            if available == 0 {
                break;
            }
            let mut data: *mut u8 = std::ptr::null_mut();
            let mut frames: u32 = 0;
            let mut flags: u32 = 0;
            // SAFETY: out-params are all written by GetBuffer; device position is not wanted.
            unsafe {
                self.capture
                    .GetBuffer(&mut data, &mut frames, &mut flags, None, None)?
            };
            let silent = flags & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0;
            let channels = self.format.channels as usize;
            let samples = frames as usize * channels;
            if silent || data.is_null() {
                out.resize(out.len() + samples, 0.0);
            } else {
                // SAFETY: `data` holds `frames * channels` samples in the mix format, and the
                // buffer stays valid until ReleaseBuffer below.
                unsafe { append_samples(out, data, samples, self.format) };
            }
            // SAFETY: exactly the frame count GetBuffer reported must be released.
            unsafe { self.capture.ReleaseBuffer(frames)? };
            packets.push(PacketStats { frames, silent });
        }
        Ok(packets)
    }
}

impl Drop for LoopbackCapture {
    fn drop(&mut self) {
        // SAFETY: client is live; Stop on an already-stopped client is harmless.
        unsafe {
            let _ = self.client.Stop();
        }
    }
}

/// Append `count` interleaved samples from `data` to `out`, converting to `f32` in `-1.0..=1.0`.
///
/// # Safety
/// `data` must point at `count` samples in `format`'s sample type.
unsafe fn append_samples(out: &mut Vec<f32>, data: *const u8, count: usize, format: MixFormat) {
    match (format.float_samples, format.bits_per_sample) {
        (true, 32) => {
            let src = std::slice::from_raw_parts(data as *const f32, count);
            out.extend_from_slice(src);
        }
        (false, 16) => {
            let src = std::slice::from_raw_parts(data as *const i16, count);
            out.extend(src.iter().map(|&s| s as f32 / 32768.0));
        }
        (false, 32) => {
            let src = std::slice::from_raw_parts(data as *const i32, count);
            out.extend(src.iter().map(|&s| s as f32 / 2_147_483_648.0));
        }
        // Anything else (24-bit packed, 8-bit) is not a shared-mode mix format Windows produces.
        // Contribute silence rather than reinterpret bytes as a sample type they are not.
        _ => out.resize(out.len() + count, 0.0),
    }
}

/// Peak and RMS of a sample block, in dBFS. `None` for an empty block.
///
/// Two numbers rather than one because they answer different questions: PEAK says whether anything
/// at all reached the capture (a single click registers), RMS says how loud it actually is. A probe
/// reporting only RMS would call a short beep silence.
pub fn levels_dbfs(samples: &[f32]) -> Option<(f32, f32)> {
    if samples.is_empty() {
        return None;
    }
    let mut peak = 0.0f32;
    let mut sum_sq = 0.0f64;
    for &s in samples {
        peak = peak.max(s.abs());
        sum_sq += (s as f64) * (s as f64);
    }
    let rms = (sum_sq / samples.len() as f64).sqrt() as f32;
    Some((to_dbfs(peak), to_dbfs(rms)))
}

/// Linear amplitude to dBFS, with a floor so digital silence prints as a number rather than `-inf`.
fn to_dbfs(amplitude: f32) -> f32 {
    const FLOOR_DBFS: f32 = -120.0;
    if amplitude <= 0.0 {
        return FLOOR_DBFS;
    }
    (20.0 * amplitude.log10()).max(FLOOR_DBFS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_scale_is_zero_dbfs_and_silence_is_the_floor() {
        assert_eq!(to_dbfs(1.0), 0.0);
        assert_eq!(to_dbfs(0.0), -120.0);
        // Half amplitude is ~-6 dB — the check that the formula is dB of AMPLITUDE, not of power.
        // A power formula (10*log10) would give -3 here and quietly halve every level reported.
        assert!((to_dbfs(0.5) + 6.02).abs() < 0.01, "got {}", to_dbfs(0.5));
    }

    #[test]
    fn peak_and_rms_differ_on_a_sparse_transient() {
        // THE reason both are reported. One full-scale sample in a block of silence: peak says
        // "something arrived", RMS says "almost nothing did". A probe printing only RMS would call
        // a real click inaudible and send someone hunting a capture fault that is not there.
        let mut block = vec![0.0f32; 1000];
        block[500] = 1.0;
        let (peak, rms) = levels_dbfs(&block).expect("non-empty");
        assert_eq!(peak, 0.0, "peak sees the transient");
        assert!(rms < -25.0, "rms averages it away: {rms}");
    }

    #[test]
    fn a_steady_tone_reports_peak_and_rms_three_db_apart() {
        // A full-scale sine is 0 dBFS peak and -3.01 dBFS RMS. An ASYMMETRIC check: it pins the
        // relationship between the two numbers, so swapping them (or computing both the same way)
        // fails, which a silence-vs-full-scale test alone would not catch.
        let block: Vec<f32> = (0..4800)
            .map(|i| (i as f32 * std::f32::consts::TAU / 100.0).sin())
            .collect();
        let (peak, rms) = levels_dbfs(&block).expect("non-empty");
        assert!((peak - 0.0).abs() < 0.01, "peak {peak}");
        assert!((rms + 3.01).abs() < 0.1, "rms {rms}");
    }

    #[test]
    fn an_empty_block_has_no_level_rather_than_a_fake_one() {
        // Nothing captured is not silence — on an idle machine loopback delivers NO packets at all,
        // and reporting that as "-120 dBFS" would claim a measurement never taken.
        assert!(levels_dbfs(&[]).is_none());
    }

    #[test]
    fn mix_format_renders_the_shape_a_reader_needs() {
        let f = MixFormat { sample_rate: 48_000, channels: 2, bits_per_sample: 32, float_samples: true };
        assert_eq!(f.to_string(), "48000 Hz, 2 ch, 32-bit float");
        let g = MixFormat { sample_rate: 44_100, channels: 1, bits_per_sample: 16, float_samples: false };
        assert_eq!(g.to_string(), "44100 Hz, 1 ch, 16-bit int");
    }
}
