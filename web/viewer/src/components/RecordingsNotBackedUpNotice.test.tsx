/**
 * The "recordings are not backed up" notice (docs/63 C11). The viewer's vitest runs in Node without a DOM, and the
 * policy section only renders its form after an async load, so the wording is tested on the notice itself and the
 * placement is pinned against the component sources (the policy form where storage is turned on, the Recordings
 * panel, and the confirmation text).
 */
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { RecordingsNotBackedUpNotice } from "./RecordingsNotBackedUpNotice";
import policySource from "./RecordingPolicySection.tsx?raw";
import panelSource from "./RecordingsPanel.tsx?raw";
import { RECORDINGS_NOT_BACKED_UP, STORAGE_ON_CONFIRMATION } from "../lib/recordings";

describe("recordings are not backed up", () => {
  it("states the loss plainly", () => {
    expect(RECORDINGS_NOT_BACKED_UP).toBe("Recordings are not backed up. A disk or server loss deletes them.");
    const markup = renderToStaticMarkup(<RecordingsNotBackedUpNotice testId="x" />);
    expect(markup).toContain(RECORDINGS_NOT_BACKED_UP);
    expect(markup).toContain('data-testid="x"');
    expect(markup).toContain('role="note"');
  });
  it("is repeated in the confirmation a tenant must accept to turn storage on", () => {
    expect(STORAGE_ON_CONFIRMATION).toContain(RECORDINGS_NOT_BACKED_UP);
  });
  it("is rendered in the policy form (loaded branch, independent of the retention choice) and in the Recordings panel", () => {
    const policy = policySource;
    const tag = "<" + "RecordingsNotBackedUpNotice";
    expect(policy).toContain(tag + ' testId="recording-policy-not-backed-up"');
    // inside the form branch that holds the retention radios, not the loading/hidden branches
    expect(policy.indexOf(tag)).toBeGreaterThan(policy.indexOf("recording-retention-off"));
    expect(policy.indexOf(tag)).toBeLessThan(policy.indexOf("recording-policy-save"));
    expect(panelSource).toContain(tag + ' testId="recordings-not-backed-up"');
  });
});
