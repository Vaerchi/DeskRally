import { describe, it, expect } from "vitest";
import { childPath, parentPath, locationLabel, formatSize, formatModified, shouldAdoptListing, pathRelativeTo, DEFAULT_TRANSFER_DIR } from "./filepath";

describe("childPath (file-browser navigation)", () => {
  it("uses an entry name as-is at the drive roots (it is already a full X:\\ path)", () => {
    expect(childPath("", "C:\\")).toBe("C:\\");
    expect(childPath("", "D:\\")).toBe("D:\\");
  });

  it("joins with exactly one backslash, collapsing a trailing one on the parent", () => {
    // A drive root already ends with a backslash — join must not double it.
    expect(childPath("C:\\", "Users")).toBe("C:\\Users");
    // A nested directory has no trailing backslash — join adds one.
    expect(childPath("C:\\Users", "Public")).toBe("C:\\Users\\Public");
  });
});

describe("parentPath (file-browser navigation)", () => {
  it("stays at the roots when already there", () => {
    expect(parentPath("")).toBe("");
  });

  it("goes from a drive root up to the roots list", () => {
    expect(parentPath("C:\\")).toBe("");
  });

  it("normalizes a first-level directory's parent back to the drive root", () => {
    expect(parentPath("C:\\Users")).toBe("C:\\");
  });

  it("drops the last segment of a nested path", () => {
    expect(parentPath("C:\\Users\\Public")).toBe("C:\\Users");
    expect(parentPath("C:\\Users\\Public\\Desktop")).toBe("C:\\Users\\Public");
  });
});

describe("locationLabel", () => {
  it("labels the roots and echoes a real path", () => {
    expect(locationLabel("")).toBe("This PC");
    expect(locationLabel("C:\\Users")).toBe("C:\\Users");
  });
});

describe("shouldAdoptListing (out-of-order reply correlation)", () => {
  it("adopts a reply for the path we are waiting on", () => {
    expect(shouldAdoptListing("C:\\Users", "C:\\Users")).toBe(true);
  });

  it("drops a stale reply for a path we have navigated away from", () => {
    // Waiting on B, an earlier A's reply arrives — must be ignored so the panel does not flip to A.
    expect(shouldAdoptListing("C:\\B", "C:\\A")).toBe(false);
  });

  it("adopts any reply when not waiting on a specific path (post-timeout recovery)", () => {
    expect(shouldAdoptListing(null, "C:\\Anything")).toBe(true);
    expect(shouldAdoptListing(null, "")).toBe(true);
  });
});

describe("formatSize", () => {
  it("uses bytes under 1 KiB, then KB/MB/GB at the binary boundaries", () => {
    expect(formatSize(0)).toBe("0 B");
    expect(formatSize(512)).toBe("512 B");
    expect(formatSize(1023)).toBe("1023 B");
    expect(formatSize(1024)).toBe("1.0 KB");
    expect(formatSize(1536)).toBe("1.5 KB");
    expect(formatSize(1024 * 1024)).toBe("1.0 MB");
    expect(formatSize(3 * 1024 * 1024)).toBe("3.0 MB");
    expect(formatSize(1024 * 1024 * 1024)).toBe("1.0 GB");
  });
});

describe("formatModified", () => {
  it("returns empty string for 0 (agent sentinel for 'unavailable')", () => {
    expect(formatModified(0)).toBe("");
  });

  it("returns empty string for negative values", () => {
    expect(formatModified(-1)).toBe("");
  });

  it("returns a YYYY-MM-DD HH:MM string for a valid timestamp", () => {
    // Use a known timestamp and compute expected output in the test's own timezone so the
    // assertion is timezone-agnostic (the formatModified contract is LOCAL time, not UTC).
    const unix = 1700000000; // 2023-11-14 some time, depends on timezone
    const expected = formatModified(unix);
    // Shape check: must match YYYY-MM-DD HH:MM
    expect(expected).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
    // Value check: round-trip via Date to assert the function uses the right epoch
    const d = new Date(unix * 1000);
    expect(expected).toContain(String(d.getFullYear()));
  });

  it("returns a non-empty string for the minimum valid value (1 second since epoch)", () => {
    // Guards the boundary: modified_unix=1 must pass the `> 0` render guard and produce output.
    // A mutation changing `<= 0` to `<= 1` inside formatModified would fail this.
    expect(formatModified(1)).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
  });

  it("two different timestamps produce different strings", () => {
    // Proves it is not a constant
    expect(formatModified(1700000000)).not.toBe(formatModified(1700000060));
  });
});

describe("pathRelativeTo", () => {
  const TD = "C:\\rmt-agent\\transfers";

  it("returns the filename for a file directly in the root", () => {
    expect(pathRelativeTo(TD, `${TD}\\report.pdf`)).toBe("report.pdf");
  });

  it("returns a forward-slash relative path for a subdirectory file", () => {
    expect(pathRelativeTo(TD, `${TD}\\incoming\\data.zip`)).toBe("incoming/data.zip");
  });

  it("returns null for a file outside the transfer directory", () => {
    expect(pathRelativeTo(TD, "C:\\Users\\Ed\\file.txt")).toBeNull();
  });

  it("is case-insensitive on root and full path", () => {
    expect(pathRelativeTo("C:\\RMT-AGENT\\TRANSFERS", "c:\\rmt-agent\\transfers\\file.txt"))
      .toBe("file.txt");
  });

  it("returns null for the root directory itself (not a file under it)", () => {
    expect(pathRelativeTo(TD, TD)).toBeNull();
  });

  it("does not match a path that only shares a prefix (transfers2 vs transfers)", () => {
    expect(pathRelativeTo(TD, "C:\\rmt-agent\\transfers2\\file.txt")).toBeNull();
  });

  it("strips trailing backslash from root before comparing", () => {
    expect(pathRelativeTo("C:\\rmt-agent\\transfers\\", `${TD}\\file.txt`)).toBe("file.txt");
  });

  it("DEFAULT_TRANSFER_DIR constant ends with 'transfers' and contains rmt-agent", () => {
    expect(DEFAULT_TRANSFER_DIR).toContain("rmt-agent");
    expect(DEFAULT_TRANSFER_DIR.toLowerCase()).toContain("transfers");
  });
});
