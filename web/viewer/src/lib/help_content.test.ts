import panel from "../components/EnrollmentTokensPanel.tsx?raw";
import { describe, expect, it } from "vitest";
import { HELP_CATEGORIES, HELP_TOPICS, topicMatches } from "./help_content";

describe("help content", () => {
  it("has unique, URL-safe topic ids", () => {
    const ids = HELP_TOPICS.map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^[a-z0-9-]+$/);
  });

  it("puts a topic in every category and every topic in a known category", () => {
    for (const c of HELP_CATEGORIES) expect(HELP_TOPICS.some((t) => t.category === c)).toBe(true);
    for (const t of HELP_TOPICS) expect(HELP_CATEGORIES).toContain(t.category);
  });

  it("gives every topic a summary and at least one non-empty section", () => {
    for (const t of HELP_TOPICS) {
      expect(t.summary.length).toBeGreaterThan(0);
      expect(t.sections.length).toBeGreaterThan(0);
      for (const s of t.sections) {
        const parts = [s.heading, s.tip, ...(s.text ?? []), ...(s.steps ?? []), ...(s.bullets ?? [])].filter(Boolean);
        expect(parts.length).toBeGreaterThan(0);
      }
    }
  });

  it("searches every word across title and body, case-insensitively", () => {
    const attended = HELP_TOPICS.find((t) => t.id === "attended")!;
    expect(topicMatches(attended, "")).toBe(true);
    expect(topicMatches(attended, "ONE-TIME code")).toBe(true);
    expect(topicMatches(attended, "code zebra")).toBe(false);
    expect(HELP_TOPICS.filter((t) => topicMatches(t, "provisioning")).map((t) => t.id)).toContain("silent-install");
  });

  // The Deploy panel sends people to a Help topic by its title; keep the two in step.
  it("has the topic the Deploy panel points to", () => {
    const named = /Help → "([^"]+)"/.exec(panel)?.[1];
    expect(named).toBeDefined();
    expect(HELP_TOPICS.map((t) => t.title)).toContain(named);
  });
});
