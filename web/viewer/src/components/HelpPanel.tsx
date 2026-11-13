/**
 * Help — task-oriented directions for a signed-in technician or administrator.
 *
 * The content is data (lib/help_content.ts), rendered here as plain React text: no markdown parser,
 * no HTML injection, so a topic can never become an XSS sink. Topics are grouped by category, can be
 * searched, and can be linked directly with `/console/help?topic=<id>`.
 */

import { useMemo, useRef, useState } from "react";
import { HELP_CATEGORIES, HELP_TOPICS, type HelpTopic, topicMatches } from "../lib/help_content";

function initialTopic(): string {
  try {
    const id = new URLSearchParams(window.location.search).get("topic");
    if (id && HELP_TOPICS.some((t) => t.id === id)) return id;
  } catch {
    /* no URL access — fall back to the first topic */
  }
  return HELP_TOPICS[0].id;
}

export function HelpPanel() {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string>(initialTopic);
  const articleRef = useRef<HTMLElement>(null);

  // One column on a phone puts the article below the whole topic list, so a tap would look like it
  // did nothing: bring the article into view there. Wide layouts show both side by side already.
  const choose = (id: string) => {
    setSelected(id);
    if (window.matchMedia?.("(max-width: 720px)").matches) {
      requestAnimationFrame(() => articleRef.current?.scrollIntoView({ block: "start" }));
    }
  };

  const visible = useMemo(() => HELP_TOPICS.filter((t) => topicMatches(t, query)), [query]);
  const topic: HelpTopic | undefined =
    visible.find((t) => t.id === selected) ?? visible[0];

  return (
    <section className="panel panel--help" data-testid="help">
      <div className="panel__form">
        <span className="panel__toolbar-title">Help</span>
        <input
          className="panel__search help__search"
          type="search"
          placeholder="Search help"
          aria-label="Search help"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          data-testid="help-search"
        />
      </div>
      <div className="help__layout">
        <nav className="help__toc" aria-label="Help topics">
          {HELP_CATEGORIES.map((category) => {
            const topics = visible.filter((t) => t.category === category);
            if (topics.length === 0) return null;
            return (
              <div key={category} className="help__toc-group">
                <h3 className="help__toc-heading">{category}</h3>
                <ul>
                  {topics.map((t) => (
                    <li key={t.id}>
                      <button
                        type="button"
                        className="help__toc-item"
                        aria-current={topic?.id === t.id ? "page" : undefined}
                        onClick={() => choose(t.id)}
                        data-testid={`help-topic-${t.id}`}
                      >
                        {t.title}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
          {visible.length === 0 && (
            <p className="panel__empty" data-testid="help-no-match">
              No help topics match “{query}”.
            </p>
          )}
        </nav>
        {topic && (
          <article className="help__article" data-testid="help-article" ref={articleRef}>
            <h2>{topic.title}</h2>
            <p className="help__summary">{topic.summary}</p>
            {topic.sections.map((s, i) => (
              <div key={i} className="help__section">
                {s.heading && <h3>{s.heading}</h3>}
                {s.text?.map((p, j) => <p key={j}>{p}</p>)}
                {s.steps && (
                  <ol>
                    {s.steps.map((step, j) => <li key={j}>{step}</li>)}
                  </ol>
                )}
                {s.bullets && (
                  <ul>
                    {s.bullets.map((b, j) => <li key={j}>{b}</li>)}
                  </ul>
                )}
                {s.tip && <p className="help__tip">{s.tip}</p>}
              </div>
            ))}
          </article>
        )}
      </div>
    </section>
  );
}
