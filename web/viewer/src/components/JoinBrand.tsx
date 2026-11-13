/**
 * The guest join page's FRAME and everything on it that a tenant's brand can touch (docs/66 stage 2): the
 * top bar (logo and product name), the heading and the fixed safety lede, the tenant's "Message from <name>"
 * box with its one contact, and the fixed attribution line. The page's own content (the steps) is `children`.
 *
 * `JoinPage` renders it with the brand its host published; stage 3's console preview renders the SAME component
 * with a DRAFT brand, so what an Owner and an operator review is the code path a guest gets (docs/66 2.7, 2a.7).
 * Nothing in here fetches, reads `window`, or touches `document`: a brand goes in as props.
 *
 * # Why this is safe to hand a tenant's strings
 *
 * - EVERY tenant string is a React text node, inside `<bdi dir="auto">` where it sits in running text. There is
 *   no HTML-insertion API of any kind and no markup or link interpretation anywhere in this file (a
 *   source-text test in JoinBrand.test.tsx lists the APIs and keeps it that way).
 * - The only `href`s a brand can produce are the validated contact kinds: `tel:` + digits, and `https://` + a
 *   public DNS name for a website. Both are BUILT here from the re-validated value (lib/host_branding.ts), never
 *   copied from a response. An email is shown as text and is never a link (docs/66 2a.7).
 * - The logo's address must be one of three constructions (`validLogoSrc`): the published-hash route built from a
 *   64-hex hash, a blob: URL, or a raster data: URI; anything else shows the neutral mark. A logo that fails to
 *   load (the server answers a stale or unpublished hash with neutral JSON, which an <img> cannot decode) falls
 *   back to the neutral mark too, rather than a broken-image box.
 * - The accent reaches the page as ONE custom property (`--join-accent`), and the stylesheet applies it to exactly
 *   two things: the primary button fill (white label) and the contact link's text. The lede, the attribution and
 *   every other colour are fixed, so no accent can reach the safety copy (docs/66 2a.7).
 * - The lede and the attribution are hard-coded here and take no tenant input; a tenant cannot reorder, restyle
 *   or hide them. Branding never asserts that anything is verified or safe (docs/27 "what the page may NOT claim").
 */

import { useId, useState, type CSSProperties, type ReactNode } from "react";
import { RallyMark } from "./RallyIdentity";
import { defaultDocsLink } from "../lib/default_docs";
import {
  phoneHref,
  urlContact,
  validAccent,
  validContact,
  validLogoSrc,
  NEUTRAL_BRAND,
  type BrandContact,
  type HostBrand,
} from "../lib/host_branding";

/** The product name when neither the brand nor the deployment's build supplies one. */
export const DEFAULT_PRODUCT_NAME = "DeskRally";

/**
 * The name the page shows: the tenant's when its host published one, else the deployment's build-time name
 * (`VITE_PRODUCT_NAME`, the self-host fallback), else "DeskRally".
 */
export function brandDisplayName(brand: HostBrand, fallbackName?: string): string {
  return brand.name !== "" ? brand.name : fallbackName?.trim() || DEFAULT_PRODUCT_NAME;
}

/** A tenant string in running text: a text node, direction-isolated so it cannot reorder what is around it. */
export function BrandName({ text, className, testId }: { text: string; className?: string; testId?: string }) {
  return (
    <bdi dir="auto" className={className} data-testid={testId}>
      {text}
    </bdi>
  );
}

function accentStyle(accent: string): CSSProperties | undefined {
  // Re-validated here (not just where the response was parsed): this component is also handed drafts.
  return accent !== "" && validAccent(accent) ? ({ "--join-accent": accent } as CSSProperties) : undefined;
}

/**
 * The logo, or the neutral mark. The slot is reserved while the image loads (no layout jump, nothing broken
 * on screen); a failed load shows the neutral mark, exactly like a tenant with no logo.
 */
function BrandLogo({ src }: { src?: string }) {
  // Keyed by the address so a new logo starts from "loading" (no reset effect: one that ran after a fast,
  // cached load would hide a logo that had already loaded).
  return src ? <BrandLogoImage key={src} src={src} /> : <RallyMark />;
}

function BrandLogoImage({ src }: { src: string }) {
  const [state, setState] = useState<"loading" | "ok" | "failed">("loading");
  if (state === "failed") return <RallyMark />;
  return (
    <span className="join-brand__logoslot">
      <img
        className="join-brand__logo"
        data-testid="join-brand-logo"
        data-state={state}
        src={src}
        alt=""
        onLoad={() => setState("ok")}
        onError={() => setState("failed")}
      />
    </span>
  );
}

function BrandContactLine({ contact }: { contact: BrandContact }) {
  // Re-validated at render, so a draft or a bug upstream can never make an href.
  if (!validContact(contact.kind, contact.value)) return null;
  const tel = contact.kind === "phone" ? phoneHref(contact.value) : null;
  const web = contact.kind === "url" ? urlContact(contact.value) : null;
  return (
    <p className="join-brand__contact" data-testid="join-brand-contact" data-kind={contact.kind}>
      <span className="join-brand__contactlabel">
        {contact.kind === "phone" ? "Phone" : contact.kind === "email" ? "Email" : "Website"}
      </span>{" "}
      {tel ? (
        <a href={tel}>{contact.value}</a>
      ) : web ? (
        // The host in bold, the rest as the server stored it: the destination is on screen before it is clicked.
        <a href={web.href} target="_blank" rel="noopener noreferrer nofollow">
          https://<strong>{web.host}</strong>
          {web.rest}
        </a>
      ) : (
        // An email is text, never a link.
        <span className="join-brand__contactvalue" dir="ltr">
          {contact.value}
        </span>
      )}
    </p>
  );
}

function BrandMessage({ name, text, contact }: { name: string; text: string; contact: BrandContact | null }) {
  const titleId = useId();
  const hasContact = contact !== null && validContact(contact.kind, contact.value);
  if (text === "" && !hasContact) return null;
  return (
    <aside
      className="join-brand__message"
      data-testid="join-brand-message"
      {...(text !== "" ? { "aria-labelledby": titleId } : { "aria-label": "Support contact" })}
    >
      {text !== "" && (
        <>
          <h2 className="join-brand__message-title" id={titleId}>
            Message from <BrandName text={name} />
          </h2>
          <p className="join-brand__message-text" data-testid="join-brand-text" dir="auto">
            {text}
          </p>
        </>
      )}
      {hasContact && <BrandContactLine contact={contact} />}
    </aside>
  );
}

/**
 * The brand the page may actually show. A tenant brand is shown ONLY together with the fixed attribution link to the
 * DEFAULT host's /docs, built from the deployment's configured origin (`VITE_DEFAULT_ORIGIN`, re-validated here).
 * When that origin is unset or invalid the page is the NEUTRAL one: never a branded page without the link.
 */
export function effectiveBrand(brand: HostBrand, defaultOrigin: string | undefined | null): HostBrand {
  return defaultDocsLink(defaultOrigin) === null ? NEUTRAL_BRAND : brand;
}

/** Fixed on every branded page: a guest who distrusts a name can still see what software it is. */
function BrandAttribution({ href }: { href: string }) {
  // The link is the DEFAULT host's /docs, built from a trusted deployment value; never this page's own host
  // (which a tenant controls). The caller renders the neutral page when there is no valid link, so it is always set.
  return (
    <p className="join-brand__attribution" data-testid="join-attribution">
      <RallyMark />
      <span>
        Remote support software by <a href={href}>DeskRally</a>
      </span>
    </p>
  );
}

export interface JoinBrandProps {
  /** A validated brand; NEUTRAL_BRAND for the page as the deployment ships it. */
  brand: HostBrand;
  /** The deployment's build-time product name, used when the brand carries none. */
  fallbackName?: string;
  /**
   * Where the logo loads from. The page passes the published-hash route (`publicBrandingLogoUrl`); a preview
   * passes its draft. Ignored for a neutral brand.
   */
  logoSrc?: string;
  /**
   * The DEFAULT host's origin (`VITE_DEFAULT_ORIGIN`); the attribution links to its /docs. Re-validated by
   * `defaultDocsLink`. Absent or invalid: the page renders NEUTRAL (see `effectiveBrand`), never branded without it.
   */
  defaultOrigin?: string;
  /** True while the host's brand is still being fetched: the neutral page is shown, flagged so tests can tell. */
  loading?: boolean;
  /** The top bar's links. Omitted by a preview. */
  nav?: ReactNode;
  /** The decorative welcome panel beside the content. Omitted by a preview (the layout then has one column). */
  welcome?: ReactNode;
  /** The page's own content, rendered after the brand's message and attribution. */
  children?: ReactNode;
}

export function JoinBrand({ brand: requestedBrand, fallbackName, logoSrc, defaultOrigin, loading = false, nav, welcome, children }: JoinBrandProps) {
  const docsHref = defaultDocsLink(defaultOrigin);
  const brand = effectiveBrand(requestedBrand, defaultOrigin);
  const branded = brand.name !== "" && docsHref !== null;
  const name = brandDisplayName(brand, fallbackName);
  return (
    <div
      className="join"
      style={accentStyle(brand.accent)}
      data-testid="join-root"
      data-brand-state={loading ? "loading" : branded ? "branded" : "neutral"}
    >
      <header className="join__topbar">
        <span className="join__brand">
          <BrandLogo src={branded && validLogoSrc(logoSrc) ? logoSrc : undefined} />
          <BrandName text={name} className="join__brandname" testId="join-brand-name" />
        </span>
        <span className="join__brandby">Remote support</span>
        {nav}
      </header>
      <div className={welcome ? "join__welcome-layout" : "join__welcome-layout join__welcome-layout--single"}>
        {welcome && (
          <aside className="join__welcome" aria-label="Welcome to DeskRally support">
            {welcome}
          </aside>
        )}
        <main className="join__main" data-testid="join-page">
          <h1 className="join__title">Get remote support</h1>
          {/* The fixed safety lede: no tenant input reaches it (docs/66 2a.7). Always first, always the same. */}
          <p className="join__lede">
            Do this only if YOU called your IT provider for help, using a phone number you looked up
            yourself. If someone phoned you unexpectedly and asked you to come here, stop and hang up.
          </p>
          {branded && <BrandMessage name={name} text={brand.supportText} contact={brand.contact} />}
          {branded && docsHref !== null && <BrandAttribution href={docsHref} />}
          {children}
        </main>
      </div>
    </div>
  );
}
