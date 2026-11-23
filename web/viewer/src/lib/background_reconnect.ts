import { watchVisibility, type VisibilityDocument } from "./background";

interface BackgroundSession {
  generation: number;
  wasLive: boolean;
  failed: boolean;
  frames: number;
}

export function watchBackgroundReturn(
  doc: VisibilityDocument,
  win: Pick<Window, "addEventListener" | "removeEventListener">,
  session: () => BackgroundSession,
  reconnect: (isCurrent: () => boolean) => void,
): () => void {
  let hidden: { since: number; generation: number } | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let visibilityEpoch = 0;
  const onVisibility = (isHidden: boolean) => {
    if (isHidden) {
      if (hidden) return;
      const current = session();
      hidden = { since: Date.now(), generation: current.generation };
      visibilityEpoch++;
      clearTimeout(timer);
      return;
    }
    const previous = hidden;
    hidden = undefined;
    if (!previous || Date.now() - previous.since < 2000) return;
    const initial = session();
    if (!initial.wasLive || initial.generation !== previous.generation) return;
    const epoch = visibilityEpoch;
    const isCurrent = () => {
      const current = session();
      return epoch === visibilityEpoch && current.wasLive && current.generation === initial.generation;
    };
    const deadline = Date.now() + 5000;
    const check = () => {
      if (!isCurrent()) return;
      const current = session();
      if (current.failed) reconnect(isCurrent);
      else if (current.frames > initial.frames) return;
      else if (Date.now() >= deadline) reconnect(isCurrent);
      else timer = setTimeout(check, 250);
    };
    check();
  };
  const onPageShow = (event: PageTransitionEvent) => {
    if (event.persisted && doc.visibilityState === "visible") onVisibility(false);
  };
  const unsubscribe = watchVisibility(doc, onVisibility);
  win.addEventListener("pageshow", onPageShow);
  return () => {
    visibilityEpoch++;
    clearTimeout(timer);
    unsubscribe();
    win.removeEventListener("pageshow", onPageShow);
  };
}
