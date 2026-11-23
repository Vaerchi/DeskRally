import rallyRoute from "../assets/rally-route.svg";

/** A road and finish-line mark, shared by the public pages and console header. */
export function RallyMark() {
  return <img className="rally-mark" src="/icons/rally-mark.svg" width="30" height="30" alt="" aria-hidden="true" />;
}

/** Decorative rally artwork; the copy remains HTML, readable at every viewport size. */
export function RallyWelcome({ technician = false }: { technician?: boolean }) {
  return <div className={`rally-welcome${technician ? " rally-welcome--technician" : ""}`}>
    <div className="rally-welcome__copy">
      <p className="rally-welcome__eyebrow"><span aria-hidden="true" /> Remote support. Keep it simple.</p>
      <h2>{technician ? <>Your next stop.<br /><em>Back in control.</em></> : <>A clear route<br /><em>back to your day.</em></>}</h2>
      <p className="rally-welcome__description">{technician
        ? "Your machines, your tools, your team. Sign in and pick up where you left off."
        : "A little technical trouble? Connect with your technician and get moving again. You choose when to share your screen and when to end the session."}</p>
    </div>
    <div className="rally-welcome__art" aria-hidden="true">
      <span className="rally-welcome__plate">DR / 01</span>
      <img src={rallyRoute} alt="" width="800" height="520" />
      <span className="rally-welcome__compass">N <span>↑</span></span>
    </div>
    <div className="rally-welcome__footer"><span className="rally-checkers" aria-hidden="true" /> Good support keeps you moving.</div>
  </div>;
}
