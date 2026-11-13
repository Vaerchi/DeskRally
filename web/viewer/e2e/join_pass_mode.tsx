import React from "react";
import { createRoot } from "react-dom/client";
import { JoinPage } from "../src/components/JoinPage";
import "../src/index.css";
// The join page with a configured download and the session bundle enabled; the spec decides what
// GET /cp/attended-sessions/support-mode answers. ?nocode renders it without a session code.
const code = new URLSearchParams(location.search).has("nocode") ? "" : "ABCD2345";
createRoot(document.getElementById("root")!).render(
  <JoinPage code={code} platform="windows" bundleEnabled
    download={{ url: "/download/support/DeskRallySupport.exe", sha256: "ab".repeat(32) }} />,
);
