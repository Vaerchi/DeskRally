// Mounts the REAL BackstagePanels with its default client, which POSTs to /backstage/exec on this
// origin, so a Playwright spec can answer, hold and fail backstage requests with page.route.
import React from "react";
import { createRoot } from "react-dom/client";
import { BackstagePanels } from "../src/components/BackstagePanels";
import "../src/index.css";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BackstagePanels machineName="TEST-PC" />
  </React.StrictMode>,
);
