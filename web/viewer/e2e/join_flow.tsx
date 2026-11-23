import { createRoot } from "react-dom/client";
import { JoinPage } from "../src/components/JoinPage";
import "../src/index.css";
// The join page under every config combination, chosen by the query string:
//   bundle=1  VITE_SUPPORT_BUNDLE_ENABLED on      url=1  VITE_SUPPORT_DOWNLOAD_URL (+sha256) set
//   code=XXXX the fragment code (default none)    platform=windows|other
const q = new URLSearchParams(location.search);
createRoot(document.getElementById("root")!).render(
  <JoinPage
    code={q.get("code") ?? ""}
    platform={(q.get("platform") as "windows" | "other") ?? "windows"}
    bundleEnabled={q.get("bundle") === "1"}
    download={q.get("url") === "1" ? { url: "/download/support/DeskRallySupport.exe", sha256: "ab".repeat(32) } : {}}
  />,
);
