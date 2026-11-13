/**
 * The console's Help topics (components/HelpPanel.tsx). Plain strings only — rendered as React
 * text, never as HTML. Labels in quotes are the exact on-screen text; keep them in step with the UI
 * when a label changes (help_content.test.ts pins the topic structure, not the prose).
 */

export const HELP_CATEGORIES = [
  "Getting started",
  "Remote sessions",
  "Support & installing",
  "Machines",
  "Administration",
] as const;

export type HelpCategory = (typeof HELP_CATEGORIES)[number];

export interface HelpSection {
  heading?: string;
  text?: string[];
  steps?: string[];
  bullets?: string[];
  tip?: string;
}

export interface HelpTopic {
  id: string;
  title: string;
  category: HelpCategory;
  summary: string;
  sections: HelpSection[];
}

export const HELP_TOPICS: HelpTopic[] = [
  // ── Getting started ──────────────────────────────────────────────────────────────────────────
  {
    id: "welcome",
    title: "Finding your way around",
    category: "Getting started",
    summary: "What DeskRally does and where everything is in the console.",
    sections: [
      {
        text: [
          "DeskRally lets you see and control Windows computers remotely. Computers you manage permanently run the DeskRally agent and appear in your machine list. People you help once run a small support tool that installs nothing.",
        ],
      },
      {
        heading: "Finding your way around",
        text: [
          "Outside a session, the bar across the top lists the console's pages: Machines, Support, History, Manage ▾ and Admin ▾ (Admin only if you may use it). Machines and History have tabs for their pages (Live and Machines; Sessions, Recordings, Audit and Reports). At its right end are the 🙋 help requests (shown when someone is waiting), the 🔔 activity bell, and \"Account ▾\" with My account, Help, Downloads and Sign out.",
          "During a session that bar is folded away to give the remote screen the room, and the same pages, the bells and your account are in the \"DeskRally\" button at the top left. On a phone the \"DeskRally\" button is how you move between pages:",
        ],
        bullets: [
          "Live — your machine list; connect to a computer.",
          "Support — start a one-time support session for someone who is not enrolled.",
          "Machines, Sessions, Audit, Recordings, Reports — your fleet, session history and records (Recordings only if you may watch them).",
          "Install DeskRally — install DeskRally permanently on a new computer.",
          "Security, Users, Roles, Machine groups and the other settings areas — administration.",
          "My account — your password, email and authenticator app.",
          "Help — this page.",
          "\"Signed in as\" shows who you are signed in as; \"Sign out\" is right below it.",
        ],
      },
      {
        heading: "Small screens",
        text: [
          "\"Compact\" in the DeskRally menu hides the machine list behind the ☰ button so the remote screen gets the room. It works at any window width.",
        ],
      },
      {
        tip: "If an area shows an error instead of data, your role probably does not include that permission. Ask an owner or administrator.",
      },
    ],
  },
  {
    id: "sign-in",
    title: "Signing in and out",
    category: "Getting started",
    summary: "Passwords, authenticator codes, Microsoft sign-in, and signing out.",
    sections: [
      {
        heading: "Sign in with a password",
        steps: [
          "Open your organization's address, for example https://yourcompany.deskrally.com/console.",
          "\"Tenant\" is filled in from the address. Enter your \"Email\" and \"Password\".",
          "If you have set up an authenticator app, type the 6-digit code into \"TOTP code (if enabled)\".",
          "Click \"Sign in\".",
        ],
      },
      {
        heading: "Sign in with Microsoft",
        text: [
          "If your organization has set up Microsoft sign-in, click \"Sign in with Microsoft\" and sign in as usual. Your DeskRally account must first be linked to your Microsoft account (My account → \"Link Microsoft account\").",
          "DeskRally may then ask for its own authenticator code on a \"Complete Microsoft sign-in\" page. The page explains why — usually because your organization has not told DeskRally to trust Microsoft's own multi-factor check.",
        ],
      },
      {
        heading: "Signing out",
        text: [
          "DeskRally menu → \"Sign out\". Sessions also end after a period of inactivity; you will be asked to sign in again.",
        ],
      },
      {
        tip: "Forgot your password? Ask an administrator to create a new \"Setup link\" for you in Users.",
      },
    ],
  },
  {
    id: "my-account",
    title: "Your account: password, email, authenticator",
    category: "Getting started",
    summary: "Change your password or login email, and set up two-factor sign-in.",
    sections: [
      {
        heading: "Set up an authenticator app (recommended)",
        steps: [
          "DeskRally menu → \"My account\" → \"Set up authenticator\".",
          "Enter your current password and click \"Generate secret\".",
          "In your authenticator app (Microsoft Authenticator, Google Authenticator, 1Password…), add an account using \"Copy secret\".",
          "Type the code the app shows into \"Confirmation code\" and click \"Confirm enrollment\".",
        ],
        text: ["From then on, enter the app's current code when you sign in."],
      },
      {
        heading: "Change your password",
        text: [
          "Under \"Change password\", enter your current and new password. All your other signed-in browsers and apps are signed out; this one stays signed in.",
        ],
      },
      {
        heading: "Change your login email",
        text: ["Under \"Change login email\", enter the new address twice and your \"Current password\"."],
      },
      {
        heading: "Microsoft sign-in",
        text: [
          "\"Link Microsoft account\" lets you use \"Sign in with Microsoft\". It asks for your authenticator code first. Linking has to be done in a web browser, not the desktop app. \"Unlink\" removes it.",
        ],
      },
    ],
  },

  // ── Remote sessions ──────────────────────────────────────────────────────────────────────────
  {
    id: "connect",
    title: "Connecting to a computer",
    category: "Remote sessions",
    summary: "Find a machine in the list and start a session, or watch without control.",
    sections: [
      {
        steps: [
          "Open \"Live\". Search the list (\"Search alias, name, group, OS…\") or tick \"Online only\".",
          "Click \"Connect\" next to the computer. The screen appears in a few seconds.",
          "When you are done, click \"Disconnect\".",
        ],
      },
      {
        heading: "Other ways to connect",
        bullets: [
          "\"⋯\" → \"View only\" (multi-session machines) watches without any control: you see the screen but cannot type, click or run anything. The session shows \"Observing · view only\".",
          "\"⋯\" → \"↗ Open in new tab\" opens the computer in a new browser tab, so you can work on several at once.",
          "\"Connect in\" (DeskRally menu) chooses whether sessions open in the desktop app or in this browser.",
        ],
      },
      {
        heading: "Someone else is already connected",
        text: [
          "An \"In session\" badge shows a session in progress; hover it to see who. Several technicians can share one computer — the session bar shows \"N co-tech(s) · N observing\". Use \"⋯\" → \"End session\" only if you mean to end the other person's session.",
        ],
      },
      {
        tip: "A machine that looked offline at the last check can still be tried — \"Connect\" is never disabled.",
      },
    ],
  },
  {
    id: "session-toolbar",
    title: "Using the session toolbar",
    category: "Remote sessions",
    summary: "Monitors, picture quality, keyboard and mouse, and remote tools.",
    sections: [
      {
        heading: "Monitors",
        text: [
          "Pick \"Display 1\", \"Display 2\"… or \"View all (composite)\". \"Display N ↗\" opens one monitor in its own window.",
        ],
      },
      {
        heading: "\"View ▾\"",
        bullets: [
          "\"Sound on\" / \"Sound off\" — hear the remote computer.",
          "\"Quality\" — Best (LAN), Balanced, Low bandwidth or Text (slow link). Use Low bandwidth on poor connections. The live picture-quality readout is under it.",
          "Size and window: zoom (−, +, \"Fit\", \"1:1\"), \"✋ Pan\", \"Full screen\", \"⧉ Pop out\" to move the remote screen into its own window, and one window per monitor.",
        ],
      },
      {
        heading: "\"Input ▾\"",
        bullets: [
          "\"Capture input\" — send your keyboard and mouse to the computer.",
          "\"Special keys ▼\" — Ctrl+Alt+Del, Windows key, Alt+Tab, Alt+F4 and others that your own computer would otherwise catch.",
          "\"⌨ Keyboard\" — type with your phone's, tablet's or computer's own keyboard. A row above it has the keys a phone keyboard lacks: Ctrl, Alt and Win (tap one, then the next key or letter — Ctrl then C sends Ctrl+C), Esc, the arrows, Home, End, Tab and Del.",
          "\"Block guest input\" — stop the person at the computer from using their mouse and keyboard while you work.",
          "\"Blank guest screen\" — hide what you are doing from anyone sitting at the computer.",
          "\"View only\" — stop sending your input. \"🔒 View only (policy)\" means your organization requires it for this computer.",
        ],
      },
      {
        heading: "\"Tools ▾\"",
        bullets: [
          "Recording: \"Record\" — record the session (see Recording sessions).",
          "\"Screenshot\" — a full-quality picture of the remote screen; click Save when it arrives.",
          "\"Note\" — add a note to this session's record.",
          "\"Command\" — run a one-line Command Prompt or PowerShell command and see the output. \"Run as admin\" runs it with the signed-in user's administrator rights (recorded in the audit trail).",
          "\"Toolbox…\" — run one of your saved scripts.",
          "\"Files\" — browse the remote computer's files and upload or download.",
          "\"Windows desktop tools ▾\" — Task Manager, Registry Editor, Event Viewer, Services, Device Manager: opens the tool on the remote computer.",
          "Power and user session: \"Lock\", \"Log off\", \"Restart\" (normally or into Safe Mode with Networking — the session reconnects by itself) and \"Shut down\" (the computer stays off until someone turns it on). Log off, Restart and Shut down ask before they act.",
        ],
      },
      {
        heading: "\"Session\"",
        bullets: [
          "The computer's name and connection state, then Clipboard, Collaboration and Connection.",
          "Collaboration: \"Hand over session…\" gives the session to a colleague, \"Invite a colleague\" copies a watch or control link for them, \"Request admin rights\" (support sessions), and passing keyboard and mouse control to another technician.",
          "Connection: \"Hide toolbar\" and connection diagnostics.",
        ],
      },
    ],
  },
  {
    id: "files-chat-clipboard",
    title: "Files, chat and clipboard",
    category: "Remote sessions",
    summary: "Move files, talk to the user, and copy and paste between computers.",
    sections: [
      {
        heading: "Files",
        bullets: [
          "\"Session view\" → \"Files\": drag a file in, or \"Choose file…\", to upload it to the remote computer.",
          "To download, enter the file name and click \"Download\". The result shows \"sha256 verified ✓\" when the copy is intact.",
          "Tools ▾ → \"Files\" browses folders on the remote computer (\"⬆ Upload here\", ⬇ to download).",
          "When the remote computer sends you a file, a prompt asks you to \"Save\" or \"Dismiss\" it.",
        ],
      },
      {
        heading: "Chat",
        text: [
          "\"Session view\" → \"Chat\". Type a message and press Enter (Shift+Enter for a new line). The person at the computer sees it in a chat window.",
        ],
      },
      {
        heading: "Clipboard",
        bullets: [
          "\"Session\" menu → \"Send clipboard → agent\" puts what you copied onto the remote computer's clipboard.",
          "\"Receive remote clipboard\" turns on copying from the remote computer back to yours (off by default, and only for this session).",
        ],
        tip: "Your organization can restrict clipboard direction per computer; if an option is missing, a policy has turned it off.",
      },
    ],
  },
  {
    id: "under-the-hood",
    title: "Under the Hood: working without disturbing the user",
    category: "Remote sessions",
    summary: "Processes, services, files, event logs and system information in the background.",
    sections: [
      {
        text: [
          "\"Session view\" → \"Under the Hood\" shows tools that work in the background, without taking over the screen the user is looking at.",
        ],
        bullets: [
          "Processes (\"Kill\"), Services (\"Start\", \"Stop\", \"Restart\"), Files, Event Log and System.",
          "Anything destructive asks you to type the computer's name to confirm.",
          "If Under the Hood needs authorization, click \"Get access\". Your permissions decide which tools work.",
        ],
      },
    ],
  },
  {
    id: "recording",
    title: "Recording sessions",
    category: "Remote sessions",
    summary: "Start, stop and find session recordings, and what policies can require.",
    sections: [
      {
        bullets: [
          "Tools ▾ → \"Record\" starts recording; \"Stop recording\" ends it. The person at the computer is told the session is being recorded.",
          "By default a recording is saved only on the remote computer (C:\\rmt-agent\\recordings) and deleted there after about 72 hours. Nothing is uploaded.",
          "If your organization has turned on central recording storage (Security → \"Session recording storage\"), the finished recording is uploaded to the server afterwards, once no session is running on that computer, and kept for the retention period you set. The computer deletes its own copy only after the server confirms it has it.",
          "\"Recording (Required)\" means your organization records every session on this computer; it cannot be stopped.",
          "If recording is blocked by policy, the button is unavailable.",
        ],
      },
      {
        heading: "Watching stored recordings",
        bullets: [
          "\"Recordings\" appears under History only for people allowed to watch recordings (Owner, Admin and Auditor by default, limited to their groups). A technician cannot replay their own sessions unless given that permission.",
          "\"Play\" plays the recording one segment after another. \"Evidence ZIP\" downloads the original recording files with a manifest of their SHA-256 digests. Every playback and download is written to the audit trail.",
          "\"Playback ready\" means a playable copy exists. \"Evidence complete\" means the original is stored and the playable copy is still being made. \"Playback failed\" means only the original is available (download it as evidence). \"Expired\" means the retention period ended and the recording was removed; the audit record of the session remains. \"Lost\" means the file could not be found after the server was restored.",
          "\"Agent-signed; matches session audit\" means the computer's agent signed the recording and a signed stop event in the session audit trail carries the same digests. \"Agent-signed; no matching stop event\" means no such event exists (for example the session ended abnormally). Neither is independent verification that the screen was captured faithfully: whoever controls the computer's agent key could fabricate either.",
          "\"Truncated\" or \"frames dropped\" means the recording is incomplete; the cut is not hidden.",
        ],
      },
      {
        heading: "Turning storage on (Owner)",
        bullets: [
          "Security → \"Session recording storage\". Off (0 days) is the default: new recordings stay only on the computer. Turning storage off later stops new uploads; recordings already on the server remain until their deletion date. Choose 30 days, 90 days or another number from 1 to 365; recordings are deleted from the server after that. Turning storage on asks you to confirm.",
          "\"Largest single recording\" (at most 1024 MiB) and \"Total storage quota\" limit what is kept. A recording that does not fit is not uploaded and stays only on the computer.",
          "Retention is a deletion deadline, not a durability promise: ask your server administrator whether the recordings volume is backed up.",
        ],
      },
    ],
  },
  {
    id: "connection-problems",
    title: "When a session will not connect",
    category: "Remote sessions",
    summary: "Black screens, dropped connections and what to send your administrator.",
    sections: [
      {
        bullets: [
          "If the connection drops you will see \"The displayed image may be out of date. Remote input is paused.\" Click \"Reconnect\".",
          "A computer that has just restarted can take a minute to come back online.",
          "On a slow connection, set View ▾ → \"Quality\" to Low bandwidth.",
        ],
      },
      {
        heading: "Still not working?",
        steps: [
          "Open the \"Session\" menu → \"Connection details\".",
          "Note the readings, wait about 10 seconds, and note them again.",
          "Reconnect once.",
          "Send those readings to your administrator. Never send passwords, tokens or files from C:\\rmt-agent.",
        ],
      },
    ],
  },

  // ── Support & installing ─────────────────────────────────────────────────────────────────────
  {
    id: "attended",
    title: "Helping someone once (attended support)",
    category: "Support & installing",
    summary: "Give a person a code; they run a small tool and approve; you connect. Nothing is installed.",
    sections: [
      {
        heading: "You",
        steps: [
          "Open \"Support\".",
          "Choose a \"Machine group\" and type a \"Reason (shown to the user)\", for example \"printer support\".",
          "Click \"Start support session\". Read the one-time code to the person, or send them the \"Join link\". The code is shown only once and expires after 10 minutes.",
          "Wait for \"Consent granted — you can connect.\", then click \"Connect\".",
          "Click \"End\" when you are finished.",
        ],
      },
      {
        heading: "The person you are helping",
        steps: [
          "Opens the join link (or your organization's address followed by /join) — the page is \"Get remote support\".",
          "Clicks \"Download support client\" (with a code, that download is a ZIP that already contains it) and runs DeskRallySupport.exe. It is not installed and should not be run as administrator.",
          "Enters the code if asked, then answers \"Yes\" to \"Allow the remote support session?\", which shows your reason.",
        ],
        tip: "The support tool does not work inside a Remote Desktop session, and some company security policies block it.",
      },
      {
        heading: "Making it permanent",
        text: [
          "During the session, click \"Enable unattended access\". The person is asked to approve a permanent install and a Windows administrator prompt. If they decline, you can ask again. Afterwards the computer appears in your machine list.",
        ],
      },
      {
        tip: "Lost the code? End that invitation and start a new support session.",
      },
    ],
  },
  {
    id: "help-requests",
    title: "When a guest asks for help",
    category: "Support & installing",
    summary: "A person at an enrolled computer asks for a technician; you accept and connect in one step.",
    sections: [
      {
        text: [
          "Someone using a computer that already has the DeskRally agent can ask for help from the agent's tray icon. The request appears in your console as a badge on the \"Help requests\" button at the top of the window, separate from the notifications bell. Only people who may start sessions on that computer's group see it, and it expires after 30 minutes.",
        ],
      },
      {
        heading: "Taking a request",
        steps: [
          "Click \"Help requests\" to see who is asking. Each entry shows the computer, and the note under \"From the guest's machine\". The note is the person's own words, shown as plain text: it is not verified, and it is not consent.",
          "Click \"Accept\". DeskRally starts a session for that request and connects you to the computer.",
          "If another technician took it first, it expired, the person cancelled, or a session limit is reached, you see the reason instead and nothing connects.",
        ],
      },
      {
        heading: "When there is no \"Accept\"",
        bullets: [
          "A computer that is offline shows \"Offline\" and cannot be connected to. The request stays until it expires, so you can accept once the computer is back.",
          "A request disappears for everyone when its computer is retired or quarantined.",
          "If the computer is moved to another group, the request follows it: only people covering the new group see it.",
        ],
      },
      {
        tip: "Accepting does not add or remove any approval: it connects the way \"Connect\" on the machine list does, under the same session policy and limits. Someone who is not enrolled still needs an attended support invitation.",
      },
    ],
  },  {
    id: "install-agent",
    title: "Installing the agent on a computer",
    category: "Support & installing",
    summary: "Add a computer to your machine list for permanent, unattended access.",
    sections: [
      {
        steps: [
          "Manage → \"Install DeskRally\" → \"Install a computer\".",
          "Choose the \"Machine group\" the computer should join. (Groups are created under \"Machine groups\".)",
          "Click \"Download Windows installer\". You get DeskRally-Install.zip. It works for ONE computer and expires 15 minutes after you download it — do not share it.",
          "On the computer, extract all the files to a local folder (not a network share) and double-click DeskRallySetup.exe.",
          "Read the \"Permanent Unattended Access\" confirmation and approve the Windows administrator prompt.",
          "When it says \"DeskRally Remote Agent installed successfully.\", delete the ZIP and the extracted files.",
        ],
        text: ["The computer appears in \"Live\" and \"Machines\" under its Windows name within a minute or so."],
      },
      {
        heading: "Updates",
        text: [
          "Installed agents update themselves from your server. An update waits until no session is open, and rolls back by itself if the new version does not start properly.",
        ],
      },
      {
        heading: "If it does not work",
        bullets: [
          "\"enrollment.token is invalid\" or the bundle is older than 15 minutes: download a new one.",
          "Setup refuses the folder: extract to a local folder such as C:\\Temp, not a network share or a redirected Desktop.",
          "\"The preconfigured installer is not available on this server yet.\": your server administrator has not enabled the installer bundle. Use the silent install instead.",
        ],
      },
    ],
  },
  {
    id: "silent-install",
    title: "Install agents silently",
    category: "Support & installing",
    summary: "Install on many computers with a script or management tool.",
    sections: [
      {
        heading: "1. Get an enrollment token",
        steps: [
          "\"Install DeskRally\" → \"Advanced: enrollment tokens\".",
          "Choose the \"Machine group\", optionally \"Expires in days\" and \"Max uses\", and click \"Mint token\".",
          "Copy the token — it is shown only once. Revoke it from the same list when you are done.",
        ],
      },
      {
        heading: "2. Get the files",
        bullets: [
          "DeskRallyAgent.msi — it is inside the installer bundle from \"Download Windows installer\" (Install a computer).",
          "new-msi-provisioning.ps1 — from your server's address followed by /download/agent/new-msi-provisioning.ps1.",
        ],
      },
      {
        heading: "3. Install (elevated PowerShell on each computer)",
        text: [
          "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force",
          "$p = .\\new-msi-provisioning.ps1 -ControlPlaneUrl 'https://<your server>/cp' -SignalingUrl 'wss://<your server>/ws' -GrantIssuerPubkey '<grant issuer key>'",
          "msiexec.exe /i .\\DeskRallyAgent.msi /qn /norestart PROVISIONINGFILE=\"$p\" /l*v \"$env:TEMP\\DeskRally-install.log\"",
          "Remove-Item $p",
        ],
        tip: "The first line lets this window run the downloaded script; Windows refuses it by default. The grant issuer key is the server's SIGNALING_TICKET_PUBKEY (64 hex characters, in the server's deploy/.env; the same for every computer). The script asks for the token and stores it in a file only administrators can read, so it never appears on a command line. Delete the file after installing.",
      },
      {
        heading: "Install log codes",
        bullets: [
          "20 — the provisioning file or a setting is missing or invalid.",
          "21 — the file's location or permissions are not trusted (network path, link).",
          "22 — an existing installation's settings are damaged.",
          "23 — enrollment failed: the token is wrong, expired or used up, or the server cannot be reached.",
          "24 — a local file error.",
        ],
      },
    ],
  },
  {
    id: "desktop-app",
    title: "The desktop app",
    category: "Support & installing",
    summary: "Run the console in its own window on Windows.",
    sections: [
      {
        steps: [
          "DeskRally menu → \"Downloads\" → \"Download Windows desktop app\".",
          "Extract the package and run Install-DeskRally-Client.cmd. No administrator rights are needed.",
          "Start DeskRally from the Start menu and enter your organization name the first time.",
        ],
      },
      {
        bullets: [
          "\"Connect in\" → \"Desktop app\" makes the console open sessions in the app.",
          "\"Sign in with Microsoft\" works inside the app (version 0.8.0 and later). Duo and some company sign-in pages are not supported there — the app tells you to use a web browser.",
          "The app updates itself; Updates → \"Check for updates\" checks now. Help → \"About DeskRally\" shows the version.",
          "With Windows Hello turned on (Security menu), you can tick \"Remember this app for 30 days\" when signing in, with your password or with \"Sign in with Microsoft\". Tick it before clicking either.",
        ],
      },
    ],
  },

  // ── Machines ─────────────────────────────────────────────────────────────────────────────────
  {
    id: "machines",
    title: "Managing machines",
    category: "Machines",
    summary: "Rename, move, quarantine and annotate computers.",
    sections: [
      {
        bullets: [
          "\"Machines\" lists every enrolled computer with its group, status, agent version and signed-in user. Search, or \"Search by property\".",
          "\"⋯\" → \"Rename\" gives a computer a friendly name. \"Add note\" stores a note for your team.",
          "Change a computer's group or status from its row, or select several and use \"Set status\" or \"Move to group\". Groups are listed with their path (\"Acme › Site A\") so equal names stay apart.",
          "Status: active (normal), quarantined (no new sessions), retired.",
          "\"Properties\" stores your own key/value labels, which Smart groups and Sites can use.",
          "A version \"⚠ mismatch\" means the computer runs a different agent version than the published one; it normally updates itself.",
          "\"Export CSV\" downloads the list.",
        ],
        tip: "Moving a computer to another group changes who can reach it and which policies apply.",
      },
    ],
  },
  {
    id: "groups-and-policy",
    title: "Machine groups",
    category: "Machines",
    summary: "Groups decide who can reach which computers and what a session may do.",
    sections: [
      {
        text: [
          "Every computer belongs to exactly one access & policy group. Technicians are given access per group, and each group carries its session policy.",
        ],
        steps: [
          "\"Machine groups\" → enter a \"Name\" → \"Create group\".",
          "Click \"Edit policy\" on the group, change its settings, then click \"Save policy\". \"Cancel\" puts back what is saved.",
        ],
      },
      {
        heading: "Subgroups",
        bullets: [
          "Groups can be nested up to 4 levels. Click \"New subgroup\" on a group, or choose a parent under \"Under\" before \"Create group\".",
          "Access given on a group covers all of its subgroups (the Users list shows this as \"Site A (and subgroups)\"). Access on a subgroup never reaches its parent or its siblings.",
          "\"Move…\" puts a group, with everything inside it, under another group or back at \"Top level\". This changes who can reach every computer in it, so only move groups you are allowed to manage. If the move is refused (it would loop, nest too deep, or clash with a policy) the reason is shown.",
          "A group is shown with its path, for example \"Acme › Site A › Lab\", wherever you pick a group, so groups with the same name stay apart. You only see the groups you can access: if a group's parent is outside your access, it appears at the top level.",
          "A group with subgroups cannot be deleted until its subgroups are moved or deleted. Search keeps the parents of every match.",
        ],
      },
      {
        heading: "Policy settings",
        bullets: [
          "View only — technicians can watch but not control.",
          "Under the Hood on view-only — still allow the background tools on view-only computers.",
          "Recording — Allowed, Blocked (sessions cannot be recorded) or Required (every session is recorded).",
          "Max session length, Max idle time — end sessions after a time limit, in seconds (0 = unlimited).",
          "Max sessions at once — 0 = unlimited (a limit also needs a max session length).",
          "A subgroup inherits its parents' policy and can only make it stricter: view-only, block and require recording add up, the shortest time limit and the lowest session limit win (a limit on a parent counts the sessions of all its subgroups). \"Effective policy\" shows the result next to each group's own settings.",
          "If a group ends up with recording both required and blocked (one set on a parent, the other below), \"Effective policy\" shows a conflict warning and new sessions in that group are refused until one is cleared.",
        ],
      },
    ],
  },
  {
    id: "sites-and-smart-groups",
    title: "Sites and smart groups",
    category: "Machines",
    summary: "Label computers by location, and build saved filters.",
    sections: [
      {
        heading: "Sites",
        text: [
          "A site is a label for where a computer is (an office, a customer). Select computers, type a name in \"Site for selected machines\", then \"Review assignment\" and \"Set site\". Sites do not grant or restrict access.",
        ],
      },
      {
        heading: "Smart groups",
        text: [
          "A smart group lists every computer whose property matches a value — for example key \"department\", value \"finance\". It is worked out live and does not grant access. Click \"Members\" to see who matches.",
        ],
      },
    ],
  },
  {
    id: "remove-agent",
    title: "Reinstall or remove an agent",
    category: "Machines",
    summary: "Repair or uninstall the agent on a computer without opening a session.",
    sections: [
      {
        bullets: [
          "These actions are for owners (the \"remove agent\" right). They are in the computer row's \"⋯\" menu (More actions), and do not appear for anyone else.",
          "\"Reinstall agent\" (active computers) repairs the agent to the current release. Its identity and settings are kept. Limits: 3 per computer per day and 20 per hour for the organisation.",
          "\"Remove agent…\" appears only on RETIRED computers. It uninstalls the service and deletes its files and identity. The computer can never reconnect with that identity, and recordings kept only on it are deleted unless central storage already holds them.",
          "\"Forget this machine…\" also appears only on RETIRED computers (and on a \"Removal unconfirmed\" row under \"Pending removals\"). It permanently removes the computer from DeskRally and does NOT uninstall anything on it. Use it when the computer is gone or its removal will never be confirmed. It can never reconnect with its current identity; reinstalling the agent enrolls it as a new computer.",
        ],
        steps: [
          "Set the computer to \"retired\" first, then click \"Remove agent…\".",
          "Type the computer's name exactly and enter your authenticator code, then \"Request removal\".",
          "You have a 15-minute window to \"Cancel removal\". Nothing is sent before it ends.",
          "If \"Require a second approver for agent removal\" is on, a different owner approves it under \"Pending removals\" (with their own code) and the 15 minutes start again.",
          "To forget a computer instead: type its name exactly, enter your authenticator code, then \"Forget this machine\". This cannot be undone.",
        ],
        tip: "\"Removal unconfirmed\" means the agent has not reported back. The computer stays retired and locked until it does, or until an owner chooses \"Forget this machine…\". Turning on the second-approver policy is recommended.",
      },
    ],
  },
  {
    id: "toolbox",
    title: "Toolbox: saved scripts",
    category: "Machines",
    summary: "Save scripts once and run them on one or many computers.",
    sections: [
      {
        steps: [
          "\"Toolbox\" → \"New script\". Give it a \"Name\", choose \"Scope\" (Personal or Shared), \"Shell\" (PowerShell or cmd) and \"Run as\" (SYSTEM or Signed-in user), and paste the \"Script\".",
          "In a session: Tools ▾ → \"Toolbox…\" → pick the script → \"Run script\".",
          "On many computers: \"Run on machines…\" (up to 25 online computers at a time) → \"Continue\" → \"Run\". Results can be exported as CSV.",
        ],
      },
    ],
  },

  // ── Administration ───────────────────────────────────────────────────────────────────────────
  {
    id: "users-and-roles",
    title: "Users and roles",
    category: "Administration",
    summary: "Add people, choose what they can do, and help them get in.",
    sections: [
      {
        heading: "Add a user",
        steps: [
          "\"Users\" → enter the email (and optionally a display name), choose a role and click \"Add user\".",
          "Click \"Setup link\" for the new user, confirm \"Your password\", then \"Create setup link\" and send them the link. It works once.",
        ],
      },
      {
        heading: "Roles",
        bullets: [
          "owner — everything, including security settings.",
          "admin — manages users, machines and settings, but cannot act on an owner.",
          "technician — connects to and supports computers (the default).",
          "readonly — can look but not change.",
          "auditor — reads the audit trail and reports.",
        ],
        text: ["\"Roles\" shows exactly which capabilities each role has."],
      },
      {
        heading: "Helping a user",
        bullets: [
          "Forgotten password — create a new \"Setup link\".",
          "Locked out after wrong codes — \"Reset lockout\".",
          "Lost or stolen device — \"Sign out\" ends all of their sessions; \"Disable\" blocks the account.",
          "Someone leaving — \"Disable\" them here even if they sign in with Microsoft: a remembered desktop app stays signed in until DeskRally ends it.",
        ],
      },
    ],
  },
  {
    id: "security-settings",
    title: "Security settings",
    category: "Administration",
    summary: "Microsoft sign-in, required two-factor, IP allow-list and session limits.",
    sections: [
      {
        heading: "Require two-factor sign-in",
        text: [
          "\"Security\" → tick \"Require TOTP 2FA for all tenant members\". Set up your own authenticator first (My account) — DeskRally will not let you lock yourself out.",
        ],
      },
      {
        heading: "Microsoft sign-in (Entra ID)",
        steps: [
          "In the Microsoft Entra admin center, register an app. Use \"Copy redirect URI\" from DeskRally as its redirect URI, and create a client secret.",
          "In DeskRally → \"Security\" → \"Single sign-on (Microsoft Entra ID)\", fill in \"Entra tenant ID\", \"Client ID\" and \"New client secret\", tick \"Enabled\" and click \"Save\" (you will be asked for your authenticator code).",
          "Click \"Test sign-in\" to check it.",
          "Each person then links their account under My account → \"Link Microsoft account\".",
          "When someone leaves, also \"Disable\" them in DeskRally (Users). Turning off their Microsoft account stops new sign-ins, but a desktop app they told to \"Remember this app for 30 days\" stays signed in for up to 30 days (7 without use) until DeskRally ends it.",
        ],
        tip: "\"Trust Entra MFA\" lets Microsoft's multi-factor check replace DeskRally's code. It needs the \"amr\" optional claim added to the app registration's ID token.",
      },
      {
        heading: "IP allow-list",
        text: [
          "Only addresses on the list can use the console. Add your own address (\"Your current IP\" is shown) before anything else, or you will lock yourself out.",
        ],
      },
      {
        heading: "Concurrent sessions",
        text: ["Limit how many sessions can be open at once and how long each can last."],
      },
    ],
  },
  {
    id: "audit-and-reports",
    title: "Audit trail, sessions and reports",
    category: "Administration",
    summary: "See who did what, when, and export it.",
    sections: [
      {
        bullets: [
          "\"Sessions\" — every session with technician, machine, start, end and duration. Live sessions can be ended here. Filter by date; \"Export CSV\".",
          "\"Audit\" — every recorded action (sign-ins, connections, changes). Search by \"Action\", \"Target\", \"Actor\" or date.",
          "\"Reports\" — totals: events by action, sessions by machine, sessions by technician, with charts.",
        ],
        tip: "All times are shown in UTC.",
      },
    ],
  },
  {
    id: "integrations",
    title: "API tokens and webhooks",
    category: "Administration",
    summary: "Connect DeskRally to scripts and other systems.",
    sections: [
      {
        heading: "API tokens",
        text: [
          "\"API tokens\" → give it a \"Name\", choose only the \"Capabilities\" it needs, optionally an expiry, and click \"Mint token\". Copy it — it is shown once. \"Revoke\" disables it.",
        ],
      },
      {
        heading: "Webhooks",
        text: [
          "\"Webhooks\" → enter an https:// \"URL\" and, optionally, which \"Events\" to send, then \"Register\". Copy the secret it shows (once) to verify deliveries. \"Deliveries\" shows recent attempts.",
        ],
      },
    ],
  },
  {
    id: "appearance",
    title: "Appearance",
    category: "Administration",
    summary: "Your product name and accent colour.",
    sections: [
      {
        text: [
          "\"Appearance\" → set the \"Product name\" and \"Accent colour\" and click \"Save\". \"Use default accent\" restores the original colour.",
        ],
      },
    ],
  },
];

/** True when every word of `query` appears somewhere in the topic (case-insensitive). */
export function topicMatches(topic: HelpTopic, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return true;
  const haystack = [
    topic.title,
    topic.summary,
    ...topic.sections.flatMap((s) => [
      s.heading ?? "",
      ...(s.text ?? []),
      ...(s.steps ?? []),
      ...(s.bullets ?? []),
      s.tip ?? "",
    ]),
  ]
    .join("\n")
    .toLowerCase();
  return words.every((w) => haystack.includes(w));
}
