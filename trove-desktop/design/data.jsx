// Trove — mock vault data
// Entries use path-style names: the path segments form a group hierarchy,
// the last segment is the entry name.

const RAW_ENTRIES = [
  {
    path: "inpace/build_key/ssh",
    username: "deploy",
    password: "Gx7$mQ2!vLpZ9wKt",
    url: "ssh://build.inpace.io",
    type: "ssh",
    notes: "CI build signing key. Rotate quarterly.\nFingerprint: SHA256:kp9x…7Qd",
    fields: [
      { k: "Host", v: "build.inpace.io" },
      { k: "Port", v: "22" },
      { k: "Key ID", v: "build-key-2026" },
    ],
    strength: 88,
    modified: "2026-06-28T14:12:00Z",
    created: "2025-01-04T09:00:00Z",
    fav: true,
  },
  {
    path: "inpace/00004.alex-clinic/ssh",
    username: "root",
    password: "Tr0v3-alex-9812-xz",
    url: "ssh://10.4.0.12",
    type: "ssh",
    notes: "Bastion host for alex-clinic tenant.",
    fields: [
      { k: "Host", v: "10.4.0.12" },
      { k: "Tenant", v: "00004" },
    ],
    strength: 74,
    modified: "2026-06-30T08:41:00Z",
    created: "2025-03-12T11:20:00Z",
  },
  {
    path: "inpace/00004.alex-clinic/mtls",
    username: "svc-alex",
    password: "mS8*qWzR!2dLpV0c",
    url: "https://api.alex-clinic.inpace.io",
    type: "cert",
    notes: "mTLS client cert. Expires 2026-11-01.",
    fields: [
      { k: "Serial", v: "3F:A2:99:1C" },
      { k: "Expires", v: "2026-11-01" },
      { k: "CA", v: "inpace-internal" },
    ],
    strength: 91,
    modified: "2026-05-19T16:03:00Z",
    created: "2025-03-12T11:24:00Z",
  },
  {
    path: "inpace/00005.ostkreuz-clinic/ssh",
    username: "root",
    password: "ostk-77!Qm-2266zZ",
    url: "ssh://10.5.0.9",
    type: "ssh",
    notes: "",
    fields: [{ k: "Host", v: "10.5.0.9" }, { k: "Tenant", v: "00005" }],
    strength: 69,
    modified: "2026-06-11T10:22:00Z",
    created: "2025-04-02T13:00:00Z",
  },
  {
    path: "inpace/00005.ostkreuz-clinic/mtls",
    username: "svc-ostkreuz",
    password: "kZ2!pMw9*Rt6vQ1a",
    url: "https://api.ostkreuz-clinic.inpace.io",
    type: "cert",
    notes: "mTLS client cert.",
    fields: [{ k: "Serial", v: "1B:07:D4:5A" }, { k: "Expires", v: "2027-02-14" }],
    strength: 90,
    modified: "2026-06-02T09:15:00Z",
    created: "2025-04-02T13:05:00Z",
  },
  {
    path: "inpace/00006.nordhafen-clinic/ssh",
    username: "root",
    password: "abc123",
    url: "ssh://10.6.0.4",
    type: "ssh",
    notes: "TODO: rotate — weak password flagged.",
    fields: [{ k: "Host", v: "10.6.0.4" }, { k: "Tenant", v: "00006" }],
    strength: 12,
    modified: "2026-01-08T07:40:00Z",
    created: "2025-05-20T15:30:00Z",
  },
  {
    path: "personal/email/fastmail",
    username: "you@fastmail.com",
    password: "correct-horse-battery-staple-42",
    url: "https://app.fastmail.com",
    type: "login",
    notes: "Primary email.",
    fields: [{ k: "2FA", v: "TOTP enabled" }, { k: "Recovery", v: "printed" }],
    strength: 95,
    modified: "2026-06-29T20:10:00Z",
    created: "2024-11-01T08:00:00Z",
    fav: true,
  },
  {
    path: "personal/email/proton",
    username: "you@proton.me",
    password: "V!ale-2288-qMzx-0k",
    url: "https://mail.proton.me",
    type: "login",
    notes: "Secondary / encrypted.",
    fields: [{ k: "2FA", v: "TOTP enabled" }],
    strength: 82,
    modified: "2026-04-14T12:00:00Z",
    created: "2024-11-01T08:05:00Z",
  },
  {
    path: "personal/banking/n26",
    username: "you@fastmail.com",
    password: "9Rt$Kw2!pMz8vLq0",
    url: "https://app.n26.com",
    type: "login",
    notes: "IBAN on file. High-value — clipboard auto-clear on.",
    fields: [{ k: "IBAN", v: "DE89 3704 0044 0532 0130 00" }, { k: "2FA", v: "App" }],
    strength: 87,
    modified: "2026-06-25T18:30:00Z",
    created: "2024-12-15T10:00:00Z",
  },
  {
    path: "personal/social/github",
    username: "you",
    password: "gh-p@ss-7712-Kqmz",
    url: "https://github.com",
    type: "login",
    notes: "PAT stored as attribute.",
    fields: [{ k: "Token", v: "ghp_••••••••••••••" }, { k: "2FA", v: "Hardware key" }],
    strength: 79,
    modified: "2026-06-18T11:11:00Z",
    created: "2024-10-02T09:00:00Z",
  },
  {
    path: "personal/social/mastodon",
    username: "@you@hachyderm.io",
    password: "masto-5561-Qw!pZ",
    url: "https://hachyderm.io",
    type: "login",
    notes: "",
    fields: [],
    strength: 66,
    modified: "2026-02-20T14:45:00Z",
    created: "2025-01-10T09:00:00Z",
  },
  {
    path: "infra/prod/postgres",
    username: "trove_app",
    password: "pg-Pr0d-8842!zQmx-vK",
    url: "postgres://db.prod.internal:5432",
    type: "db",
    notes: "Read/write app role. Do not share.",
    fields: [{ k: "Host", v: "db.prod.internal" }, { k: "DB", v: "trove" }, { k: "SSL", v: "require" }],
    strength: 93,
    modified: "2026-07-01T06:20:00Z",
    created: "2025-02-01T09:00:00Z",
    fav: true,
  },
  {
    path: "infra/prod/redis",
    username: "default",
    password: "rd-Pr0d-2299-Kmzx!",
    url: "rediss://cache.prod.internal:6379",
    type: "db",
    notes: "",
    fields: [{ k: "Host", v: "cache.prod.internal" }],
    strength: 84,
    modified: "2026-06-27T05:50:00Z",
    created: "2025-02-01T09:05:00Z",
  },
  {
    path: "infra/staging/postgres",
    username: "trove_app",
    password: "pg-Stg-1120-qWmz",
    url: "postgres://db.staging.internal:5432",
    type: "db",
    notes: "Staging — refreshed nightly from prod snapshot.",
    fields: [{ k: "Host", v: "db.staging.internal" }, { k: "DB", v: "trove" }],
    strength: 71,
    modified: "2026-06-30T02:00:00Z",
    created: "2025-02-01T09:10:00Z",
  },
];

function buildEntries(raw, prefix) {
  return raw.map((e, i) => {
    const segs = e.path.split("/");
    const title = segs[segs.length - 1];
    const group = segs.slice(0, -1);
    return { id: prefix + "-e" + i, ...e, title, group, groupPath: group.join("/") };
  });
}

// Build a nested group tree with counts
function buildTree(entries) {
  const root = { name: "", path: "", children: {}, count: 0 };
  for (const e of entries) {
    let node = root;
    node.count++;
    let acc = [];
    for (const seg of e.group) {
      acc.push(seg);
      if (!node.children[seg]) {
        node.children[seg] = { name: seg, path: acc.join("/"), children: {}, count: 0 };
      }
      node = node.children[seg];
      node.count++;
    }
  }
  const toArr = (node) => ({
    name: node.name,
    path: node.path,
    count: node.count,
    children: Object.values(node.children).map(toArr),
  });
  return toArr(root).children;
}

const ARCHIVE_RAW = [
  { path: "legacy/wordpress/admin", username: "admin", password: "wp-2019-Old!pass", url: "https://blog.example.org/wp-admin", type: "login", notes: "Decommissioned blog. Kept for reference.", fields: [], strength: 41, modified: "2025-11-02T10:00:00Z", created: "2019-03-01T09:00:00Z" },
  { path: "legacy/ftp/deploy", username: "deploy", password: "ftp!2020-zQx8", url: "ftp://old-host.example.org", type: "login", notes: "", fields: [{ k: "Host", v: "old-host.example.org" }], strength: 38, modified: "2025-08-15T14:00:00Z", created: "2020-01-10T09:00:00Z" },
  { path: "legacy/router/admin", username: "admin", password: "admin", url: "http://192.168.0.1", type: "login", notes: "Old apartment router — returned to ISP.", fields: [], strength: 4, modified: "2025-02-01T09:00:00Z", created: "2018-06-01T09:00:00Z" },
  { path: "2025/taxes/elster", username: "you@fastmail.com", password: "Elster-2025!qWz7", url: "https://www.elster.de", type: "login", notes: "2025 filing complete.", fields: [{ k: "Steuernummer", v: "12/345/67890" }], strength: 81, modified: "2026-03-30T16:00:00Z", created: "2025-01-15T09:00:00Z", fav: true },
  { path: "2025/aws/root", username: "root@old-account", password: "aws-Root-2025-Kmz!84", url: "https://console.aws.amazon.com", type: "login", notes: "Closed account — retained for audit trail.", fields: [{ k: "Account ID", v: "3382-1190-2245" }], strength: 86, modified: "2025-12-20T11:00:00Z", created: "2025-02-01T09:00:00Z" },
];

const WORK_RAW = [
  { path: "acme/vpn/openvpn", username: "j.doe", password: "vpn-Acme-9917!Kz", url: "vpn.acme.dev", type: "cert", notes: "", fields: [{ k: "Profile", v: "acme-prod.ovpn" }], strength: 85, modified: "2026-06-20T09:00:00Z", created: "2026-01-05T09:00:00Z" },
  { path: "acme/jira/login", username: "j.doe@acme.dev", password: "jira-2026!wQz8m", url: "https://acme.atlassian.net", type: "login", notes: "", fields: [], strength: 77, modified: "2026-07-01T13:00:00Z", created: "2026-01-05T09:00:00Z" },
  { path: "acme/ci/deploy-token", username: "ci-bot", password: "glpat-XXq92mZk77Lw", url: "https://gitlab.acme.dev", type: "ssh", notes: "Rotates every 90 days.", fields: [{ k: "Scope", v: "write_repository" }], strength: 92, modified: "2026-06-15T08:00:00Z", created: "2026-04-01T09:00:00Z" },
];

const FAMILY_RAW = [
  { path: "family/wifi/router", username: "admin", password: "Fam-WLAN-2026!88", url: "http://fritz.box", type: "login", notes: "Guest network: TroveGuest / sunflower22", fields: [{ k: "SSID", v: "TroveHome" }], strength: 72, modified: "2026-05-10T09:00:00Z", created: "2025-09-01T09:00:00Z" },
  { path: "family/streaming/jellyfin", username: "family", password: "jf-Home-2026-qz", url: "https://media.home.local", type: "login", notes: "", fields: [], strength: 68, modified: "2026-04-22T09:00:00Z", created: "2025-10-01T09:00:00Z" },
  { path: "family/insurance/portal", username: "you@fastmail.com", password: "Ins-2026!Kmz90x", url: "https://portal.insurer.example", type: "login", notes: "Policy #HH-482-119.", fields: [{ k: "Policy", v: "HH-482-119" }], strength: 83, modified: "2026-02-14T09:00:00Z", created: "2025-11-01T09:00:00Z" },
];

let vaultSeq = 0;
function makeVault(name, file, raw, locked) {
  vaultSeq++;
  const id = "v" + vaultSeq;
  return { id, name, file, locked, entries: buildEntries(raw, id) };
}

const INITIAL_VAULTS = [
  makeVault("Personal Vault", "inpace.kdbx", RAW_ENTRIES, false),
  makeVault("Archive 2025", "archive-2025.kdbx", ARCHIVE_RAW, true),
];

const OPENABLE_VAULTS = [
  { name: "Work — Acme", file: "work.kdbx", raw: WORK_RAW },
  { name: "Shared Family", file: "shared-family.kdbx", raw: FAMILY_RAW },
];

Object.assign(window, { buildEntries, buildTree, makeVault, INITIAL_VAULTS, OPENABLE_VAULTS });
