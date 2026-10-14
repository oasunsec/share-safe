"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { scan, redact } = require("../scanner.js");

// Fake credentials are generated at runtime so that no complete token is
// committed to the repository, where secret scanners would flag it.
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX = "0123456789abcdef";
let seed = 1;
function rand(n, alphabet = ALNUM) {
  const next = rng(seed++);
  let s = "";
  while (s.length < n) s += alphabet[Math.floor(next() * alphabet.length)];
  // Make sure mixed alphabets really contain a digit and both cases.
  if (alphabet === ALNUM && n >= 6) s = "a7" + s.slice(2, -1) + "Q";
  return s;
}
const join = (...parts) => parts.join("");

function redacted(text, options) {
  const { findings } = scan(text, options);
  return redact(text, findings);
}

function labels(text, options) {
  return scan(text, options).findings.map((f) => f.label);
}

// ---------------------------------------------------------------------------
// Reported problems
// ---------------------------------------------------------------------------

test("labelled personal details from the bug report are redacted", () => {
  const text = "Name: Fisayo bosede\nssn: 284092\nphone number: 029420984-02";
  assert.equal(redacted(text), "Name: [NAME-1]\nssn: [SSN-1]\nphone number: [PHONE-1]");
});

test("bare sk- keys from the bug report are redacted", () => {
  const text = [
    join("sk-", "abcdef1234567890abcdef1234567890abcdef12"),
    join("sk-", "1234567890abcdef1234567890abcdef12345678"),
    join("sk-", "abcdefabcdefabcdefabcdefabcdefabcdef12")
  ].join("\n");
  assert.equal(redacted(text), "[API-KEY-1]\n[API-KEY-2]\n[API-KEY-3]");
});

test("a key name stays readable and only the value is replaced", () => {
  assert.equal(redacted("api_key = example-value-only"), "api_key = [SECRET-1]");
});

test("a single pasted value with no context is treated as a credential", () => {
  assert.equal(redacted("oerieiprw"), "[SECRET-1]");
  assert.equal(redacted("  " + rand(32) + "\n"), "  [SECRET-1]\n");
});

// ---------------------------------------------------------------------------
// Provider key formats
// ---------------------------------------------------------------------------

const providerCases = [
  ["OpenAI API key", join("sk-", "proj-", rand(64))],
  ["Anthropic API key", join("sk-", "ant-", "api03-", rand(93), "AA")],
  ["OpenRouter API key", join("sk-", "or-", "v1-", rand(64, HEX))],
  ["AWS access key ID", join("AK", "IA", rand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"))],
  ["GitHub token", join("gh", "p_", rand(36))],
  ["GitHub token", join("github", "_pat_", rand(22), "_", rand(59))],
  ["GitLab token", join("gl", "pat-", rand(20))],
  ["Google API key", join("AI", "za", rand(35))],
  ["Google OAuth client secret", join("GOC", "SPX-", rand(28))],
  ["Azure AD client secret", join(rand(3), "8Q~", rand(34))],
  ["Slack token", join("xo", "xb-", "1234567890-", rand(24))],
  ["Slack webhook URL", join("https://hooks.slack.com/services/T", rand(8), "/B", rand(8), "/", rand(24))],
  ["Discord webhook URL", join("https://discord.com/api/webhooks/123456789012345678/", rand(68))],
  ["Stripe secret key", join("sk", "_live_", rand(24))],
  ["Stripe webhook secret", join("wh", "sec_", rand(32))],
  ["Twilio API key", join("S", "K", rand(32, HEX))],
  ["SendGrid API key", join("S", "G.", rand(22), ".", rand(43))],
  ["npm token", join("np", "m_", rand(36))],
  ["Hugging Face token", join("h", "f_", rand(34))],
  ["NVIDIA API key", join("nv", "api-", rand(64))],
  ["Groq API key", join("gs", "k_", rand(52))],
  ["DigitalOcean token", join("do", "p_v1_", rand(64, HEX))],
  ["Shopify token", join("shp", "at_", rand(32, HEX))],
  ["Databricks token", join("da", "pi", rand(32, HEX))],
  ["Linear API key", join("lin", "_api_", rand(40))],
  ["Postman API key", join("PM", "AK-", rand(24, HEX), "-", rand(34, HEX))],
  ["HashiCorp Vault token", join("hv", "s.", rand(90))],
  ["Docker Hub token", join("dckr", "_pat_", rand(27))],
  ["age secret key", join("AGE-", "SECRET-KEY-1", rand(58, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))],
  ["JSON Web Token", join("ey", "JhbGciOiJIUzI1NiJ9.", "ey", "J", rand(40), ".", rand(43))]
];

for (const [label, token] of providerCases) {
  test(`detects ${label} on its own and inside text`, () => {
    const inText = `deploy step failed, used ${token} for auth`;
    const found = scan(inText).findings;
    assert.equal(found.length, 1, `expected one finding in: ${inText}`);
    assert.equal(found[0].label, label);
    assert.equal(found[0].value, token);
  });
}

test("detects a private key block, including a truncated paste", () => {
  const body = rand(64) + "\n" + rand(64);
  const pem = (edge, kind) => join("-----", edge, " ", kind, " PRIVATE", " KEY-----");
  const full = `before\n${pem("BEGIN", "OPENSSH")}\n${body}\n${pem("END", "OPENSSH")}\nafter`;
  assert.equal(redacted(full), "before\n[PRIVATE-KEY-1]\nafter");
  const cut = `log line\n${pem("BEGIN", "RSA")}\n${body}`;
  assert.equal(redacted(cut), "log line\n[PRIVATE-KEY-1]");
});

// ---------------------------------------------------------------------------
// Keys with no known prefix
// ---------------------------------------------------------------------------

test("detects random-looking keys with no prefix inside text", () => {
  for (const n of [16, 24, 32, 40, 64]) {
    const key = rand(n);
    const text = `the service rejected ${key} again`;
    assert.equal(redacted(text), "the service rejected [SECRET-1] again", `length ${n}`);
  }
});

test("detects base64-style secrets such as AWS secret keys", () => {
  const key = rand(16) + "/" + rand(12) + "+" + rand(10);
  assert.match(redacted(`aws configure set something ${key}`), /\[SECRET-1\]$/);
});

test("detects a 32-character hex key but marks known hashes as low confidence", () => {
  const key = rand(32, HEX);
  assert.equal(scan(`apikey ${key}`).findings[0].confidence !== "low", true);
  const hash = scan(`sha256: ${rand(64, HEX)}`).findings[0];
  assert.equal(hash.confidence, "low");
});

// ---------------------------------------------------------------------------
// Secrets assigned to names, in many syntaxes
// ---------------------------------------------------------------------------

test("redacts values in env, JSON, YAML, XML, flags and PowerShell", () => {
  const cases = [
    ["OPENAI_API_KEY=abc123def", "OPENAI_API_KEY=[SECRET-1]"],
    ['{"clientSecret": "s3cr3t-value"}', '{"clientSecret": "[SECRET-1]"}'],
    ["password: hunter2", "password: [PASSWORD-1]"],
    ["db_pass=Tr0ub4dor&3x", "db_pass=[PASSWORD-1]"],
    ["<Password>P@ssw0rd!</Password>", "<Password>[PASSWORD-1]</Password>"],
    ["mysql --password=Sup3r!pass -h db", "mysql --password=[PASSWORD-1] -h db"],
    ['$env:GITHUB_TOKEN = "abcdef123456"', '$env:GITHUB_TOKEN = "[TOKEN-1]"'],
    ["export AWS_SECRET_ACCESS_KEY='abc/def+ghi123'", "export AWS_SECRET_ACCESS_KEY='[SECRET-1]'"],
    ["Server=sql01;Database=app;User Id=svc;Password=Winter2026!;", "Server=sql01;Database=app;User Id=svc;Password=[PASSWORD-1];"],
    ["spring.datasource.password=changeme123", "spring.datasource.password=[PASSWORD-1]"],
    ["X-Api-Key: 9f8e7d6c5b4a", "X-Api-Key: [SECRET-1]"],
    ["id_token=abc.def.ghi123", "id_token=[TOKEN-1]"]
  ];
  for (const [input, expected] of cases) assert.equal(redacted(input), expected, input);
});

test("redacts secrets written in sentences", () => {
  const cases = [
    ["my password is hunter22", "my password is [PASSWORD-1]"],
    ["The API key: abc123xyz", "The API key: [SECRET-1]"],
    ["here is the token 9f8Kx2mQ7pL4", "here is the token [TOKEN-1]"],
    ["use secret Zx81-pq0!", "use secret [SECRET-1]"],
    ["Your verification code is 482913.", "Your verification code is [PIN-1]."],
    ["the wifi password for guests is SunnyDays", "the wifi password for guests is [PASSWORD-1]"]
  ];
  for (const [input, expected] of cases) assert.equal(redacted(input), expected, input);
});

test("leaves ordinary sentences about passwords alone", () => {
  const text = [
    "The token expired after an hour.",
    "Reset your password from the account page.",
    "The secret is stored in Key Vault.",
    "Rotate the key before Friday.",
    "Exit code 1 means the token was invalid.",
    "password reset link sent",
    "max_tokens: 1500",
    "token_type: bearer",
    "secret_name: my-secret",
    "password_policy: strict"
  ].join("\n");
  assert.deepEqual(labels(text), []);
});

test("skips placeholders and variable references", () => {
  const text = [
    "API_KEY=${API_KEY}",
    "password: <your-password>",
    "token = os.environ['TOKEN']",
    "secret: null",
    "password = settings.DB_PASSWORD",
    "client_secret: '********'",
    "TOKEN=%TOKEN%",
    "api_key: your_api_key_here"
  ].join("\n");
  assert.deepEqual(labels(text), []);
});

// ---------------------------------------------------------------------------
// URLs, headers and cookies
// ---------------------------------------------------------------------------

test("redacts passwords in URLs, auth headers, curl and cookies", () => {
  const token = rand(40);
  const text = [
    "postgres://admin:S3cretPass@db.example.com:5432/app",
    `Authorization: Bearer ${token}`,
    "curl -u alice:pa55word https://api.example.com",
    `Cookie: session=${rand(26)}; theme=dark`
  ].join("\n");
  assert.equal(redacted(text), [
    "postgres://admin:[PASSWORD-1]@db.example.com:5432/app",
    "Authorization: Bearer [TOKEN-1]",
    "curl -u alice:[PASSWORD-2] https://api.example.com",
    "Cookie: session=[SESSION-1]; theme=dark"
  ].join("\n"));
});

test("redacts Azure SAS signatures and storage account keys", () => {
  const sas = `https://acct01.blob.core.windows.net/c/f.txt?sv=2022-11-02&se=2026-01-01&sig=${rand(43)}%3D`;
  const out = redacted(sas);
  assert.match(out, /sig=\[SECRET-1\]/);
  assert.match(out, /^https:\/\/\[RESOURCE-1\]\.blob\.core\.windows\.net/);
  const conn = `DefaultEndpointsProtocol=https;AccountName=acct01;AccountKey=${rand(86)}==;EndpointSuffix=core.windows.net`;
  assert.match(redacted(conn), /AccountKey=\[SECRET-1\];/);
});

test("finds a secret hidden in base64", () => {
  const inner = join("password=", "Winter2026!");
  const encoded = Buffer.from(inner).toString("base64");
  const found = scan(`data: ${encoded}`).findings;
  assert.equal(found.length, 1);
  assert.match(found[0].label, /^Base64-encoded/);
});

// ---------------------------------------------------------------------------
// Personal data
// ---------------------------------------------------------------------------

test("redacts labelled personal fields", () => {
  const cases = [
    ["Full Name: Ada Lovelace", "Full Name: [NAME-1]"],
    ["DOB: 02/01/1990", "DOB: [DOB-1]"],
    ["Date of birth - 1 Jan 1990", "Date of birth - [DOB-1]"],
    ["Passport No: A12345678", "Passport No: [PASSPORT-1]"],
    ["BVN: 22212345678", "BVN: [NATIONAL-ID-1]"],
    ["Home address: 12 Allen Avenue, Ikeja, Lagos", "Home address: [ADDRESS-1]"],
    ["Mobile: +234 803 123 4567", "Mobile: [PHONE-1]"],
    ['{"phone": "029420984-02", "ssn": "284-09-1234"}', '{"phone": "[PHONE-1]", "ssn": "[SSN-1]"}'],
    ["Account Number: 0123456789", "Account Number: [ACCOUNT-1]"],
    ["CVV: 123", "CVV: [PIN-1]"]
  ];
  for (const [input, expected] of cases) assert.equal(redacted(input), expected, input);
});

test("a name found once is redacted everywhere else", () => {
  const text = "Name: Fisayo Bosede\nTicket opened by Fisayo about Bosede's account.";
  const out = redacted(text);
  assert.ok(!/Fisayo|Bosede/.test(out), out);
});

test("redacts emails, card numbers, IBANs and unlabelled SSNs and phones", () => {
  const text = "mail ada@example.org, card 4111 1111 1111 1111, IBAN GB82 WEST 1234 5698 7654 32, SSN 123-45-6789, call (555) 123-4567 or 08031234567";
  assert.equal(
    redacted(text),
    "mail [EMAIL-1], card [CARD-1], IBAN [IBAN-1], SSN [SSN-1], call [PHONE-1] or [PHONE-2]"
  );
});

test("rejects card numbers and IBANs that fail their checksums", () => {
  assert.deepEqual(labels("order 4111 1111 1111 1112 and GB82 WEST 1234 5698 7654 33"), []);
});

test("redacts the username in paths and wherever else it appears", () => {
  const text = "C:\\Users\\jdoe\\Downloads\\logs\nopened by jdoe\nssh jdoe@WORKSTATION01:~$ ls /home/jdoe/src";
  assert.equal(redacted(text), "C:\\Users\\[USER-1]\\Downloads\\logs\nopened by [USER-1]\nssh [USER-1]@[HOST-1]:~$ ls /home/[USER-1]/src");
});

test("redacts Windows event XML user and computer fields", () => {
  const text = '<Computer>DESKTOP-7QK2M9P</Computer><Data Name="TargetUserName">jsmith</Data>';
  assert.equal(redacted(text), '<Computer>[HOST-1]</Computer><Data Name="TargetUserName">[USER-1]</Data>');
});

test("redacts IPs, internal hosts and MAC addresses but not documentation ranges", () => {
  const text = "from 10.20.4.17 and 52.168.4.17 via fileserver.corp.local, mac 00:1A:2B:3C:4D:5E, example 192.0.2.10, loopback 127.0.0.1";
  assert.equal(
    redacted(text),
    "from [INTERNAL-IP-1] and [IP-1] via [HOST-1], mac [MAC-1], example 192.0.2.10, loopback 127.0.0.1"
  );
});

test("Azure tenant IDs are redacted; other GUIDs are flagged but kept by default", () => {
  const guid = "3f2a9c1e-4b7d-4e2a-9c1e-4b7d4e2a9c1e";
  assert.equal(redacted(`tenantId: ${guid}`), "tenantId: [TENANT-ID-1]");
  const other = scan(`correlation ${guid}`).findings;
  assert.equal(other.length, 1);
  assert.equal(other[0].confidence, "low");
  assert.equal(redacted(`correlation ${guid}`), `correlation ${guid}`);
});

// ---------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------

test("the same value always gets the same placeholder", () => {
  const text = "a@example.org wrote to b@example.org, then a@example.org replied";
  assert.equal(redacted(text), "[EMAIL-1] wrote to [EMAIL-2], then [EMAIL-1] replied");
});

test("custom terms are always redacted and allow terms are never flagged", () => {
  const text = "Project Falcon at Contoso, contact ada@example.org";
  assert.equal(
    redacted(text, { customTerms: ["Falcon", "Contoso"], allowTerms: ["ada@example.org"] }),
    "Project [REDACTED-1] at [REDACTED-2], contact ada@example.org"
  );
});

test("redact() honours per-finding choices", () => {
  const text = "a@example.org and 10.0.0.5";
  const { findings } = scan(text);
  const out = redact(text, findings, (f) => f.tag !== "INTERNAL-IP");
  assert.equal(out, "[EMAIL-1] and 10.0.0.5");
});

// ---------------------------------------------------------------------------
// Things that must not be flagged
// ---------------------------------------------------------------------------

test("ordinary logs, code and config produce no findings", () => {
  const text = [
    "2025-02-03T14:26:57.123Z INFO build started version 1.2.3.4 at 12:30:45",
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\devenv.exe",
    "DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx",
    "Microsoft-Windows-Sysmon/Operational EventID 4624 LogonType 10",
    "https://github.com/oasunsec/triage-engine/actions/runs/34173877877",
    "name: build",
    "  - name: Run Tests",
    "    uses: actions/checkout@v4",
    "image: mcr.microsoft.com/dotnet/aspnet:8.0-jammy-amd64",
    "\"integrity\": \"sha512-" + rand(86) + "==\"",
    "def getUserProfileById(user_id): return session.query(UserProfile).get(user_id)",
    "Traceback (most recent call last): File \"app.py\", line 42, in handle_request2024",
    "SELECT id, created_at FROM orders WHERE status = 'pending' LIMIT 100;",
    "git@github.com:oasunsec/share-safe.git",
    "npm WARN deprecated inflight@1.0.6: This module is not supported",
    "The quick brown fox jumps over the lazy dog 1234 times.",
    "Total: $1,234.56 for 3 items, order #A-1029",
    "logo@2x.png icon@3x.webp",
    "kubernetes.io/service-account-token",
    "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto;",
    "Error: ECONNREFUSED connect ECONNREFUSED 127.0.0.1:5432",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "token_count=512 prompt_tokens=88 completion_tokens=424",
    // Security writing and source code that mention secrets without containing any
    "Credential Access -> OS Credential Dumping",
    "Privilege Escalation -> Access Token Manipulation",
    "\"title\": \"Reversible Password Encryption Enabled\",",
    "and assume local secrets were exposed.",
    "| `ActiveCanary` | Whether the token was active when received. |",
    "raise HTTPException(401, \"Current password is incorrect\")",
    "    \"user\": a.user,",
    "    user=hidden_user,",
    "    \"user\": registry_finding.user or related_run_key.user,",
    "    password: str",
    "    user: PublicUserResponse",
    "has_password_extraction = \"getnetworkcredential().password\" in low",
    "REMOTE_CREDENTIAL_CONTEXT_FINDINGS = REMOTE_CREDENTIAL_FINDINGS | {",
    "user_key = username or \"__unknown__\"",
    "\"csrf_token\": csrf_token,",
    "fetch(url, { credentials: \"same-origin\" })",
    "body: JSON.stringify({ password: currentPassword })",
    "./repo_cache/EVTX-ATTACK-SAMPLES/Defense Evasion/DE_WinEventLogSvc_Crash_System_7036.evtx",
    "./repo_cache/EVTX-ATTACK-SAMPLES/Credential Access/CA_DCSync_4662.evtx",
    "{\"name\": \"Credit Card Number\", \"minCount\": 1}",
    "{\"name\": \"Default Office Policy\"}"
  ].join("\n");
  const found = scan(text).findings.filter((f) => f.confidence !== "low");
  assert.deepEqual(found.map((f) => `${f.label}: ${f.value}`), []);
});
