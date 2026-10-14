/*
 * ShareSafe scanner.
 *
 * Finds secrets and personal data in text and builds a redacted copy.
 * Pure functions only: no DOM access and no network calls. The same file runs
 * in the browser (window.ShareSafe) and in Node (require) for the tests.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.ShareSafe = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // Token boundaries: a key must not be glued to more key-like characters.
  const B = String.raw`(?<![A-Za-z0-9_\-])`;
  const E = String.raw`(?![A-Za-z0-9_\-])`;

  const hasDigit = (s) => /\d/.test(s);
  const hasLetter = (s) => /[A-Za-z]/.test(s);

  // ---------------------------------------------------------------------------
  // Provider key formats. [id, label, placeholder tag, pattern, extra check]
  // Listed most specific first: when two patterns cover the same text, the
  // earlier one names it.
  // ---------------------------------------------------------------------------
  const PROVIDERS = [
    ["anthropic-key", "Anthropic API key", "ANTHROPIC-KEY", String.raw`sk-ant-(?:api|admin|sid)\d{2}-[A-Za-z0-9_\-]{20,}`],
    ["openrouter-key", "OpenRouter API key", "OPENROUTER-KEY", String.raw`sk-or-v1-[A-Za-z0-9]{32,}`],
    ["openai-key", "OpenAI API key", "OPENAI-KEY", String.raw`sk-(?:proj|svcacct|admin|None)-[A-Za-z0-9_\-]{20,}`],
    ["sk-key", "Secret key (sk- format, OpenAI and similar)", "API-KEY", String.raw`sk-[A-Za-z0-9_\-]{20,}`, (v) => hasDigit(v.slice(3))],
    ["aws-access-key", "AWS access key ID", "AWS-KEY", String.raw`(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA)[A-Z0-9]{16}`],
    ["github-token", "GitHub token", "GITHUB-TOKEN", String.raw`gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{22,255}`],
    ["gitlab-token", "GitLab token", "GITLAB-TOKEN", String.raw`gl(?:pat|ptt|dt|rt|cbt|imt|oas|ffct|soat|agent)-[A-Za-z0-9_\-]{20,}`],
    ["google-api-key", "Google API key", "GOOGLE-KEY", String.raw`AIza[0-9A-Za-z_\-]{35}`],
    ["google-oauth-secret", "Google OAuth client secret", "GOOGLE-SECRET", String.raw`GOCSPX-[A-Za-z0-9_\-]{28}`],
    ["google-oauth-token", "Google OAuth access token", "GOOGLE-TOKEN", String.raw`ya29\.[0-9A-Za-z_\-]{20,}`],
    ["azure-client-secret", "Azure AD client secret", "AZURE-SECRET", String.raw`[A-Za-z0-9_~.\-]{3}\dQ~[A-Za-z0-9_~.\-]{31,34}`],
    ["azure-devops-pat", "Azure DevOps token", "AZURE-DEVOPS-TOKEN", String.raw`[A-Za-z0-9]{52}AZDO[A-Za-z0-9]{4}`],
    ["slack-token", "Slack token", "SLACK-TOKEN", String.raw`xox[abposre]-[A-Za-z0-9\-]{10,}`],
    ["slack-webhook", "Slack webhook URL", "SLACK-WEBHOOK", String.raw`https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_\-]{20,}`],
    ["discord-webhook", "Discord webhook URL", "DISCORD-WEBHOOK", String.raw`https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{20,}`],
    ["teams-webhook", "Microsoft Teams webhook URL", "TEAMS-WEBHOOK", String.raw`https://[A-Za-z0-9\-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9@/_\-]{20,}`],
    ["discord-token", "Discord bot token", "DISCORD-TOKEN", String.raw`[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}`],
    ["telegram-token", "Telegram bot token", "TELEGRAM-TOKEN", String.raw`\d{8,10}:AA[A-Za-z0-9_\-]{33}`],
    ["stripe-key", "Stripe secret key", "STRIPE-KEY", String.raw`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`],
    ["stripe-webhook", "Stripe webhook secret", "STRIPE-SECRET", String.raw`whsec_[A-Za-z0-9]{24,}`],
    ["twilio-key", "Twilio API key", "TWILIO-KEY", String.raw`SK[0-9a-f]{32}`],
    ["sendgrid-key", "SendGrid API key", "SENDGRID-KEY", String.raw`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`],
    ["mailgun-key", "Mailgun API key", "MAILGUN-KEY", String.raw`key-[0-9a-f]{32}`],
    ["mailchimp-key", "Mailchimp API key", "MAILCHIMP-KEY", String.raw`[0-9a-f]{32}-us\d{1,2}`],
    ["npm-token", "npm token", "NPM-TOKEN", String.raw`npm_[A-Za-z0-9]{36}`],
    ["pypi-token", "PyPI token", "PYPI-TOKEN", String.raw`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}`],
    ["huggingface-token", "Hugging Face token", "HF-TOKEN", String.raw`hf_[A-Za-z0-9]{30,}`],
    ["nvidia-key", "NVIDIA API key", "NVIDIA-KEY", String.raw`nvapi-[A-Za-z0-9_\-]{40,}`],
    ["groq-key", "Groq API key", "GROQ-KEY", String.raw`gsk_[A-Za-z0-9]{40,}`],
    ["xai-key", "xAI API key", "XAI-KEY", String.raw`xai-[A-Za-z0-9]{60,}`],
    ["replicate-token", "Replicate token", "REPLICATE-TOKEN", String.raw`r8_[A-Za-z0-9]{37}`],
    ["perplexity-key", "Perplexity API key", "PERPLEXITY-KEY", String.raw`pplx-[A-Za-z0-9]{40,}`],
    ["digitalocean-token", "DigitalOcean token", "DO-TOKEN", String.raw`do[opr]_v1_[a-f0-9]{64}`],
    ["shopify-token", "Shopify token", "SHOPIFY-TOKEN", String.raw`shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}`],
    ["databricks-token", "Databricks token", "DATABRICKS-TOKEN", String.raw`dapi[a-f0-9]{32}(?:-\d)?`],
    ["atlassian-token", "Atlassian API token", "ATLASSIAN-TOKEN", String.raw`ATATT3[A-Za-z0-9_\-=]{50,}`],
    ["linear-key", "Linear API key", "LINEAR-KEY", String.raw`lin_api_[A-Za-z0-9]{40}`],
    ["notion-token", "Notion token", "NOTION-TOKEN", String.raw`secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,}`],
    ["postman-key", "Postman API key", "POSTMAN-KEY", String.raw`PMAK-[a-f0-9]{24}-[a-f0-9]{34}`],
    ["doppler-token", "Doppler token", "DOPPLER-TOKEN", String.raw`dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}`],
    ["vault-token", "HashiCorp Vault token", "VAULT-TOKEN", String.raw`hv[sbr]\.[A-Za-z0-9_\-]{24,}`],
    ["terraform-token", "Terraform Cloud token", "TFC-TOKEN", String.raw`[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=\-]{60,}`],
    ["docker-token", "Docker Hub token", "DOCKER-TOKEN", String.raw`dckr_pat_[A-Za-z0-9_\-]{27,}`],
    ["supabase-token", "Supabase token", "SUPABASE-TOKEN", String.raw`sbp_[a-f0-9]{40}`],
    ["grafana-token", "Grafana token", "GRAFANA-TOKEN", String.raw`glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}|glc_[A-Za-z0-9+/]{32,}={0,2}`],
    ["netlify-token", "Netlify token", "NETLIFY-TOKEN", String.raw`nfp_[A-Za-z0-9]{36}`],
    ["fly-token", "Fly.io token", "FLY-TOKEN", String.raw`fo1_[A-Za-z0-9_\-]{43}`],
    ["pulumi-token", "Pulumi token", "PULUMI-TOKEN", String.raw`pul-[a-f0-9]{40}`],
    ["square-token", "Square token", "SQUARE-TOKEN", String.raw`sq0(?:atp|csp)-[A-Za-z0-9_\-]{22,43}`],
    ["age-key", "age secret key", "AGE-KEY", String.raw`AGE-SECRET-KEY-1[0-9A-Z]{58}`],
    ["fcm-key", "Firebase Cloud Messaging key", "FCM-KEY", String.raw`AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}`],
    ["heroku-key", "Heroku API key", "HEROKU-KEY", String.raw`HRKU-[A-Za-z0-9_\-]{60}`],
    ["jwt", "JSON Web Token", "JWT", String.raw`eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*`]
  ];

  // ---------------------------------------------------------------------------
  // Key names that hold secrets (api_key, DB_PASSWORD, clientSecret, ...)
  // ---------------------------------------------------------------------------
  const SECRET_WORDS = new Set([
    "password", "passwd", "passphrase", "pwd", "secret", "secrets", "token", "apikey", "apitoken",
    "accesstoken", "authtoken", "refreshtoken", "idtoken", "privatekey", "secretkey", "accesskey",
    "accountkey", "sharedaccesskey", "masterkey", "clientsecret", "credential", "credentials", "creds",
    "cred", "sas", "signature", "cookie", "sessionid", "jsessionid", "phpsessid", "sessiontoken",
    "connectionstring", "connstr", "connstring", "dsn", "authorization", "bearer", "otp", "totp",
    "cvv", "cvc", "hmac", "webhooksecret", "encryptionkey", "signingkey"
  ]);
  // Only count as secret words when they end the name ("db_pass", not "pass_through").
  const SECRET_LAST_ONLY = new Set(["pass", "auth", "pat", "pin", "sig"]);
  function lastWordCounts(word, wordCount) {
    if (word === "sig") return wordCount === 1; // Azure SAS "sig=" query parameter
    if (word === "auth" || word === "pin") return wordCount <= 2;
    return true;
  }
  const KEY_FIRST = new Set([
    "api", "access", "secret", "private", "account", "shared", "signing", "encryption", "decryption",
    "master", "auth", "license", "subscription", "storage", "primary", "secondary", "deploy", "app",
    "consumer", "instrumentation", "service", "admin", "query", "function", "client", "session",
    "refresh", "id", "bearer", "personal", "webhook", "sas", "jwt", "hmac", "oauth", "bot", "user"
  ]);
  const KEY_SECOND = new Set(["key", "keys", "token", "tokens", "secret"]);
  const QUANTITY_WORDS = new Set([
    "max", "min", "count", "total", "prompt", "completion", "completions", "usage", "limit", "length",
    "len", "size", "per", "rate", "budget", "cached", "reasoning", "input", "output", "num"
  ]);
  const ALLOWED_AFTER = new Set([
    "value", "val", "b64", "base64", "raw", "plain", "plaintext", "text", "enc", "encrypted", "hash",
    "hashed", "hex", "str", "data", "secret", "key", "base", "old", "new", "current", "prev", "previous",
    "next", "primary", "secondary", "main", "default", "admin", "root", "user", "prod", "production",
    "dev", "development", "test", "staging", "stage", "local", "live", "sandbox", "v", "b", "alt",
    "backup", "override", "real", "actual", "confirm", "confirmation", "again", "repeat", "string"
  ]);
  const BOOL_PREFIX = new Set([
    "has", "is", "should", "enable", "enabled", "use", "allow", "require", "requires", "needs", "show",
    "can", "did", "was", "check", "validate", "verify", "hide", "mask", "no", "skip", "with", "without",
    "get", "set", "fetch", "load", "read", "parse", "generate", "rotate", "reset", "on", "handle"
  ]);

  function splitWords(name) {
    return name
      .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
      .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean);
  }

  const KEY_KINDS = {
    password: ["PASSWORD", "Password"],
    pin: ["PIN", "PIN or one-time code"],
    session: ["SESSION", "Session or cookie value"],
    token: ["TOKEN", "Token"],
    connection: ["CONNECTION", "Connection string"],
    secret: ["SECRET", "Secret value"]
  };

  function kindOf(word) {
    if (/^(?:password|passwd|passphrase|pwd|pass)$/.test(word)) return "password";
    if (/^(?:pin|otp|totp|cvv|cvc)$/.test(word)) return "pin";
    if (/(?:cookie|session)/.test(word)) return "session";
    if (/(?:token|bearer|auth|pat)/.test(word)) return "token";
    if (/^(?:connectionstring|connstr|connstring|dsn|string)$/.test(word)) return "connection";
    return "secret";
  }

  // Returns { tag, label, kind } when the key name holds a secret, else null.
  function classifyKey(name) {
    const words = splitWords(name);
    if (!words.length || words.length > 8) return null;
    const joined = words.join("");
    let pos = -1;
    let kind = null;
    if (SECRET_WORDS.has(joined)) {
      pos = words.length - 1;
      kind = kindOf(joined);
    }
    for (let i = 0; i < words.length; i++) {
      const w = words[i];
      const next = words[i + 1];
      if (next !== undefined && KEY_FIRST.has(w) && KEY_SECOND.has(next)) {
        pos = i + 1;
        kind = kindOf(next === "key" || next === "keys" ? "secret" : next);
        if (w === "session") kind = "session";
        i += 1;
      } else if (next === "id" && w === "session") {
        pos = i + 1;
        kind = "session";
        i += 1;
      } else if (w === "connection" && next === "string") {
        pos = i + 1;
        kind = "connection";
        i += 1;
      } else if (SECRET_WORDS.has(w)) {
        pos = i;
        kind = kindOf(w);
      } else if (SECRET_LAST_ONLY.has(w) && i === words.length - 1 && lastWordCounts(w, words.length)) {
        pos = i;
        kind = kindOf(w);
      }
    }
    if (pos < 0) return null;
    if (BOOL_PREFIX.has(words[0]) && words.length > 1) return null; // has_password, is_secret_set
    if (words.some((w) => QUANTITY_WORDS.has(w))) return null;
    // After the secret word only qualifiers may follow (DB_PASSWORD_PROD, client_secret_value).
    // Anything else names something about the secret (token_type, api_key_header, CREDENTIAL_FINDINGS).
    if (words.slice(pos + 1).some((w) => !ALLOWED_AFTER.has(w) && !/^\d+$/.test(w))) return null;
    const [tag, label] = KEY_KINDS[kind];
    return { tag, label, kind };
  }

  // Values that are clearly not a real secret: placeholders, variables, booleans.
  const PLACEHOLDER_WORDS = /^(?:null|nil|none|undefined|true|false|yes|no|on|off|redacted|removed|hidden|masked|example|sample|placeholder|dummy|string|required|optional|todo|tbd|tba|n\/a|na|unknown|empty|secret|password|token|changeit|value|default|test|same-origin|include|omit|same-site|cross-site)$/i;

  // Words that follow "password", "token" and friends in ordinary sentences.
  const PROSE_WORDS = new Set([
    "is", "was", "are", "were", "be", "been", "the", "a", "an", "and", "or", "to", "for", "from", "with", "without",
    "that", "this", "these", "those", "has", "have", "had", "will", "would", "should", "must", "can", "could", "may",
    "expired", "expires", "rotated", "revoked", "reset", "changed", "updated", "stored", "saved", "missing", "invalid",
    "valid", "required", "needed", "here", "there", "below", "above", "field", "fields", "manager", "managers",
    "policy", "policies", "length", "strength", "hash", "hashes", "file", "files", "store", "vault", "rotation",
    "authentication", "authorization", "header", "headers", "format", "value", "values", "type", "types",
    "used", "using", "into", "onto", "when", "while", "after", "before", "because", "which", "what", "where",
    "should", "please", "not", "never", "always", "again", "also", "only", "just", "then", "than", "them",
    "they", "their", "your", "yours", "our", "ours", "my", "mine", "his", "her", "its", "it", "you", "we",
    "request", "requests", "response", "responses", "endpoint", "server", "client", "flow", "exchange",
    "refresh", "generation", "generator", "limit", "limits", "count", "usage", "budget", "window", "size",
    "provided", "supplied", "accepted", "rejected", "denied", "failed", "failure", "error", "errors", "check",
    "checks", "validation", "verification", "prompt", "prompts", "dialog", "screen", "page", "form", "input",
    "itself", "issued", "issuer", "lifetime", "scope", "scopes", "permissions", "access", "secret", "secrets",
    "token", "tokens", "password", "passwords", "key", "keys", "pair", "pairs", "id", "ids", "name", "names",
    "incorrect", "correct", "wrong", "weak", "strong", "blank", "short", "long", "set", "unset", "ok", "okay",
    "different", "same", "exposed", "leaked", "compromised", "written", "harvested", "stolen", "dumped",
    "encrypted", "hashed", "cached", "shared", "sent", "logged", "printed", "displayed", "masked", "redacted",
    "created", "deleted", "removed", "loaded", "read", "found", "reused", "known", "unknown", "available",
    "unavailable", "enabled", "disabled", "configured", "managed", "protected", "secured", "visible", "hidden",
    "being", "still", "usually", "often", "typically", "currently", "now", "already", "required.", "case-sensitive",
    "mismatch", "mismatched", "accepted.", "too", "very", "quite", "good", "bad", "fine", "unique", "random",
    "generated", "issued", "granted", "attached", "included", "embedded", "hardcoded", "plaintext", "visible",
    "checked", "verified", "validated", "rejected", "ignored", "returned", "received", "copied", "pasted",
    "entered", "typed", "submitted", "sent.", "rotating", "expiring", "expiry", "never", "optional", "mandatory",
    "manipulation", "dumping", "theft", "access", "storage", "modified", "memory", "prompting", "spraying",
    "stuffing", "guessing", "cracking", "replay", "relay", "impersonation", "forgery", "injection", "abuse",
    "active", "inactive", "live", "dead", "current", "latest", "old", "present", "absent", "fresh", "stale",
    "sensitive", "confidential", "private", "public", "personal", "temporary", "permanent", "local", "remote"
  ]);
  const TYPE_WORDS = new Set([
    "str", "string", "int", "integer", "bool", "boolean", "number", "float", "double", "any", "object", "dict",
    "list", "bytes", "none", "optional", "uuid", "secretstr", "char", "varchar", "text", "self", "this", "void",
    "null", "undefined", "unknown", "never", "date", "datetime", "timestamp", "json", "array", "map", "record"
  ]);

  // Code that reads a secret rather than containing one: getPassword(),
  // os.environ["TOKEN"], settings.DB_PASSWORD.
  function looksLikeCode(v) {
    if (/[(\[]/.test(v) || TYPE_WORDS.has(v.toLowerCase())) return true;
    if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) return true; // OTHER_CONSTANT
    if (/^[a-z]+(?:[A-Z][a-z]+)+$/.test(v)) return true; // currentPassword (a variable)
    if (/^\{|^same-origin$|^include$|^omit$/.test(v)) return true; // {template}, fetch credentials modes
    return /^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$/.test(v) && !/\d/.test(v);
  }

  // True when an expression continues after the value: `x or "default"`, `x if y else z`.
  function followedByCode(text, end) {
    return /^[ \t]+(?:or|and|if|else|\+|\|\||&&|\?\?|\?)[ \t]/.test(text.slice(end, end + 8));
  }

  // Values in source code rather than in data: a.user, lead.address ?? "", str = "".
  function codeish(v) {
    return looksLikeCode(v) || /[(){}\[\];=`<>]|=>|\?\?|&&|\|\||\?\.|::/.test(v);
  }

  function isPlaceholder(value) {
    const v = value.trim();
    if (v.length < 2) return true;
    if (PLACEHOLDER_WORDS.test(v)) return true;
    if (/^(.)\1+$/.test(v)) return true; // xxxx, ****, ....
    if (/^[•●*xX.\-_ ]+$/.test(v)) return true;
    if (/^<[^<>]*>$/.test(v) || /^\[[^\[\]]*\]$/.test(v)) return true;
    if (/^\{\{.*\}\}$/.test(v) || /^\$\{[^}]*\}$/.test(v) || /^\$\(.*\)$/.test(v)) return true;
    if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(v) || /^%[A-Za-z_][A-Za-z0-9_]*%$/.test(v)) return true;
    if (/^\$env:[A-Za-z_][A-Za-z0-9_]*$/i.test(v)) return true; // PowerShell variable
    if (/^(?:your|my|insert|enter|replace|put|add|use|set|change)[-_ ]/i.test(v)) return true;
    return false;
  }

  // ---------------------------------------------------------------------------
  // Labelled personal fields ("Name: ...", "ssn: ...", "phone number: ...")
  // ---------------------------------------------------------------------------
  const S = String.raw`[ _\-]?`;
  const NO = String.raw`(?:${S}(?:number|no\.?|num|#))?`;
  const FIELD_DEFS = [
    {
      tag: "NAME", label: "Person's name", category: "personal", kind: "name", confidence: "high",
      keys: [`full${S}name`, `first${S}name`, `last${S}name`, `middle${S}name`, `sur${S}name`, `given${S}name`,
        `family${S}name`, `legal${S}name`, `maiden${S}name`, `mother'?s${S}maiden${S}name`, `customer${S}name`,
        `client${S}name`, `patient${S}name`, `employee${S}name`, `contact${S}name`, `account${S}holder(?:${S}name)?`,
        `card${S}holder(?:${S}name)?`, `beneficiary(?:${S}name)?`, `next${S}of${S}kin`, `spouse(?:${S}name)?`,
        `father'?s${S}name`, `mother'?s${S}name`, `recipient${S}name`, `sender${S}name`, `applicant${S}name`,
        `guardian(?:${S}name)?`, `emergency${S}contact(?:${S}name)?`]
    },
    { tag: "NAME", label: "Person's name", category: "personal", kind: "bare-name", confidence: "medium", keys: ["name"] },
    {
      tag: "SSN", label: "Social Security number", category: "personal", kind: "id", confidence: "high",
      keys: ["ssn", `social${S}security${NO}`]
    },
    {
      tag: "NATIONAL-ID", label: "National ID number", category: "personal", kind: "id", confidence: "high",
      keys: [`national${S}id(?:entity)?(?:${S}card)?${NO}`, "nin", "nino", `national${S}insurance${NO}`, "sin",
        `social${S}insurance${NO}`, "bvn", `aadhaar${NO}`, `id${S}card${NO}`, `id${S}(?:number|no\\.?|num|#)`,
        `identity${S}(?:card|number|no)`, `voter'?s?${S}(?:id|card)${NO}`, `resident${S}(?:id|permit)${NO}`]
    },
    {
      tag: "TAX-ID", label: "Tax ID", category: "personal", kind: "id", confidence: "high",
      keys: [`tax${S}(?:id|identification)${NO}`, `tax${S}(?:number|no)`, "tin", "itin", "ein", "utr", `vat${S}(?:id|number|no)`]
    },
    { tag: "PASSPORT", label: "Passport number", category: "personal", kind: "id", confidence: "high", keys: [`passport${NO}`] },
    {
      tag: "LICENSE", label: "Driver's license number", category: "personal", kind: "id", confidence: "high",
      keys: [`driver'?s?${S}licen[cs]e${NO}`, `driving${S}licen[cs]e${NO}`, `dl${S}(?:number|no|#)`]
    },
    {
      tag: "MEDICAL-ID", label: "Medical or insurance ID", category: "personal", kind: "id", confidence: "high",
      keys: ["mrn", `medical${S}record${NO}`, `patient${S}(?:id|number|no)`, `nhs${NO}`, `medicare${S}(?:id|number|no)`,
        `medicaid${S}(?:id|number|no)`, `health${S}(?:id|card|insurance)${NO}`, `insurance${S}(?:id|number|no|policy)`,
        `policy${S}(?:number|no|#)`, `member${S}(?:id|number|no)`]
    },
    {
      tag: "PHONE", label: "Phone number", category: "personal", kind: "phone", confidence: "high",
      keys: [`(?:mobile|cell|home|work|office|contact|emergency|business)${S}(?:phone|tel)${NO}`,
        `(?:mobile|cell|contact|emergency)${S}(?:number|no)`, `phone${NO}`, "mobile", "cell", `tel(?:ephone)?${NO}`,
        `whats${S}app${NO}`, `fax${NO}`, "msisdn"]
    },
    {
      tag: "DOB", label: "Date of birth", category: "personal", kind: "date", confidence: "high",
      keys: ["dob", String.raw`d\.o\.b\.?`, `date${S}of${S}birth`, `birth${S}date`, `birth${S}day`]
    },
    { tag: "PLACE", label: "Place of birth", category: "personal", kind: "text", confidence: "high", keys: [`place${S}of${S}birth`, `birth${S}place`] },
    {
      tag: "ADDRESS", label: "Postal address", category: "personal", kind: "address", confidence: "high",
      keys: [`(?:home|street|mailing|postal|billing|shipping|residential|delivery|house|permanent|current)${S}address`,
        `address(?:${S}line${S}\\d)?`, `street`]
    },
    { tag: "POSTCODE", label: "Postal code", category: "personal", kind: "postcode", confidence: "medium", keys: [`zip(?:${S}code)?`, `post(?:al)?${S}code`] },
    {
      tag: "ACCOUNT", label: "Bank account number", category: "financial", kind: "id", confidence: "high",
      keys: [`(?:bank${S})?account${S}(?:number|no\\.?|num|#)`, `acct${NO}`, `routing${S}(?:number|no)`, `sort${S}code`, "iban"]
    },
    { tag: "CARD", label: "Card number", category: "financial", kind: "id", confidence: "high", keys: [`(?:credit${S}|debit${S})?card${S}(?:number|no\\.?|num|#)`, `cc${S}(?:number|no|num)`] },
    { tag: "PIN", label: "Card security code or PIN", category: "financial", kind: "code", confidence: "high", keys: ["cvv2?", "cvc2?", "csc", `security${S}code`, `pin(?:${S}(?:code|number|no))?`] },
    {
      tag: "USER", label: "Username", category: "personal", kind: "user", confidence: "medium",
      keys: [`user${S}name`, `account${S}name`, `login(?:${S}(?:name|id))?`, `logon${S}name`, `sam${S}account${S}name`,
        `user${S}principal${S}name`, "upn", `target${S}user${S}name`, `subject${S}user${S}name`, "user"]
    },
    {
      tag: "HOST", label: "Hostname", category: "network", kind: "user", confidence: "medium",
      keys: [`host${S}name`, `computer${S}name`, "computer", `machine${S}name`, `workstation(?:${S}name)?`, `device${S}name`, `node${S}name`]
    }
  ];
  for (const def of FIELD_DEFS) {
    def.source = def.keys.join("|");
    def.anchored = new RegExp("^(?:" + def.source + ")$", "i");
  }
  const FIELD_KEYS = FIELD_DEFS.map((d) => "(?:" + d.source + ")").join("|");
  const FIELD_RE = new RegExp(
    String.raw`(?<![A-Za-z0-9_'])(?<q>["']?)(?<k>` + FIELD_KEYS + String.raw`)\k<q>[ \t]*(?:\.[ \t]*)*(?::=|:|=|-(?=[ \t]))[ \t]*` +
    String.raw`(?:"(?<v1>[^"\r\n]*)"|'(?<v2>[^'\r\n]*)'|(?<v3>[^\r\n;|\t}]*?)(?=[ \t]*(?:$|[\r\n;|\t}]|,[ \t]*["']?[A-Za-z_][\w .'\-]{0,30}["']?[ \t]*[:=])))`,
    "gdim"
  );

  const NOT_NAME_WORDS = new Set([
    "number", "card", "credit", "debit", "account", "policy", "rule", "rules", "type", "group", "test", "tests",
    "lab", "data", "default", "file", "files", "record", "records", "id", "code", "key", "service", "server",
    "app", "application", "project", "team", "site", "page", "report", "alert", "alerts", "incident", "case",
    "task", "job", "build", "deploy", "release", "access", "block", "control", "controls", "check", "checks",
    "user", "users", "admin", "admins", "role", "roles", "workspace", "storage", "container", "bucket",
    "network", "security", "detection", "query", "queries", "table", "event", "events", "log", "logs",
    "item", "items", "document", "documents", "folder", "list", "settings", "config", "template", "sample",
    "financial", "external", "internal", "public", "private", "strict", "isolated", "validation", "info"
  ]);
  const NAME_VALUE = /^[\p{L}][\p{L}'’.\-]*(?:[ ]+[\p{L}][\p{L}'’.\-]*){0,5}$/u;
  const TITLE_WORD = /^[\p{Lu}][\p{Ll}'’.\-]+$/u;
  const COMMON_ACCOUNTS = new Set([
    "system", "local service", "network service", "anonymous logon", "root", "admin", "administrator",
    "guest", "user", "users", "default", "public", "nobody", "daemon", "localhost", "runner", "unknown"
  ]);
  const ADDRESS_NOT = /(?:ip|ipv4|ipv6|mac|e-?mail|remote|local|bind|listen|server|memory|base|return|web|wallet|contract|network|broadcast|gateway|proxy|mail|source|destination|src|dst|client|peer|public|private|internal|external|physical|virtual|link|hardware|start|end|load|entry)\s*$/i;

  function fieldDef(key) {
    for (const def of FIELD_DEFS) if (def.anchored.test(key)) return def;
    return null;
  }

  function checkFieldValue(def, key, value, text, keyStart) {
    const v = value.trim();
    if (!v || isPlaceholder(v)) return false;
    if (/^(?:name|bare-name|user|address|text)$/.test(def.kind) && codeish(v)) return false;
    const digits = (v.match(/\d/g) || []).length;
    switch (def.kind) {
      case "name":
        return v.length <= 80 && NAME_VALUE.test(v);
      case "bare-name": {
        if (v.length > 60 || !NAME_VALUE.test(v)) return false;
        const words = v.split(/ +/);
        // "TargetUserName" or Name="..." attributes are identifiers, not people.
        if (!words.every((w) => TITLE_WORD.test(w) || /^[\p{Ll}'’.\-]+$/u.test(w))) return false;
        if (/^Name\s*=\s*["']/.test(text.slice(keyStart, keyStart + 8))) return false;
        if (key === "Name" || key === "NAME") return words.length <= 5;
        // Lowercase "name:" is everywhere in YAML and JSON. Only take it when the
        // value looks like a person's name and the line is not an indented config entry.
        const lineStart = text.lastIndexOf("\n", keyStart - 1) + 1;
        const before = text.slice(lineStart, keyStart);
        if (/^[ \t]{2,}|^[ \t]*-[ \t]/.test(before)) return false;
        // "Credit Card Number", "Default Policy": Title Case labels, not people.
        if (words.some((w) => NOT_NAME_WORDS.has(w.toLowerCase()))) return false;
        return words.length >= 2 && words.length <= 4 && words.every((w) => TITLE_WORD.test(w));
      }
      case "id":
        return v.length <= 40 && digits >= 3 && /^[A-Za-z0-9 .\-\/]+$/.test(v);
      case "code":
        return /^\d{3,8}$/.test(v);
      case "phone":
        return digits >= 6 && digits <= 16 && /^[+\d\s().\-\/]+(?:\s*(?:x|ext\.?)\s*\d+)?$/i.test(v);
      case "date":
        return v.length <= 40 && (digits >= 2 || /(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)/i.test(v));
      case "text":
        return v.length <= 120 && /\p{L}/u.test(v);
      case "address": {
        if (v.length > 200 || !/\p{L}/u.test(v)) return false;
        if (/^[0-9A-Fa-f:.\-]+$/.test(v) || /^\d{1,3}(?:\.\d{1,3}){3}/.test(v) || v.includes("@")) return false;
        if (/^address/i.test(key)) {
          const lineStart = text.lastIndexOf("\n", keyStart - 1) + 1;
          if (ADDRESS_NOT.test(text.slice(lineStart, keyStart))) return false;
        }
        return /\d/.test(v) || v.includes(",") || v.split(/\s+/).length >= 2;
      }
      case "postcode":
        return v.length <= 12 && digits >= 2;
      case "user":
        if (/^[A-Z][a-z]+(?:[A-Z][a-z]+){1,}$/.test(v)) return false; // PublicUserResponse (a type)
        return v.length <= 64 && v.split(/\s+/).length <= 3 && !/[(){}<>]/.test(v) &&
          !COMMON_ACCOUNTS.has(v.toLowerCase()) && !/^[-–—]$/.test(v);
      default:
        return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------
  function shannon(s) {
    const freq = new Map();
    for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
    let h = 0;
    for (const n of freq.values()) {
      const p = n / s.length;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function charClasses(s) {
    return (/[a-z]/.test(s) ? 1 : 0) + (/[A-Z]/.test(s) ? 1 : 0) + (/\d/.test(s) ? 1 : 0);
  }

  // True for strings that look machine-generated rather than written by a person.
  function looksRandom(seg) {
    const classes = charClasses(seg);
    // 16+ characters is enough when upper, lower and digits are all present.
    if (seg.length < (classes === 3 ? 16 : 20)) return false;
    if (/^[0-9a-fA-F]+$/.test(seg)) return false; // hex has its own rule
    if (!hasLetter(seg)) return false;
    if (!hasDigit(seg) && !(classes === 2 && seg.length >= 24)) return false;
    let mixed = 0;
    for (const piece of seg.split(/[-_+=~]+/)) {
      if (piece.length > 3 && charClasses(piece) >= 2 && !wordy(piece)) mixed += piece.length;
    }
    if (mixed < 12 || mixed < seg.length * 0.4) return false;
    // Readable identifiers (Tunneling2025Results, DE_WinEventLogSvc_Crash) are mostly words.
    if (wordy(seg)) return false;
    return shannon(seg) >= (seg.length >= 32 ? 3.9 : 3.5);
  }

  // True when a string is mostly made of word-like pieces: Event, Log, 2025, getUser.
  // Random keys break into many one- and two-character pieces instead.
  function wordy(s) {
    let covered = 0;
    for (const t of s.match(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+/g) || []) {
      if (/^\d+$/.test(t) ? t.length >= 2 : t.length >= 3 && /[aeiouyAEIOUY]/.test(t)) covered += t.length;
    }
    const letters = s.replace(/[^A-Za-z0-9]/g, "").length;
    return letters > 0 && covered >= letters * 0.75;
  }

  function luhn(digits) {
    let sum = 0;
    let dbl = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (dbl) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      dbl = !dbl;
    }
    return sum % 10 === 0;
  }

  function ibanValid(raw) {
    const s = raw.replace(/\s+/g, "").toUpperCase();
    if (s.length < 15 || s.length > 34) return false;
    const moved = s.slice(4) + s.slice(0, 4);
    let rem = 0;
    for (const ch of moved) {
      const code = ch.charCodeAt(0);
      const val = code >= 65 && code <= 90 ? String(code - 55) : ch;
      for (const d of val) rem = (rem * 10 + (d.charCodeAt(0) - 48)) % 97;
    }
    return rem === 1;
  }

  function decodeBase64(s) {
    try {
      const fn = typeof atob === "function" ? atob : null;
      if (!fn) return null;
      return fn(s.replace(/-/g, "+").replace(/_/g, "/"));
    } catch (error) {
      return null;
    }
  }

  // Long base64 that decodes to structured text (JSON, markup) is data, such as a
  // diagram embedded in an SVG. Short decoded strings stay suspicious: they are
  // often just an encoded password.
  function isEncodedText(seg) {
    if (seg.length < 64 || !/^[A-Za-z0-9+\/]+={0,2}$/.test(seg)) return false;
    const body = seg.replace(/=+$/, "");
    const decoded = decodeBase64(body.slice(0, body.length - (body.length % 4)));
    if (!decoded || decoded.length < 48) return false;
    const printable = decoded.replace(/[^\x20-\x7e\t\r\n]/g, "").length;
    return printable >= decoded.length * 0.95 && (decoded.match(/[{}\[\]":,<>=]/g) || []).length >= 4;
  }

  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function valueSpan(m) {
    const groups = m.indices && m.indices.groups;
    if (groups) {
      for (const name of ["v", "v1", "v2", "v3"]) {
        if (groups[name]) return groups[name];
      }
    }
    return [m.index, m.index + m[0].length];
  }

  function stripQuotes(value, start, end) {
    const first = value[0];
    if ((first === '"' || first === "'" || first === "`") && value.length >= 2 && value[value.length - 1] === first) {
      return { value: value.slice(1, -1), start: start + 1, end: end - 1 };
    }
    return { value, start, end };
  }

  function contextBefore(text, start, n) {
    return text.slice(Math.max(0, start - n), start);
  }

  // ---------------------------------------------------------------------------
  // Detectors. Order is priority: when two findings overlap, the earlier
  // detector wins.
  // ---------------------------------------------------------------------------
  function buildDetectors() {
    const list = [];

    list.push({
      id: "private-key", label: "Private key", tag: "PRIVATE-KEY", category: "secret", confidence: "high",
      find(text) {
        const out = [];
        const begin = /-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY(?: BLOCK)?-----/g;
        let m;
        while ((m = begin.exec(text)) !== null) {
          const endMarker = /-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g;
          endMarker.lastIndex = begin.lastIndex;
          const e = endMarker.exec(text);
          // A pasted key that was cut off is still redacted to the end of the text.
          const end = e ? e.index + e[0].length : text.length;
          out.push({ start: m.index, end });
          begin.lastIndex = end;
        }
        const putty = /^Private-Lines: \d+\r?\n[\s\S]*?(?=^Private-MAC:|$(?![\s\S]))/gm;
        while ((m = putty.exec(text)) !== null) {
          if (m[0].length) out.push({ start: m.index, end: m.index + m[0].length, label: "PuTTY private key" });
          else putty.lastIndex++;
        }
        return out;
      }
    });

    for (const [id, label, tag, source, check] of PROVIDERS) {
      list.push({
        id, label, tag, category: "secret", confidence: "high",
        regex: new RegExp(B + "(?:" + source + ")" + E, "gd"),
        check: check ? (value) => (check(value) ? {} : null) : null
      });
    }

    list.push({
      id: "url-password", label: "Password in a URL", tag: "PASSWORD", category: "secret", confidence: "high",
      regex: /\b[a-z][a-z0-9+.\-]*:\/\/[^\s:@\/?#'"]+:(?<v>[^\s@\/?#'"]+)@/gid,
      check: (value) => (isPlaceholder(value) ? null : {})
    });

    list.push({
      id: "auth-header", label: "Authorization header", tag: "TOKEN", category: "secret", confidence: "high",
      regex: /\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?(?:(?:bearer|basic|token|digest|negotiate|ntlm|apikey|api-key|sso-key|hmac|sharedaccesssignature)\s+)?(?<v>[A-Za-z0-9._~+\/=:,\-]{8,})/gid,
      check: (value) => (/^(?:bearer|basic|token|digest|negotiate|ntlm)$/i.test(value) || isPlaceholder(value) ? null : {})
    });

    list.push({
      id: "bearer-token", label: "Bearer token", tag: "TOKEN", category: "secret", confidence: "high",
      regex: /\bbearer\s+(?<v>[A-Za-z0-9._~+\/\-]{16,}=*)/gid
    });

    list.push({
      id: "curl-user", label: "Password in a -u flag", tag: "PASSWORD", category: "secret", confidence: "high",
      regex: /(?:^|\s)(?:-u|--user|--proxy-user)\s+["']?[^\s:"']+:(?<v>[^\s"']+)/gd,
      check: (value) => (isPlaceholder(value) ? null : {})
    });

    list.push({
      id: "cookie", label: "Cookie value", tag: "SESSION", category: "secret", confidence: "high",
      find(text) {
        const out = [];
        const header = /^[ \t]*(?:set-)?cookie[ \t]*:[ \t]*(?<v>[^\r\n]+)/gdim;
        const skip = /^(?:path|domain|expires|max-age|samesite|secure|httponly|priority|partitioned|version|comment)$/i;
        let m;
        while ((m = header.exec(text)) !== null) {
          const [vs] = m.indices.groups.v;
          const pairs = /(?:^|;)\s*(?<name>[^=;\s]+)\s*=\s*(?<v>[^;]*)/gd;
          let p;
          while ((p = pairs.exec(m.groups.v)) !== null) {
            const cv = p.groups.v.trim();
            if (skip.test(p.groups.name) || !cv || isPlaceholder(cv)) continue;
            if (cv.length < 8 && !hasDigit(cv)) continue; // theme=dark, lang=en
            const [ps, pe] = p.indices.groups.v;
            out.push({ start: vs + ps, end: vs + pe, context: p.groups.name });
          }
        }
        return out;
      }
    });

    list.push({
      id: "xml-field", label: "Secret value", tag: "SECRET", category: "secret", confidence: "high",
      find(text) {
        const out = [];
        const re = /<(?<k>[A-Za-z_][\w:.\-]*)(?<attrs>\s[^<>]*)?>(?<v>[^<\r\n]{1,300})<\/\k<k>>/gd;
        let m;
        while ((m = re.exec(text)) !== null) {
          let key = m.groups.k.replace(/^.*:/, "");
          const attrName = m.groups.attrs && /\bName\s*=\s*["']([^"']+)["']/i.exec(m.groups.attrs);
          if (attrName) key = attrName[1];
          const [vs, ve] = m.indices.groups.v;
          const value = m.groups.v.trim();
          if (!value || isPlaceholder(value)) continue;
          const secret = classifyKey(key);
          if (secret) {
            out.push({ start: vs, end: ve, tag: secret.tag, label: secret.label, context: key });
            continue;
          }
          const field = fieldDef(key) || (/^(?:target|subject)?user(?:name)?$/i.test(key) ? fieldDef("username") : null) ||
            (/^(?:workstation|computer|host)(?:name)?$/i.test(key) ? fieldDef("hostname") : null);
          if (field && field.kind !== "bare-name" && checkFieldValue(field, key, value, text, m.index)) {
            out.push({ start: vs, end: ve, tag: field.tag, label: field.label, category: field.category, confidence: field.confidence, context: key });
          }
        }
        return out;
      }
    });

    list.push({
      id: "cli-flag", label: "Secret value", tag: "SECRET", category: "secret", confidence: "high",
      regex: /(?<![\w\-])--?(?<k>[A-Za-z][\w\-]{2,})(?:[ \t]+|=)(?<v>"[^"\r\n]*"|'[^'\r\n]*'|[^\s"'\-][^\s"']*)/gd,
      retry: true,
      check(value, m, text, start, end) {
        const secret = classifyKey(m.groups.k);
        if (!secret) return null;
        const q = stripQuotes(value, start, end);
        if (isPlaceholder(q.value)) return null;
        return { start: q.start, end: q.end, tag: secret.tag, label: secret.label, context: m.groups.k };
      }
    });

    list.push({
      id: "assignment", label: "Secret value", tag: "SECRET", category: "secret", confidence: "high",
      regex: /(?<![A-Za-z0-9_.\-])(?<q>["']?)(?<k>[A-Za-z_][A-Za-z0-9_.\-]{0,80})\k<q>[ \t]*(?<op>:=|=>|=|:)[ \t]*(?<v>"(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*'|`[^`\r\n]*`|\$\{[^}\r\n]*\}|<[^<>\r\n]*>|[^\s"'`,;)}\]>]+)/gd,
      retry: true,
      check(value, m, text, start, end) {
        const key = m.groups.k;
        const secret = classifyKey(key);
        if (!secret) return null;
        const quoted = /^["'`]/.test(value);
        const q = stripQuotes(value, start, end);
        // In a URL query (?a=1&sig=...) the value ends at the next "&".
        if (!quoted && /[?&]$/.test(contextBefore(text, m.index + m.groups.q.length, 1)) && q.value.includes("&")) {
          q.value = q.value.slice(0, q.value.indexOf("&"));
          q.end = q.start + q.value.length;
        }
        const v = q.value.trim();
        if (isPlaceholder(v)) return null;
        if (/^(?:bearer|basic|token|digest|negotiate|ntlm)$/i.test(v)) return null;
        if (!quoted && looksLikeCode(v)) return null;
        if (!quoted && m.groups.q && /^[A-Za-z_][\w.]*$/.test(v)) return null; // "csrf_token": csrf_token
        if (!quoted && followedByCode(text, q.end)) return null; // user_key = username or "x"
        // "Credential: rotate the exfiltrated key" is a sentence, not a value.
        if (!quoted && m.groups.op === ":" && /^[a-z][a-z\-]*$/.test(v) && /^[ \t]+[a-z]{2,}/.test(text.slice(q.end, q.end + 24))) return null;
        if (v === key) return null;
        if (/^\d+$/.test(v) && v.length < 6 && secret.kind !== "pin") return null;
        // Session IDs are long and random; "triage_session" is a cookie name.
        if (secret.tag === "SESSION" && !(v.length >= 12 && hasDigit(v))) return null;
        if (v.length < 3 && secret.kind !== "pin") return null;
        return { start: q.start, end: q.end, tag: secret.tag, label: secret.label, context: key };
      }
    });

    // Secrets written in a sentence: "my password is hunter2", "the API key: abc...",
    // "here is the token 9f8Kx...". A connector word lets ordinary values through;
    // without one, the value has to look like a credential.
    list.push({
      id: "keyword-value", label: "Secret value", tag: "SECRET", category: "secret", confidence: "high",
      regex: /\b(?<k>passwords?|passwd|pwd|passcode|pass ?phrase|tokens?|secrets?|api[ _\-]?keys?|access[ _\-]?keys?|secret[ _\-]?keys?|private[ _\-]?keys?|client[ _\-]?secrets?|license[ _\-]?keys?|keys?|pins?|otp|one[ -]time (?:code|password)|(?:access|verification|auth|backup|recovery|security|login|2fa|mfa) codes?|credentials?)\b(?:(?<c>[ \t]*[:=])[ \t]*|(?<verb>[ \t]+(?:is|was|are|were|will be|reads|for[ \t]+\S+[ \t]+(?:is|was)))[ \t]+|[ \t]+)["'`“]?(?<v>[^\s"'`”]{4,200})/gid,
      retry: true,
      check(value, m) {
        const v = value.replace(/[.,;:)\]]+$/, "");
        const start = m.indices.groups.v[0];
        const keyword = m.groups.k.toLowerCase();
        if (isPlaceholder(v) || PROSE_WORDS.has(v.toLowerCase())) return null;
        if (/^(?:https?:|[A-Za-z]:\\)|\//.test(v) || looksLikeCode(v)) return null;
        // Looks like a credential: digits, symbols, or case mixing that is not just CamelCase words.
        const secretish = v.length >= 6 && (hasDigit(v) || /[!@#$%^&*+=?~<>{}|\\]/.test(v) ||
          (/[a-z]/.test(v) && /[A-Z]/.test(v) && !/^(?:[A-Z][a-z]+|[a-z]+)(?:[A-Z][a-z]+)*$/.test(v)));
        if (/^(?:keys?|pins?)$/.test(keyword) || /codes?$/.test(keyword)) {
          // "key" and "code" are common English words: need a connector and a value with digits.
          if (!(m.groups.c || m.groups.verb) || !hasDigit(v)) return null;
        } else if (m.groups.verb) {
          // "my password is SunnyDays": the sentence says it is the value.
          // "credentials were exported", "the token is separate" are sentences about it.
          if (/^[a-z][a-z'\-]*$/.test(v)) return null;
        } else if (m.groups.c) {
          if (!secretish) return null;
        } else if (!secretish || v.length < 8) {
          return null;
        }
        const kind = /pass|pwd|phrase/.test(keyword) ? "password" : /pin|otp|code|one/.test(keyword) ? "pin" :
          /token/.test(keyword) ? "token" : "secret";
        const [tag, label] = KEY_KINDS[kind];
        return { start, end: start + v.length, tag, label, context: m.groups.k };
      }
    });

    list.push({
      id: "base64-secret", label: "Base64-encoded secret", tag: "SECRET", category: "secret", confidence: "high",
      find(text, ctx) {
        if (ctx.depth > 0) return [];
        const out = [];
        const re = /(?<![A-Za-z0-9+\/=_\-])[A-Za-z0-9+\/]{16,}={0,2}(?![A-Za-z0-9+\/=_\-])/g;
        let m;
        while ((m = re.exec(text)) !== null) {
          if (m[0].length > 8192) continue;
          const decoded = decodeBase64(m[0]);
          if (!decoded || decoded.length < 8) continue;
          const printable = decoded.replace(/[^\x20-\x7e\t\r\n]/g, "").length;
          if (printable < decoded.length * 0.95) continue;
          const inner = collect(decoded, { depth: 1, secretsOnly: true, customTerms: [], allowTerms: [] });
          const hit = inner.find((f) => f.category === "secret" && f.confidence === "high");
          if (hit) {
            out.push({
              start: m.index, end: m.index + m[0].length, tag: hit.tag,
              label: "Base64-encoded " + hit.label.charAt(0).toLowerCase() + hit.label.slice(1)
            });
          }
        }
        return out;
      }
    });

    list.push({
      id: "labelled-field", label: "Personal data", tag: "PII", category: "personal", confidence: "high",
      regex: FIELD_RE,
      retry: true,
      check(value, m, text, start, end) {
        const key = m.groups.k;
        const def = fieldDef(key);
        if (!def) return null;
        let trimmed = value.replace(/\s+$/, "");
        const keyStart = m.index + m.groups.q.length;
        if (m.groups.v3 !== undefined) {
          // Source code shapes: "user": actor, | user=hidden_user, | "host": a.host or b.host
          if (m.groups.q && /^[A-Za-z_][\w.]*,?$/.test(trimmed)) return null;
          if (/,$/.test(trimmed) && /^[ \t]*(?:\r?\n|$)/.test(text.slice(start + trimmed.length, start + trimmed.length + 2))) {
            if (/^[A-Za-z_][\w.]*,$/.test(trimmed)) return null;
          }
          trimmed = trimmed.replace(/,$/, "");
          if (followedByCode(text, start + trimmed.length) || /\s(?:or|and|if|else|\+)\s/.test(trimmed)) return null;
        }
        // "user = account" with spaces around "=" is source code, not a log field.
        const sep = text.slice(keyStart + key.length, start);
        if (def.kind === "user" && /\s=\s/.test(sep) && /^[a-z_][\w]*$/.test(trimmed)) return null;
        if (!checkFieldValue(def, key, trimmed, text, keyStart)) return null;
        return {
          start, end: start + trimmed.length, tag: def.tag, label: def.label,
          category: def.category, confidence: def.confidence, context: key
        };
      }
    });

    list.push({
      id: "card", label: "Payment card number", tag: "CARD", category: "financial", confidence: "high",
      regex: /(?<![\d\-.])(?:\d[ \-]?){12,18}\d(?![\d\-]|\.\d)/g, // not inside decimals like 64.4839968774395
      check(value) {
        const digits = value.replace(/\D/g, "");
        if (digits.length < 13 || digits.length > 19) return null;
        if (!/^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5|4[4-9])|3(?:0[0-5]|[68])|35)/.test(digits)) return null;
        return luhn(digits) ? {} : null;
      }
    });

    list.push({
      id: "iban", label: "IBAN", tag: "IBAN", category: "financial", confidence: "high",
      regex: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g,
      check: (value) => (ibanValid(value) ? {} : null)
    });

    list.push({
      id: "ssn", label: "Social Security number", tag: "SSN", category: "personal", confidence: "medium",
      regex: /(?<![\d\-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d\-])/g
    });

    list.push({
      id: "email", label: "Email address", tag: "EMAIL", category: "personal", confidence: "high",
      regex: /(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![A-Za-z0-9\-])/g,
      check(value) {
        const [local, domain] = value.split("@");
        if (/\.(?:png|jpe?g|gif|svg|webp|ico|js|css|map)$/i.test(domain)) return null;
        if (local === "git" && /^(?:github|gitlab|bitbucket|ssh\.dev\.azure)\./i.test(domain)) return null;
        return {};
      }
    });

    list.push({
      id: "shell-prompt", label: "Username in a shell prompt", tag: "USER", category: "personal", confidence: "medium",
      find(text) {
        const out = [];
        const re = /(?<![\w.\-@])(?<u>[a-z_][a-z0-9_\-]{1,31})@(?<h>[A-Za-z0-9][A-Za-z0-9\-]{0,62})(?=:[~\/])/gd;
        let m;
        while ((m = re.exec(text)) !== null) {
          const [us, ue] = m.indices.groups.u;
          const [hs, he] = m.indices.groups.h;
          if (!COMMON_ACCOUNTS.has(m.groups.u)) out.push({ start: us, end: ue });
          if (!COMMON_ACCOUNTS.has(m.groups.h.toLowerCase())) {
            out.push({ start: hs, end: he, tag: "HOST", label: "Hostname in a shell prompt", category: "network" });
          }
        }
        return out;
      }
    });

    const skipUsers = /^(?:public|default|default user|all users|administrator|runneradmin|runner|shared|linuxbrew|guest)$/i;
    list.push({
      id: "windows-user-path", label: "Username in a path", tag: "USER", category: "personal", confidence: "high",
      regex: /\b[A-Za-z]:(?:\\{1,2}|\/)(?:Users|Documents and Settings)(?:\\{1,2}|\/)(?<v>[^\\\/\r\n"'<>:|?*]+)/gid,
      check: (value) => (skipUsers.test(value) || isPlaceholder(value) || /^%.*%$/.test(value) ? null : {})
    });
    list.push({
      id: "unix-user-path", label: "Username in a path", tag: "USER", category: "personal", confidence: "high",
      regex: /(?<![\w.\-])(?:\/var)?\/(?:home|Users)\/(?<v>[A-Za-z0-9._\-]+)/gd,
      check: (value) => (skipUsers.test(value) || isPlaceholder(value) ? null : {})
    });

    list.push({
      id: "windows-hostname", label: "Windows computer name", tag: "HOST", category: "network", confidence: "medium",
      regex: /\b(?:DESKTOP|LAPTOP|WIN)-[A-Z0-9]{6,15}\b/g
    });

    list.push({
      id: "internal-host", label: "Internal hostname", tag: "HOST", category: "network", confidence: "medium",
      regex: /(?<![A-Za-z0-9\-.])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+(?:local|lan|corp|internal|intranet|localdomain|home\.arpa)(?![A-Za-z0-9\-])/gi,
      check: (value) => (/^localhost\./i.test(value) ? null : {})
    });

    list.push({
      id: "cloud-host", label: "Cloud resource name", tag: "RESOURCE", category: "network", confidence: "medium",
      regex: /(?<![A-Za-z0-9\-.])(?<v>(?:[a-z0-9][a-z0-9\-]{0,62}\.)*[a-z0-9][a-z0-9\-]{0,62})\.(?:scm\.azurewebsites\.net|azurewebsites\.net|azurecontainerapps\.io|azurecr\.io|(?:blob|file|queue|table|dfs|web)\.core\.windows\.net|vault\.azure\.net|database\.windows\.net|servicebus\.windows\.net|azure-api\.net|cognitiveservices\.azure\.com|openai\.azure\.com|search\.windows\.net|documents\.azure\.com|redis\.cache\.windows\.net|azurefd\.net|cloudapp\.azure\.com|azure-devices\.net|s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|execute-api\.[a-z0-9\-]+\.amazonaws\.com|rds\.amazonaws\.com|elb\.amazonaws\.com|cloudfront\.net|herokuapp\.com|vercel\.app|netlify\.app|firebaseio\.com|firebaseapp\.com|web\.app|appspot\.com|run\.app|supabase\.co|ngrok-free\.app|ngrok\.io|trycloudflare\.com|loca\.lt)(?![A-Za-z0-9\-])/gid,
      check: (value) => (/^(?:www|login|portal|management)$/i.test(value) ? null : {})
    });

    list.push({ id: "custom-term", label: "Your term", tag: "REDACTED", category: "custom", confidence: "high", find: findCustomTerms });

    list.push({
      id: "ipv4", label: "IP address", tag: "IP", category: "network", confidence: "medium",
      regex: /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?!\.?\d)/g,
      check(value, m, text, start) {
        const o = value.split(".").map(Number);
        if (o[0] === 0 || o[0] === 127 || o[0] === 255 || o[0] >= 224) return null;
        if ((o[0] === 192 && o[1] === 0 && o[2] === 2) || (o[0] === 198 && o[1] === 51 && o[2] === 100) || (o[0] === 203 && o[1] === 0 && o[2] === 113)) return null;
        if (/(?:\bv|version\s*:?\s*|ver\.?\s*)$/i.test(contextBefore(text, start, 12))) return null;
        const internal = o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168) ||
          (o[0] === 100 && o[1] >= 64 && o[1] <= 127) || (o[0] === 169 && o[1] === 254);
        return internal ? { tag: "INTERNAL-IP", label: "Internal IP address" } : { label: "Public IP address" };
      }
    });

    list.push({
      id: "ipv6", label: "IPv6 address", tag: "IPV6", category: "network", confidence: "medium",
      regex: /(?<![\w:.])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![\w:])|(?<![\w:.])(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?(?![\w:])/gi,
      check(value) {
        const groups = value.split(":").filter(Boolean);
        if (groups.length < 3) return null;
        if (groups.every((g) => /^\d{1,2}$/.test(g))) return null; // clock times
        if (!/[a-f]/i.test(value) && !groups.some((g) => g.length >= 3)) return null;
        return {};
      }
    });

    list.push({
      id: "mac", label: "MAC address", tag: "MAC", category: "network", confidence: "medium",
      regex: /(?<![0-9A-Fa-f:\-])[0-9A-Fa-f]{2}([:\-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:\-])/g,
      check: (value) => (/^(?:00[:\-]){5}00$/.test(value) || /^(?:ff[:\-]){5}ff$/i.test(value) ? null : {})
    });

    list.push({
      id: "phone", label: "Phone number", tag: "PHONE", category: "personal", confidence: "medium",
      regex: /(?<![\w+])\+\d{1,3}[ .\-]?(?:\(\d{1,4}\)[ .\-]?)?\d{2,4}(?:[ .\-]?\d{2,4}){1,4}(?![\w])|(?<![\w\-])\(\d{3}\)[ .\-]?\d{3}[ .\-]\d{4}(?![\w\-])|(?<![\w\-.])\d{3}[.\-]\d{3}[.\-]\d{4}(?![\w\-.])|(?<![\d+])0[789][01]\d[ \-]?\d{3}[ \-]?\d{4}(?!\d)|(?<![\d+])07\d{3}[ ]?\d{6}(?!\d)/g,
      check(value) {
        const digits = value.replace(/\D/g, "");
        return digits.length >= 10 && digits.length <= 15 ? {} : null;
      }
    });

    list.push({
      id: "uuid", label: "ID (GUID)", tag: "ID", category: "network", confidence: "low",
      regex: /(?<![0-9A-Fa-f\-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9A-Fa-f\-])/g,
      check(value, m, text, start) {
        const before = contextBefore(text, start, 48).toLowerCase();
        if (/(?:tenant|subscription|directory)[\s\w\-"']*[:=\s/"']\s*["']?$|\/subscriptions\/$/.test(before)) {
          return { label: "Azure tenant or subscription ID", tag: "TENANT-ID", confidence: "medium" };
        }
        return {};
      }
    });

    list.push({
      id: "random-string", label: "Possible secret (random-looking string)", tag: "SECRET", category: "secret", confidence: "medium",
      find(text) {
        const out = [];
        const re = /[A-Za-z0-9+\/=_\-~.]{16,}/g;
        let m;
        while ((m = re.exec(text)) !== null) {
          const tok = m[0];
          const base = m.index;
          const parts = [];
          const segs = tok.split("/");
          const blob = !tok.includes(".") && !tok.startsWith("/") &&
            (/[+]/.test(tok) || /=$/.test(tok) || (segs.length > 1 && segs.every((s) => s.length >= 6) && /[A-Z]/.test(tok) && /[a-z]/.test(tok)));
          if (blob) {
            parts.push([0, tok.length]);
          } else {
            const sep = /[^./]+/g;
            let s;
            while ((s = sep.exec(tok)) !== null) parts.push([s.index, s.index + s[0].length]);
          }
          for (const [ps, pe] of parts) {
            let seg = tok.slice(ps, pe);
            const lead = seg.match(/^[=_\-~+]*/)[0].length;
            seg = seg.slice(lead).replace(/[_\-~]+$/, "");
            if (/^(?:sha(?:1|224|256|384|512)|md5)-/i.test(seg) || !looksRandom(seg)) continue;
            const start = base + ps + lead;
            if (/(?:sha(?:1|224|256|384|512)|md5)[-:]$/i.test(contextBefore(text, start, 8))) continue; // integrity hashes
            if (isEncodedText(seg)) {
              out.push({ start, end: start + seg.length, confidence: "low", label: "Encoded data (base64 text)" });
              continue;
            }
            const long = seg.length > 256;
            out.push({
              start, end: start + seg.length,
              confidence: long ? "low" : "medium",
              label: long ? "Long encoded data" : undefined
            });
          }
        }
        return out;
      }
    });

    list.push({
      id: "hex", label: "Long hex string (key or hash)", tag: "HEX", category: "secret", confidence: "medium",
      regex: /(?<![A-Za-z0-9])[0-9a-fA-F]{32,}(?![A-Za-z0-9])/g,
      check(value, m, text, start) {
        if (!hasDigit(value) || !/[a-f]/i.test(value)) return null;
        if (/(?:sha-?\d*|md5|hash|digest|checksum|commit|fingerprint|thumbprint|sha256sum|integrity|etag|object)[\s\w"'=:\-()]{0,24}$/i.test(contextBefore(text, start, 40))) {
          return { label: "Hash value", confidence: "low" };
        }
        return {};
      }
    });

    return list;
  }

  function findCustomTerms(text, ctx) {
    const out = [];
    for (const term of ctx.customTerms || []) {
      const t = term.trim();
      if (t.length < 2) continue;
      const re = new RegExp("(?<![\\p{L}\\p{N}])" + escapeRegex(t) + "(?![\\p{L}\\p{N}])", "giu");
      let m;
      while ((m = re.exec(text)) !== null) out.push({ start: m.index, end: m.index + m[0].length, context: t });
    }
    return out;
  }

  const DETECTORS = buildDetectors();
  DETECTORS.forEach((d, i) => { d.priority = i; });
  const SECRET_DETECTORS = DETECTORS.filter((d) => d.category === "secret" && d.id !== "random-string" && d.id !== "hex");

  function runDetector(det, text, ctx, out) {
    const push = (verdict, start, end) => {
      const f = {
        detector: det.id,
        label: verdict.label || det.label,
        tag: verdict.tag || det.tag,
        category: verdict.category || det.category,
        confidence: verdict.confidence || det.confidence,
        context: verdict.context || null,
        start: verdict.start !== undefined ? verdict.start : start,
        end: verdict.end !== undefined ? verdict.end : end,
        priority: det.priority
      };
      if (f.end > f.start) out.push(f);
    };
    if (det.find) {
      for (const hit of det.find(text, ctx)) push(hit, hit.start, hit.end);
      return;
    }
    const re = det.regex;
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const at = m.index;
      if (m[0].length === 0) {
        re.lastIndex = at + 1;
        continue;
      }
      const [start, end] = valueSpan(m);
      const value = text.slice(start, end);
      const verdict = det.check ? det.check(value, m, text, start, end) : {};
      if (verdict) {
        push(verdict, start, end);
      } else if (det.retry) {
        // The match was rejected (for example "https:" looked like a key).
        // Try again from inside it so a real key later on the line is not skipped.
        re.lastIndex = start > at ? start : at + 1;
      }
    }
  }

  // Keep the highest-priority finding wherever two overlap.
  function resolve(candidates) {
    candidates.sort((a, b) => a.priority - b.priority || a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const accepted = [];
    const overlaps = (s, e) => {
      let lo = 0;
      let hi = accepted.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (accepted[mid].start < s) lo = mid + 1;
        else hi = mid;
      }
      if (lo > 0 && accepted[lo - 1].end > s) return true;
      if (lo < accepted.length && accepted[lo].start < e) return true;
      return false;
    };
    const insert = (f) => {
      let lo = 0;
      let hi = accepted.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (accepted[mid].start < f.start) lo = mid + 1;
        else hi = mid;
      }
      accepted.splice(lo, 0, f);
    };
    for (const f of candidates) if (!overlaps(f.start, f.end)) insert(f);
    return { accepted, overlaps, insert };
  }

  function collect(text, ctx) {
    const detectors = ctx.secretsOnly ? SECRET_DETECTORS : DETECTORS;
    const candidates = [];
    for (const det of detectors) runDetector(det, text, ctx, candidates);
    const allow = new Set((ctx.allowTerms || []).map((t) => t.trim().toLowerCase()).filter(Boolean));
    const kept = allow.size ? candidates.filter((f) => !allow.has(text.slice(f.start, f.end).trim().toLowerCase())) : candidates;
    const { accepted, overlaps, insert } = resolve(kept);
    if (ctx.secretsOnly) return accepted;

    // A whole paste that is one bare value is almost always a credential.
    const trimmed = text.trim();
    if (trimmed && !/\s/.test(trimmed) && trimmed.length >= 8 && trimmed.length <= 512 &&
        !/^[a-z][a-z0-9+.\-]*:\/\//i.test(trimmed) && !/^[\/~\\]|^[A-Za-z]:[\\/]/.test(trimmed) &&
        !/^[A-Za-z_$][\w.\-:]*[:=]/.test(trimmed) && !allow.has(trimmed.toLowerCase())) {
      const s = text.indexOf(trimmed);
      if (!overlaps(s, s + trimmed.length)) {
        insert({
          detector: "lone-value", label: "Single pasted value (treated as a credential)", tag: "SECRET",
          category: "secret", confidence: "medium", context: null, start: s, end: s + trimmed.length, priority: 999
        });
      }
    }

    // Names, usernames and hosts found once are redacted everywhere else too.
    const learned = new Map();
    const learnFrom = new Set(["windows-user-path", "unix-user-path", "shell-prompt", "windows-hostname", "xml-field", "labelled-field"]);
    for (const f of accepted) {
      if (!["USER", "HOST", "NAME"].includes(f.tag) || !learnFrom.has(f.detector)) continue;
      if (f.detector === "labelled-field" && /^(?:user|computer)$/.test(f.context || "")) continue;
      const value = text.slice(f.start, f.end).trim();
      const terms = f.tag === "NAME" ? [value, ...value.split(/\s+/).filter((w) => w.length >= 3)] : [value];
      for (const term of terms) {
        const key = term.toLowerCase();
        if (term.length < (f.tag === "NAME" ? 3 : 4) || COMMON_ACCOUNTS.has(key) || PROSE_WORDS.has(key) ||
            TYPE_WORDS.has(key) || allow.has(key) || learned.has(key)) continue;
        learned.set(key, { term, tag: f.tag, category: f.category, label: f.label });
      }
    }
    for (const { term, tag, category, label } of learned.values()) {
      const re = new RegExp("(?<![\\p{L}\\p{N}_])" + escapeRegex(term) + "(?![\\p{L}\\p{N}_])", "giu");
      let m;
      while ((m = re.exec(text)) !== null) {
        const s = m.index;
        const e = s + m[0].length;
        if (overlaps(s, e)) continue;
        insert({
          detector: "repeat", label: label.replace(/ in a .*$/, "") + " (seen elsewhere in the text)", tag, category,
          confidence: "medium", context: null, start: s, end: e, priority: 1000
        });
      }
    }
    return accepted;
  }

  function lineStarts(text) {
    const starts = [0];
    for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
    return starts;
  }

  function lineOf(starts, offset) {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }

  /**
   * Scan text. Options:
   *   customTerms: strings to always redact (your name, company, hostnames)
   *   allowTerms:  exact values never to flag
   * Returns { findings, groups }. Each group is one distinct value with its
   * placeholder, every place it occurs, and whether it is on by default.
   */
  function scan(text, options) {
    const opts = options || {};
    const ctx = { depth: 0, customTerms: opts.customTerms || [], allowTerms: opts.allowTerms || [] };
    const findings = text ? collect(text, ctx) : [];
    const starts = lineStarts(text || "");
    const counters = new Map();
    const numbers = new Map();
    const groups = new Map();
    for (const f of findings) {
      f.value = text.slice(f.start, f.end);
      const norm = f.category === "secret" ? f.value : f.value.toLowerCase();
      f.key = f.tag + "\u0000" + norm;
      if (!numbers.has(f.key)) {
        const n = (counters.get(f.tag) || 0) + 1;
        counters.set(f.tag, n);
        numbers.set(f.key, n);
      }
      f.placeholder = "[" + f.tag + "-" + numbers.get(f.key) + "]";
      f.line = lineOf(starts, f.start);
      let g = groups.get(f.key);
      if (!g) {
        g = {
          key: f.key, placeholder: f.placeholder, label: f.label, tag: f.tag, category: f.category,
          confidence: f.confidence, context: f.context, value: f.value, count: 0, lines: [], first: f.start
        };
        groups.set(f.key, g);
      } else if (rank(f.confidence) > rank(g.confidence)) {
        g.confidence = f.confidence;
        g.label = f.label;
      }
      g.count += 1;
      if (!g.lines.includes(f.line)) g.lines.push(f.line);
    }
    return { findings, groups: Array.from(groups.values()) };
  }

  function rank(confidence) {
    return confidence === "high" ? 3 : confidence === "medium" ? 2 : 1;
  }

  /**
   * Split text into plain and redacted pieces. isOn(finding) decides whether a
   * finding is replaced; it defaults to every finding that is not low confidence.
   */
  function segments(text, findings, isOn) {
    const on = isOn || ((f) => f.confidence !== "low");
    const out = [];
    let pos = 0;
    for (const f of findings) {
      if (f.start > pos) out.push({ text: text.slice(pos, f.start) });
      const redacted = on(f);
      out.push({ text: redacted ? f.placeholder : f.value, finding: f, redacted });
      pos = f.end;
    }
    if (pos < text.length) out.push({ text: text.slice(pos) });
    return out;
  }

  function redact(text, findings, isOn) {
    return segments(text, findings, isOn).map((s) => s.text).join("");
  }

  return { scan, redact, segments, classifyKey, looksRandom, version: "2.0.0" };
});
