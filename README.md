# ShareSafe

A browser tool that redacts secrets and personal data from logs, tickets, config files and chats before you paste them somewhere public.

Try it: [oasunsec.github.io/share-safe](https://oasunsec.github.io/share-safe/)

## What it finds

**Secrets and credentials**
- 53 key and token formats: OpenAI, Anthropic, OpenRouter, Google, AWS, Azure AD and DevOps, GitHub, GitLab, Slack, Discord, Teams, Stripe, Twilio, SendGrid, npm, PyPI, Hugging Face, NVIDIA, Groq, Vault, Docker Hub, JWTs, private key blocks and more
- Keys with no known prefix, by how random they look
- Values assigned to secret-looking names in env files, JSON, YAML, XML, CLI flags, PowerShell, connection strings and URL query strings (`sig=`, `token=`)
- Passwords in URLs (`postgres://user:pass@host`), `Authorization` headers, `curl -u`, and cookies
- Secrets written in sentences, such as "my password is …" or "the API key: …"
- Secrets hidden inside base64
- A single value pasted on its own, which is treated as a credential

**Personal data**
- Labelled fields: name, SSN, national ID and BVN, tax ID, passport, driver's license, date of birth, phone, address, medical and insurance IDs, username
- Email addresses and phone numbers
- Usernames in Windows and Unix paths and shell prompts, which are then redacted everywhere else they appear in the text

**Financial:** card numbers (Luhn-checked), IBANs (checksum-checked), account numbers, CVV and PIN fields

**Network and infrastructure:** internal and public IPs, IPv6, MAC addresses, internal hostnames, Windows computer names, and Azure and AWS resource names. Documentation, loopback and multicast addresses are skipped.

## How redaction works

Each value is replaced with a numbered placeholder such as `[EMAIL-1]` or `[OPENAI-KEY-2]`. The same value always gets the same placeholder, so the redacted log still shows that two lines refer to the same user or key. Only the value is replaced. `api_key = …` stays readable as `api_key = [SECRET-1]`.

Every finding has a confidence level. High and medium matches are redacted by default. Low-confidence matches, such as file hashes and GUIDs, are listed but left in until you tick them. You can untick anything you want to keep, and the page tells you how many unticked items will be shared as-is.

Under **Your terms and settings** you can add words to always redact (your name, company, server names) and exact values that should never be flagged. These lists are saved in your browser only.

## Privacy

The page has no backend and no analytics. Its Content-Security-Policy blocks all network requests (`connect-src 'none'`), so nothing you paste can be sent anywhere. It does not check whether a key is live.

## Use it

1. Open the [live page](https://oasunsec.github.io/share-safe/), or open `index.html` from a local copy.
2. Paste text or drop a file. It is checked as you type.
3. Review the findings and untick anything that is safe to share.
4. Copy or download the redacted copy.

## Tests

The detection engine is in `scanner.js` and has no dependencies. The tests need Node 18 or later:

```bash
node --test
```

They cover each key format, secrets with and without labels, personal data, checksums, placeholder numbering, and a set of ordinary logs, source code and security writing that must produce no findings.

## Limits

Detection is pattern-based. It cannot know that a plain word is your password unless the text says so, and it can flag test data or sample values as real. Add anything the patterns miss to **Always redact**, and read the redacted copy before you share it.
