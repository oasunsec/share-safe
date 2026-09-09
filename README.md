# ShareSafe

A small local browser tool that checks text before you post it.

## What it checks

- API keys and access tokens
- Private key blocks
- Password-like assignments
- Email addresses
- Local Windows, macOS, and Linux paths

The tool shows the line where a possible match was found and can create a redacted copy.

## Use it

1. Open index.html in a browser.
2. Paste text into the box or choose a local text file.
3. Select Scan text.
4. Copy or download the redacted version before sharing.

There is no build step and no account is needed.

## Privacy

The page does not send text to a server. It has no backend, analytics, or live-secret verification. Text stays in the browser tab unless you copy or download it.

## Limits

This is a pattern checker, not proof that a value is a real credential. It can miss secrets and can flag harmless examples. It does not replace GitHub push protection, Gitleaks, TruffleHog, or a review by a security team.

The first version checks text files. It does not inspect screenshots or scan Git history.

## Why it exists

People often paste logs, tickets, and error messages into public issues or support chats. A quick local check can catch obvious secrets and personal paths before they are shared.
