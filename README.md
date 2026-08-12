#  checkSRI

**A fast CLI tool for detecting missing and invalid Subresource Integrity (SRI) on websites.**

checkSRI scans external JavaScript and CSS resources and verifies whether their `integrity` attributes correctly match the resources being loaded.

```text
   ███████╗██████╗██╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
  ██╔════╝██╔══██╗██║    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
  ███████╗██████╔╝██║    ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
  ╚════██║██╔══██╗██║    ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
  ███████║██║  ██║██║    ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
  ╚══════╝╚═╝  ╚═╝╚═╝    ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

---

## Features

*  Detect missing SRI attributes
* ✅ Validate existing SRI hashes
* ❌ Detect incorrect or outdated SRI hashes
*  Check JavaScript resources
* Check external CSS stylesheets
*  Crawl same-domain pages
*  Display scan statistics
*  Exclude unwanted domains
*  Support authenticated pages using cookies
*  Simple command-line interface
*  Works on Kali Linux and other Node.js environments

---

##  Installation

### Requirements

* Node.js 14+
* npm
* Git

### Clone

```bash
git clone https://github.com/pwnedproof/checkSRI.git
cd checkSRI/checksritool
```

### Install dependencies

```bash
npm install
```

### Install globally

Install the `sricheck` command:

```bash
sudo npm install -g .
```

Verify:

```bash
sricheck --help
```

---

#  Usage

Basic scan:

```bash
sricheck https://example.com
```

Example:

```bash
sricheck https://www.example.com
```

---

##  Help

```bash
sricheck --help
```

Output:

```text
SRI Detector

Usage:
  sricheck <url>

Options:
  -h, --help              Show help
  -c, --crawl             Crawl same-domain pages
  -d, --depth <number>    Maximum crawl depth
  -f, --filter <domains>  Comma-separated domains to exclude
  --cookies <cookies>     Cookies to send with requests
```

---

#  Scan a Website

```bash
sricheck https://example.com
```

checkSRI looks for external:

```html
<script src="https://cdn.example.com/app.js"></script>
```

and:

```html
<link rel="stylesheet" href="https://cdn.example.com/style.css">
```

resources.

It then checks their SRI configuration.

---

#  SRI Results

### ✅ VALID

The resource contains an SRI hash and the hash matches the downloaded resource.

```text
✅ VALID
```

### ❌ INVALID

The resource contains an SRI hash, but the hash does not match the downloaded resource.

```text
❌ INVALID
```

This can happen when a resource has changed but its SRI hash was not updated.

### ⚠️ MISSING

The resource does not contain an `integrity` attribute.

```text
⚠️ MISSING
```

### 🚨 ERROR

The resource could not be downloaded or validated.

```text
🚨 ERROR
```

---

#  Crawl a Website

Scan the starting page and additional same-domain pages:

```bash
sricheck https://example.com --crawl
```

Short form:

```bash
sricheck https://example.com -c
```

---

## Crawl Depth

Set the maximum crawl depth:

```bash
sricheck https://example.com --crawl --depth 3
```

Short form:

```bash
sricheck https://example.com -c -d 3
```

Example:

```text
Depth 0
└── Homepage

Depth 1
├── About
├── Contact
└── Services

Depth 2
├── Services/Web
├── Services/Security
└── Contact/Team
```

Higher depths may result in more pages being scanned.

---

#  Exclude Domains

Exclude specific domains from the scan:

```bash
sricheck https://example.com --filter "analytics.example.com"
```

Multiple domains can be supplied:

```bash
sricheck https://example.com \
  --filter "analytics.example.com,tracking.example.com"
```

---

#  Authenticated Websites

For websites requiring an authenticated session, cookies can be supplied:

```bash
sricheck https://example.com \
  --cookies "session=YOUR_SESSION_COOKIE"
```

Multiple cookies:

```bash
sricheck https://example.com \
  --cookies "session=abc123; user=john"
```


---

#  Example

```text
SRI Detector

📥 Fetching https://example.com...

╔════════════════════════════════════════╗
║          RESULTS SUMMARY               ║
╚════════════════════════════════════════╝

✅ VALID (8)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ✓ script       https://cdn.example.com/app.js
   ✓ stylesheet   https://cdn.example.com/style.css

❌ INVALID (1)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ✗ script       https://cdn.example.com/old.js

⚠️ MISSING (3)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ! script       https://cdn.example.com/vendor.js

🚨 ERROR (0)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

╔════════════════════════════════════════╗
║              STATISTICS                ║
╠════════════════════════════════════════╣
║ Total Resources:                    12 ║
║ Valid:                               8 ║
║ Invalid:                             1 ║
║ Missing:                             3 ║
║ Errors:                              0 ║
╚════════════════════════════════════════╝
```

---

#  Why SRI?

Subresource Integrity allows browsers to verify that externally hosted resources have not been unexpectedly modified.

Example:

```html
<script
  src="https://cdn.example.com/app.js"
  integrity="sha384-..."
  crossorigin="anonymous">
</script>
```

If the downloaded resource does not match the declared hash, the browser can prevent the resource from being executed or applied.

checkSRI helps identify resources that:

* Have no SRI protection
* Have an incorrect SRI hash
* Have an outdated SRI hash
* Need their integrity value updated

---

#  Development

Run directly without global installation:

```bash
node cli.js https://example.com
```

Show help:

```bash
node cli.js --help
```

Run tests:

```bash
npm test
```

Check syntax:

```bash
node --check index.js
node --check cli.js
```

---

#  Update

Update the repository:

```bash
cd ~/checkSRI
git pull
```

Update dependencies:

```bash
cd checksritool
npm install
```

Reinstall the global CLI:

```bash
sudo npm install -g .
```

Verify:

```bash
sricheck --help
```

---

#  Uninstall

Remove the globally installed CLI:

```bash
sudo npm uninstall -g sri-detector
```

Remove the repository:

```bash
rm -rf ~/checkSRI
```



---

#  Responsible Use

Only scan websites and systems that you own or have explicit permission to test.

Do not use checkSRI to bypass authentication, access controls, or other security mechanisms.

The author is not responsible for misuse of this tool.

---

#  License

See LISENCE for further details

---

# ⭐ Support

If you find checkSRI useful:

* ⭐ Star the repository
* 🐛 Report bugs
* 💡 Suggest improvements
* 🔧 Submit pull requests

## GitHub

https://github.com/pwnedproof/checkSRI

---

**checkSRI : Find missing SRI. Validate what exists. Secure your resources.**

