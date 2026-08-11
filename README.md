# checkSRI

A simple command-line tool for checking whether external JavaScript and CSS resources on a website use **Subresource Integrity (SRI)**.

The tool scans the HTML of a website, identifies external JavaScript and stylesheet resources, and separates them into:

* **WITH SRI** — the HTML resource contains an `integrity` attribute.
* **NO SRI** — the HTML resource does not contain an `integrity` attribute.

> Only scan websites you own or are authorized to test.

---

## Requirements

* Kali Linux
* Git
* Node.js
* npm

Check whether they are installed:

```bash
git --version
node --version
npm --version
```

---

# Download / Install

Clone the repository:

```bash
cd ~
git clone https://github.com/pwnedproof/checkSRI.git
```

Enter the project:

```bash
cd ~/checkSRI/checksritool
```

Install the Node.js dependencies:

```bash
npm install
```

---

# Run the Tool

From the `checksritool` directory:

```bash
node cli.js https://example.com
```

For example:

```bash
node cli.js https://www.mynamsa.org
```

Do **not** include Markdown formatting such as:

```text
[https://example.com](https://example.com)
```

Use:

```bash
node cli.js https://example.com
```
# Show help
sricheck --help

# Basic scan
sricheck https://example.com

# With crawling
sricheck https://example.com --crawl

# Crawl 5 levels deep
sricheck https://example.com -c -d 5

# Filter domains
sricheck https://example.com -f "tracking.js, analytics"

# Authentication
sricheck https://private.site.com --cookies "session=xyz"

# Everything together
sricheck https://example.com -c -d 3 -f "internal-*" --cookies "auth=token"
---

# Example Output

The tool separates resources into two sections.

```text
========================================
              WITH SRI
========================================

[+] SCRIPT: https://example.com/script.js
[+] STYLESHEET: https://example.com/style.css

Total with SRI: 2


========================================
               NO SRI
========================================

[-] SCRIPT: https://cdn.example.com/library.js
[-] SCRIPT: https://cdn.example.com/app.js

Total without SRI: 2


========================================
                 SUMMARY
========================================
Total resources: 4
With SRI:        2
Without SRI:     2
========================================
```

### WITH SRI

A resource is placed in this section when its HTML tag contains an `integrity` attribute.

Example:

```html
<script
    src="https://example.com/script.js"
    integrity="sha384-example">
</script>
```

### NO SRI

A resource is placed in this section when its HTML tag does not contain an `integrity` attribute.

Example:

```html
<script src="https://example.com/script.js"></script>
```

---

# Update the Tool

If you originally downloaded the repository using `git clone`, update it with:

```bash
cd ~/checkSRI
git pull
```

Then update Node.js dependencies:

```bash
cd ~/checkSRI/checksritool
npm install
```

Run the updated version:

```bash
node cli.js https://example.com
```

## Check Your Current Version

To see whether your local repository has changes:

```bash
cd ~/checkSRI
git status
```

You can also check the latest commits:

```bash
git log --oneline -5
```

---

# If You Modified Files Locally

If you have made your own changes to `index.js` or other files, `git pull` may refuse to update.

Check:

```bash
cd ~/checkSRI
git status
```

If you want to keep your local changes:

```bash
git stash
git pull
git stash pop
```

If you **do not** need your local changes and want your Kali copy to exactly match GitHub:

```bash
git reset --hard
git pull
```

> `git reset --hard` deletes uncommitted local changes. Make sure you do not need them first.

---

# Delete / Uninstall

## Remove the cloned repository

If you want to completely delete the downloaded tool:

```bash
rm -rf ~/checkSRI
```

This removes the entire repository from your Kali machine.

You can confirm:

```bash
ls ~/checkSRI
```

You should get:

```text
No such file or directory
```

---

# If You Installed It Globally

If you previously ran:

```bash
sudo npm install -g .
```

you may also have installed the `sricheck` command globally.

Remove the global package with:

```bash
sudo npm uninstall -g checksritool
```

Then remove the repository:

```bash
rm -rf ~/checkSRI
```

If you are unsure of the global package name, check:

```bash
npm list -g --depth=0
```

---

# Reinstall From Scratch

If something becomes corrupted, the easiest solution is to remove the old copy and clone it again:

```bash
rm -rf ~/checkSRI
```

Then:

```bash
cd ~
git clone https://github.com/pwnedproof/checkSRI.git
cd ~/checkSRI/checksritool
npm install
```

Run:

```bash
node cli.js https://example.com
```

---

# Project Structure

The important files are:

```text
checkSRI/
└── checksritool/
    ├── cli.js
    ├── index.js
    ├── package.json
    └── package-lock.json
```

### `cli.js`

Command-line entry point.

### `index.js`

Contains the SRI scanning logic.

It:

1. Fetches the target webpage.
2. Finds external JavaScript resources.
3. Finds external CSS resources.
4. Checks whether each resource has an `integrity` attribute.
5. Separates resources into `WITH SRI` and `NO SRI`.

### `package.json`

Contains the Node.js project configuration and dependencies.

### `package-lock.json`

Locks dependency versions used by npm.

---

# Troubleshooting

## Check JavaScript syntax

If Node reports a `SyntaxError`:

```bash
cd ~/checkSRI/checksritool
node --check index.js
```

No output means the file passed the syntax check.

---

## Check Node.js

```bash
node --version
```

If Node.js is missing:

```bash
sudo apt update
sudo apt install -y nodejs npm
```

---

## Reinstall dependencies

If you encounter dependency errors:

```bash
cd ~/checkSRI/checksritool
rm -rf node_modules
npm install
```

Then:

```bash
node cli.js https://example.com
```

---

# Important Notes

The tool checks whether the page's HTML contains an `integrity` attribute.

It does **not** currently verify that an existing SRI hash matches the downloaded resource.

For example:

```html
<script src="script.js" integrity="sha384-..."></script>
```

is classified as:

```text
WITH SRI
```

while:

```html
<script src="script.js"></script>
```

is classified as:

```text
NO SRI
```

The tool also excludes several common domains such as social-media, analytics, Google, and font domains according to the exclusion list in `index.js`.

---

# Quick Commands

### Install

```bash
cd ~
git clone https://github.com/pwnedproof/checkSRI.git
cd ~/checkSRI/checksritool
npm install
```

### Run

```bash
node cli.js https://example.com
```

### Update

```bash
cd ~/checkSRI
git pull
cd checksritool
npm install
```

### Syntax check

```bash
cd ~/checkSRI/checksritool
node --check index.js
```

### Delete

```bash
rm -rf ~/checkSRI
```

### Reinstall

```bash
rm -rf ~/checkSRI
git clone https://github.com/pwnedproof/checkSRI.git
cd ~/checkSRI/checksritool
npm install
```

---

## Legal / Responsible Use

Use this tool only against websites and systems you own or have explicit permission to test.

The tool is intended for SRI configuration auditing and educational/security testing.
