# Quick Start Guide

## Installation

### Option 1: Global Install (Recommended)
```bash
npm install -g sri-detector
sricheck https://example.com
```

### Option 2: Local Install
```bash
git clone https://github.com/yourusername/sri-detector.git
cd sri-detector
npm install
node cli.js https://example.com
```

## What It Does

Given a website URL, sri-detector will:

1. **Fetch the HTML** from that URL
2. **Extract all external resources** (scripts and stylesheets)
3. **Filter out unwanted resources** (Google Fonts, Analytics, Social Media, GTM)
4. **Generate SHA-384 hashes** for each resource
5. **Show you the ready-to-use HTML** with integrity attributes

## Example Usage

```bash
$ sricheck https://mywebsite.com

📥 Fetching https://mywebsite.com...

Found 3 resource(s):

📄 SCRIPT: https://cdn.example.com/app.js
   SRI: sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4K8mkZL
   HTML: <script src="https://cdn.example.com/app.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4K8mkZL">

📄 STYLESHEET: https://cdn.example.com/style.css
   SRI: sha384-k3zGyvapOgLookyWPrAVo5AoYQJjSX/7pHJlcTcwUdZBBk5+Jy5NKVxZGKl6zOgY
   HTML: <link href="https://cdn.example.com/style.css" integrity="sha384-k3zGyvapOgLookyWPrAVo5AoYQJjSX/7pHJlcTcwUdZBBk5+Jy5NKVxZGKl6zOgY">

📄 SCRIPT: https://cdn.example.com/tracking.js
   SRI: sha384-xyz123...
   HTML: <script src="https://cdn.example.com/tracking.js" integrity="sha384-xyz123...">
```

## Excluded by Default

The tool automatically filters out:
- ❌ Google Tag Manager
- ❌ Google Analytics  
- ❌ Facebook Pixel
- ❌ Google Fonts
- ❌ Social media embed scripts
- ❌ Other common analytics platforms

## Use in Your HTML

Copy the generated HTML snippets directly into your code:

```html
<script 
  src="https://cdn.example.com/app.js" 
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4K8mkZL"
  crossorigin="anonymous"
></script>
```

The `crossorigin="anonymous"` attribute is recommended for maximum security.

## Testing

```bash
npm test
```

This runs local tests without needing to fetch real URLs.

## Need Help?

```bash
sricheck
```

Run without arguments to see the help menu.

## Security Best Practices

1. **Always use with `crossorigin="anonymous"`** on script/link tags
2. **Regenerate SRI hashes** when you update your dependencies
3. **SRI only protects third-party resources** - your own domain's files can't use SRI
4. **Keep this tool updated** to ensure you have the latest security best practices

## Troubleshooting

**"Cannot fetch URL"** - The website might be blocking requests or offline. Try a different URL.

**"No resources found"** - The website might not have any external resources, or they're all filtered out (analytics/fonts/etc).

**"Error fetching resource"** - The individual CDN resource might be temporarily unavailable.