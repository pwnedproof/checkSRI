#!/usr/bin/env node

const { checkSRI } = require('./index.js');

const args = process.argv.slice(2);

if (args.length === 0) {
  console.log(`
  SRI Detector - Generate Subresource Integrity hashes for external resources
  
  Usage: sricheck <url>
  
  Example: sricheck https://example.com
  
  Features:
  - Extracts all external script and stylesheet resources
  - Automatically excludes: social media, analytics, Google Tag Manager, and fonts
  - Generates SHA-384 SRI hashes
  - Shows ready-to-use HTML with integrity attributes
  `);
  process.exit(0);
}

const url = args[0];

if (!url.startsWith('http://') && !url.startsWith('https://')) {
  console.error('❌ URL must start with http:// or https://');
  process.exit(1);
}

checkSRI(url);