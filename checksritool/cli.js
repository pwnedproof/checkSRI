#!/usr/bin/env node

const { checkSRI } = require('./index.js');
const chalk = require('chalk');

const args = process.argv.slice(2);

if (args.length === 0) {
  console.log(chalk.cyan(`
  ╔════════════════════════════════════════════════════════════════╗
  ║                   SRI DETECTOR - HELP                          ║
  ╚════════════════════════════════════════════════════════════════╝

  ${chalk.white('USAGE:')}
    sricheck <url> [options]

  ${chalk.white('EXAMPLES:')}
    # Basic scan
    sricheck https://example.com

    # Scan with crawling
    sricheck https://example.com --crawl

    # Filter out specific domains
    sricheck https://example.com --filter "cdn.example.com, custom.js"

    # With cookie authentication
    sricheck https://example.com --cookies "session=abc123; user=john"

    # All features combined
    sricheck https://example.com --crawl --depth 3 --filter "tracking.js" --cookies "session=xyz"

  ${chalk.white('OPTIONS:')}
    ${chalk.cyan('-h, --help')}             Show this help menu
    ${chalk.cyan('-c, --crawl')}            Crawl and check all pages on the domain
    ${chalk.cyan('-d, --depth <number>')}   Max crawl depth (default: 2)
    ${chalk.cyan('-f, --filter <domains>')} Exclude domains (comma-separated)
    ${chalk.cyan('--cookies <string>')}     Authentication cookies for private sites

  ${chalk.white('FEATURES:')}
    ✅ Detect resources with/without SRI
    ✅ Crawl entire websites
    ✅ Filter specific domains
    ✅ Cookie-based authentication
    ✅ Beautiful colored output
    ✅ Statistical summary

  ${chalk.white('NOTES:')}
    • Resources from social media, analytics, and fonts are auto-excluded
    • Crawling respects same-origin policy
    • Cookies should be URL-encoded if they contain special characters
  `));
  process.exit(0);
}

// Parse arguments
let url = null;
let crawl = false;
let maxDepth = 2;
let filter = null;
let cookies = null;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];

  if (arg === '-h' || arg === '--help') {
    process.argv.splice(2, args.length);
    process.argv.push();
    require('./cli.js');
  } else if (arg === '-c' || arg === '--crawl') {
    crawl = true;
  } else if (arg === '-d' || arg === '--depth') {
    maxDepth = parseInt(args[++i], 10) || 2;
  } else if (arg === '-f' || arg === '--filter') {
    filter = args[++i];
  } else if (arg === '--cookies' || arg === '--auth') {
    cookies = args[++i];
  } else if (!arg.startsWith('-') && !url) {
    url = arg;
  }
}

if (!url) {
  console.error(chalk.red('❌ URL is required'));
  console.error(chalk.yellow('Run "sricheck --help" for usage information'));
  process.exit(1);
}

if (!url.startsWith('http://') && !url.startsWith('https://')) {
  console.error(chalk.red('❌ URL must start with http:// or https://'));
  process.exit(1);
}

// Run the check
checkSRI(url, {
  crawl,
  maxDepth,
  filter,
  cookies
});
