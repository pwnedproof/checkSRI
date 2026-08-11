#!/usr/bin/env node

const path = require('path');
const chalk = require('chalk');

// Resolve index.js relative to the installed package,
// rather than relative to /usr/local/bin/sricheck.
const { checkSRI } = require(
  path.join(__dirname, '..', 'lib', 'index.js')
);

const args = process.argv.slice(2);

function showHelp() {
  console.log(chalk.cyan(`
SRI Detector

Usage:
  sricheck <url>

Options:
  -h, --help              Show this help message
  -c, --crawl             Crawl same-domain pages
  -d, --depth <number>    Maximum crawl depth
  -f, --filter <domains>  Comma-separated domains to exclude
  --cookies <cookies>     Cookies to send with requests

Examples:
  sricheck https://example.com
  sricheck https://example.com --crawl
  sricheck https://example.com --crawl --depth 2
  sricheck https://example.com --filter example.com
`));
}

function parseArgs(args) {
  const options = {
    crawl: false,
    maxDepth: 2,
    filter: null,
    cookies: null
  };

  let url = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '-h' || arg === '--help') {
      showHelp();
      process.exit(0);
    }

    if (arg === '-c' || arg === '--crawl') {
      options.crawl = true;
      continue;
    }

    if (arg === '-d' || arg === '--depth') {
      const depth = Number(args[++i]);

      if (!Number.isInteger(depth) || depth < 0) {
        console.error(
          chalk.red('Error: depth must be a non-negative integer.')
        );
        process.exit(1);
      }

      options.maxDepth = depth;
      continue;
    }

    if (arg === '-f' || arg === '--filter') {
      options.filter = args[++i];

      if (!options.filter) {
        console.error(
          chalk.red('Error: --filter requires a value.')
        );
        process.exit(1);
      }

      continue;
    }

    if (arg === '--cookies') {
      options.cookies = args[++i];

      if (!options.cookies) {
        console.error(
          chalk.red('Error: --cookies requires a value.')
        );
        process.exit(1);
      }

      continue;
    }

    if (!arg.startsWith('-') && !url) {
      url = arg;
      continue;
    }

    console.error(
      chalk.red(`Unknown argument: ${arg}`)
    );

    console.log(
      chalk.gray('Run "sricheck --help" for usage.')
    );

    process.exit(1);
  }

  if (!url) {
    showHelp();
    process.exit(1);
  }

  return {
    url,
    options
  };
}

async function main() {
  try {
    const { url, options } = parseArgs(args);

    // Validate URL
    try {
      new URL(url);
    } catch {
      console.error(
        chalk.red(`Invalid URL: ${url}`)
      );
      process.exit(1);
    }

    await checkSRI(url, options);
  } catch (error) {
    console.error(
      chalk.red(`\n❌ ${error.message}`)
    );

    process.exit(1);
  }
}

main();
