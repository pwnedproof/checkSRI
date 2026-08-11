#!/usr/bin/env node

const { checkSRI } = require('./index.js');
const chalk = require('chalk');

const args = process.argv.slice(2);

function showHelp() {
  console.log(chalk.cyan(`
SRI Detector

Usage:
  sricheck <url>

Options:
  -h, --help              Show help
  -c, --crawl             Crawl same-domain pages
  -d, --depth <number>    Maximum crawl depth
  -f, --filter <domains>  Comma-separated domains to exclude
  --cookies <cookies>     Cookies to send with requests

Examples:
  sricheck https://example.com
  sricheck https://example.com --crawl
  sricheck https://example.com --crawl --depth 2
  sricheck https://example.com --filter cdn.example.com
`));
}

function main() {
  if (
    args.includes('-h') ||
    args.includes('--help')
  ) {
    showHelp();
    return;
  }

  const url = args.find(
    arg => !arg.startsWith('-')
  );

  if (!url) {
    console.error(
      chalk.red('❌ Error: URL is required.')
    );

    console.log(
      chalk.gray('Run: sricheck --help')
    );

    process.exit(1);
  }

  let crawl = false;
  let maxDepth = 2;
  let filter = null;
  let cookies = null;

  if (
    args.includes('-c') ||
    args.includes('--crawl')
  ) {
    crawl = true;
  }

  const depthIndex = args.findIndex(
    arg =>
      arg === '-d' ||
      arg === '--depth'
  );

  if (depthIndex !== -1) {
    const depth = Number(
      args[depthIndex + 1]
    );

    if (
      !Number.isInteger(depth) ||
      depth < 0
    ) {
      console.error(
        chalk.red(
          '❌ Error: depth must be a non-negative integer.'
        )
      );

      process.exit(1);
    }

    maxDepth = depth;
  }

  const filterIndex = args.findIndex(
    arg =>
      arg === '-f' ||
      arg === '--filter'
  );

  if (filterIndex !== -1) {
    filter = args[filterIndex + 1];

    if (!filter) {
      console.error(
        chalk.red(
          '❌ Error: --filter requires a value.'
        )
      );

      process.exit(1);
    }
  }

  const cookiesIndex = args.findIndex(
    arg => arg === '--cookies'
  );

  if (cookiesIndex !== -1) {
    cookies = args[cookiesIndex + 1];

    if (!cookies) {
      console.error(
        chalk.red(
          '❌ Error: --cookies requires a value.'
        )
      );

      process.exit(1);
    }
  }

  try {
    new URL(url);
  } catch {
    console.error(
      chalk.red(`❌ Invalid URL: ${url}`)
    );

    process.exit(1);
  }

  checkSRI(url, {
    crawl,
    maxDepth,
    filter,
    cookies
  }).catch(error => {
    console.error(
      chalk.red(
        `❌ Error: ${error.message}`
      )
    );

    process.exit(1);
  });
}

main();
