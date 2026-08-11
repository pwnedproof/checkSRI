
#!/usr/bin/env node

const { checkSRI } = require('./index.js');
const chalk = require('chalk');

const args = process.argv.slice(2);

function showHelp() {
  console.log(chalk.cyan(`
╔════════════════════════════════════════════════════════════════╗
║                       SRI CHECK                               ║
╚════════════════════════════════════════════════════════════════╝

USAGE:

  sricheck <url> [options]

EXAMPLES:

  sricheck https://example.com

  sricheck https://example.com --crawl

  sricheck https://example.com --crawl --depth 3

  sricheck https://example.com --filter "analytics.com"

  sricheck https://example.com --cookies "session=abc123"

OPTIONS:

  -h, --help
      Show this help menu

  -c, --crawl
      Crawl same-domain pages

  -d, --depth <number>
      Maximum crawl depth
      Default: 2

  -f, --filter <domains>
      Exclude domains
      Comma-separated list

  --cookies <string>
      Cookies for authenticated websites

RESULTS:

  ✅ VALID
      Integrity attribute exists and the
      calculated hash matches the resource.

  ❌ INVALID
      Integrity attribute exists but the
      calculated hash does not match.

  ⚠️  MISSING
      Resource does not contain an integrity attribute.

  🚨 ERROR
      Resource could not be downloaded or checked.
`));
}

if (
  args.includes('-h') ||
  args.includes('--help')
) {
  showHelp();
  process.exit(0);
}

if (args.length === 0) {
  showHelp();
  process.exit(1);
}

let url = null;
let crawl = false;
let maxDepth = 2;
let filter = null;
let cookies = null;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];

  if (arg === '-c' || arg === '--crawl') {
    crawl = true;
    continue;
  }

  if (arg === '-d' || arg === '--depth') {
    const value = args[++i];

    if (!value) {
      console.error(
        chalk.red('❌ --depth requires a number')
      );
      process.exit(1);
    }

    maxDepth = parseInt(value, 10);

    if (
      Number.isNaN(maxDepth) ||
      maxDepth < 0
    ) {
      console.error(
        chalk.red(
          '❌ Depth must be a non-negative number'
        )
      );
      process.exit(1);
    }

    continue;
  }

  if (arg === '-f' || arg === '--filter') {
    filter = args[++i];

    if (!filter) {
      console.error(
        chalk.red(
          '❌ --filter requires domains'
        )
      );
      process.exit(1);
    }

    continue;
  }

  if (
    arg === '--cookies' ||
    arg === '--auth'
  ) {
    cookies = args[++i];

    if (!cookies) {
      console.error(
        chalk.red(
          '❌ --cookies requires a value'
        )
      );
      process.exit(1);
    }

    continue;
  }

  if (!arg.startsWith('-') && !url) {
    url = arg;
    continue;
  }

  if (arg.startsWith('-')) {
    console.error(
      chalk.red(
        `❌ Unknown option: ${arg}`
      )
    );

    console.error(
      chalk.yellow(
        'Run "sricheck --help" for usage.'
      )
    );

    process.exit(1);
  }
}

if (!url) {
  console.error(
    chalk.red('❌ URL is required')
  );

  console.error(
    chalk.yellow(
      'Run "sricheck --help" for usage.'
    )
  );

  process.exit(1);
}

if (
  !url.startsWith('http://') &&
  !url.startsWith('https://')
) {
  console.error(
    chalk.red(
      '❌ URL must start with http:// or https://'
    )
  );

  process.exit(1);
}

checkSRI(url, {
  crawl,
  maxDepth,
  filter,
  cookies
}).catch((error) => {
  console.error(
    chalk.red(
      `❌ ${error.message}`
    )
  );

  process.exit(1);
});

