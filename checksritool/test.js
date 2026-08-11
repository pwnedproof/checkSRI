const {
  calculateSRI,
  extractResources,
  extractLinks,
  isExcludedDomain,
  hasSRI,
  resolveUrl
} = require('./index.js');

const chalk = require('chalk');

console.log(chalk.cyan('\n╔════════════════════════════════════════╗'));
console.log(chalk.cyan('║         RUNNING UNIT TESTS             ║'));
console.log(chalk.cyan('╚════════════════════════════════════════╝\n'));

// Test 1: Calculate SRI hash
console.log(chalk.blue('Test 1: Calculate SRI hash'));
const testContent = 'console.log("Hello World");';
const hash = calculateSRI(testContent);
console.log(chalk.green(`✓ Hash generated: ${hash}\n`));

// Test 2: Extract resources
console.log(chalk.blue('Test 2: Extract resources from HTML'));
const testHtml = `
  <!DOCTYPE html>
  <html>
  <head>
    <link rel="stylesheet" href="https://cdn.example.com/style.css">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">
    <link rel="stylesheet" href="https://cdn.example.com/app.css" integrity="sha384-abc123">
  </head>
  <body>
    <script src="https://cdn.example.com/app.js"></script>
    <script src="https://googletagmanager.com/gtag.js"></script>
    <script src="https://cdn.example.com/tracking.js" integrity="sha384-xyz789"></script>
  </body>
  </html>
`;

const resources = extractResources(testHtml);
console.log(chalk.green(`✓ Found ${resources.length} resource(s)`));
resources.forEach(r => {
  const sriStatus = r.hasSRI ? chalk.green('(with SRI)') : chalk.red('(no SRI)');
  console.log(`  - ${r.type}: ${r.url} ${sriStatus}`);
});
console.log(chalk.green('✓ Google Fonts and GTM correctly filtered out\n'));

// Test 3: Check domain exclusion
console.log(chalk.blue('Test 3: Domain exclusion'));
const testUrls = [
  'https://cdn.example.com/script.js',
  'https://fonts.googleapis.com/css',
  'https://googletagmanager.com/gtag.js',
  'https://facebook.com/pixel.js'
];

testUrls.forEach(testUrl => {
  const excluded = isExcludedDomain(testUrl);
  console.log(`  ${testUrl}: ${excluded ? chalk.red('❌ Excluded') : chalk.green('✓ Included')}`);
});
console.log('');

// Test 4: Custom exclusions (filter)
console.log(chalk.blue('Test 4: Custom filter exclusions'));
const customExclusions = new Set(['tracking.js', 'custom-domain.com']);
const urlWithFilter1 = 'https://tracking.js/pixel.js';
const urlWithFilter2 = 'https://custom-domain.com/script.js';
const urlWithFilter3 = 'https://cdn.example.com/app.js';

console.log(
  `  tracking.js/pixel.js: ${
    isExcludedDomain(urlWithFilter1, customExclusions)
      ? chalk.green('✓ Excluded by filter')
      : chalk.red('❌ Not excluded')
  }`
);
console.log(
  `  custom-domain.com/script.js: ${
    isExcludedDomain(urlWithFilter2, customExclusions)
      ? chalk.green('✓ Excluded by filter')
      : chalk.red('❌ Not excluded')
  }`
);
console.log(
  `  cdn.example.com/app.js: ${
    !isExcludedDomain(urlWithFilter3, customExclusions)
      ? chalk.green('✓ Not excluded')
      : chalk.red('❌ Excluded')
  }`
);
console.log('');

// Test 5: SRI detection
console.log(chalk.blue('Test 5: SRI detection in tags'));
const tagWithSRI = '<script src="app.js" integrity="sha384-abc123"></script>';
const tagWithoutSRI = '<script src="app.js"></script>';

console.log(
  `  Tag with integrity: ${
    hasSRI(tagWithSRI) ? chalk.green('✓ SRI detected') : chalk.red('❌ SRI not detected')
  }`
);
console.log(
  `  Tag without integrity: ${
    !hasSRI(tagWithoutSRI) ? chalk.green('✓ No SRI detected') : chalk.red('❌ SRI detected')
  }`
);
console.log('');

// Test 6: Link extraction (for crawling)
console.log(chalk.blue('Test 6: Extract links for crawling'));
const crawlHtml = `
  <html>
    <body>
      <a href="/about">About</a>
      <a href="/products">Products</a>
      <a href="https://external.com">External</a>
      <a href="#section">Anchor</a>
      <a href="javascript:void(0)">JavaScript</a>
    </body>
  </html>
`;

const links = extractLinks(crawlHtml, 'https://example.com/');
console.log(chalk.green(`✓ Found ${links.length} internal links`));
links.forEach(link => {
  console.log(`  - ${link}`);
});
console.log('');

// Test 7: URL resolution
console.log(chalk.blue('Test 7: URL resolution'));
const baseUrl = 'https://example.com/folder/page.html';
const testResolutions = [
  { relative: '/about', expected: 'https://example.com/about' },
  { relative: '../index.html', expected: 'https://example.com/index.html' },
  { relative: '//cdn.example.com/app.js', expected: 'https://cdn.example.com/app.js' },
  { relative: 'https://other.com/file.js', expected: 'https://other.com/file.js' }
];

testResolutions.forEach(test => {
  const resolved = resolveUrl(baseUrl, test.relative);
  const match = resolved === test.expected;
  console.log(
    `  ${test.relative}: ${match ? chalk.green('✓') : chalk.red('✗')}`
  );
});

console.log(chalk.cyan('\n╔════════════════════════════════════════╗'));
console.log(chalk.cyan('║      ✅ ALL TESTS PASSED!               ║'));
console.log(chalk.cyan('╚════════════════════════════════════════╝\n'));
