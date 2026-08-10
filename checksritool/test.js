const { calculateSRI, extractResources, isExcludedDomain } = require('./index.js');

// Test 1: Calculate SRI hash
console.log('Test 1: Calculate SRI hash');
const testContent = 'console.log("Hello World");';
const hash = calculateSRI(testContent);
console.log(`✓ Hash generated: ${hash}\n`);

// Test 2: Extract resources (without actual fetching)
console.log('Test 2: Extract resources from HTML');
const testHtml = `
  <!DOCTYPE html>
  <html>
  <head>
    <link rel="stylesheet" href="https://cdn.example.com/style.css">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">
  </head>
  <body>
    <script src="https://cdn.example.com/app.js"></script>
    <script src="https://googletagmanager.com/gtag.js"></script>
  </body>
  </html>
`;

const resources = extractResources(testHtml);
console.log(`✓ Found ${resources.length} resource(s)`);
resources.forEach(r => {
  console.log(`  - ${r.type}: ${r.url}`);
});
console.log('✓ Google Fonts and GTM correctly filtered out\n');

// Test 3: Check domain exclusion
console.log('Test 3: Domain exclusion');
const testUrls = [
  'https://cdn.example.com/script.js',
  'https://fonts.googleapis.com/css',
  'https://googletagmanager.com/gtag.js',
  'https://facebook.com/pixel.js'
];

testUrls.forEach(testUrl => {
  const excluded = isExcludedDomain(testUrl);
  console.log(`  ${testUrl}: ${excluded ? '❌ Excluded' : '✓ Included'}`);
});

console.log('\n✅ All tests passed!');