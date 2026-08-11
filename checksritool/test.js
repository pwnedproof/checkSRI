
const assert = require('assert');
const crypto = require('crypto');

const {
  calculateSRI,
  verifySRI,
  parseIntegrity,
  hasSRI,
  getIntegrityAttribute,
  resolveUrl
} = require('./index.js');

console.log('Running SRI tests...\n');

// --------------------------------------------------
// calculateSRI
// --------------------------------------------------

const content = Buffer.from(
  'console.log("hello");',
  'utf8'
);

const expectedHash =
  'sha384-' +
  crypto
    .createHash('sha384')
    .update(content)
    .digest('base64');

assert.strictEqual(
  calculateSRI(content, 'sha384'),
  expectedHash
);

console.log('✓ calculateSRI works');

// --------------------------------------------------
// parseIntegrity
// --------------------------------------------------

const integrity =
  'sha384-ABC123 sha512-XYZ789';

const parsed =
  parseIntegrity(integrity);

assert.strictEqual(
  parsed.length,
  2
);

console.log('✓ parseIntegrity works');

// --------------------------------------------------
// verifySRI - valid
// --------------------------------------------------

const validIntegrity =
  calculateSRI(content, 'sha384');

const validResult =
  verifySRI(
    content,
    validIntegrity
  );

assert.strictEqual(
  validResult.valid,
  true
);

assert.strictEqual(
  validResult.matchingHash,
  validIntegrity
);

console.log('✓ valid SRI is detected');

// --------------------------------------------------
// verifySRI - invalid
// --------------------------------------------------

const invalidIntegrity =
  'sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const invalidResult =
  verifySRI(
    content,
    invalidIntegrity
  );

assert.strictEqual(
  invalidResult.valid,
  false
);

console.log('✓ invalid SRI is detected');

// --------------------------------------------------
// verifySRI - multiple hashes
// --------------------------------------------------

const sha256 =
  calculateSRI(content, 'sha256');

const sha384 =
  calculateSRI(content, 'sha384');

const multipleResult =
  verifySRI(
    content,
    `${sha256} ${sha384}`
  );

assert.strictEqual(
  multipleResult.valid,
  true
);

console.log(
  '✓ multiple SRI hashes are supported'
);

// --------------------------------------------------
// hasSRI
// --------------------------------------------------

const tagWithSRI =
  '<script src="app.js" integrity="sha384-ABC"></script>';

const tagWithoutSRI =
  '<script src="app.js"></script>';

assert.strictEqual(
  hasSRI(tagWithSRI),
  true
);

assert.strictEqual(
  hasSRI(tagWithoutSRI),
  false
);

console.log('✓ hasSRI works');

// --------------------------------------------------
// getIntegrityAttribute
// --------------------------------------------------

assert.strictEqual(
  getIntegrityAttribute(
    '<script src="app.js" integrity="sha384-ABC"></script>'
  ),
  'sha384-ABC'
);

assert.strictEqual(
  getIntegrityAttribute(
    '<script src="app.js"></script>'
  ),
  null
);

console.log(
  '✓ getIntegrityAttribute works'
);

// --------------------------------------------------
// resolveUrl
// --------------------------------------------------

assert.strictEqual(
  resolveUrl(
    'https://example.com/page/',
    '/js/app.js'
  ),
  'https://example.com/js/app.js'
);

assert.strictEqual(
  resolveUrl(
    'https://example.com/page/',
    'app.js'
  ),
  'https://example.com/page/app.js'
);

console.log('✓ resolveUrl works');

// --------------------------------------------------

console.log(
  '\n✅ All tests passed!'
);


