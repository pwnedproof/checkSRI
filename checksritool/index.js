```javascript
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const chalk = require('chalk');

// Domains to exclude
const EXCLUDED_DOMAINS = [
  'facebook.com',
  'twitter.com',
  'instagram.com',
  'tiktok.com',
  'pinterest.com',
  'linkedin.com',
  'youtube.com',
  'google-analytics.com',
  'googletagmanager.com',
  'google.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'cdn.jsdelivr.net',
  'fonts.google'
];

/**
 * Print ASCII art title
 */
function printTitle() {
  console.log(chalk.cyan(`
  ███████╗██████╗ ██╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
  ██╔════╝██╔══██╗██║    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
  ███████╗██████╔╝██║    ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
  ╚════██║██╔══██╗██║    ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
  ███████║██║  ██║██║    ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
  ╚══════╝╚═╝  ╚═╝╚═╝    ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
  `));
}

/**
 * Fetch URL and return raw bytes.
 *
 * SRI must be calculated from the exact bytes of the resource.
 */
async function fetchUrl(urlString, cookies = null, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    if (redirectCount > 5) {
      return reject(new Error('Too many redirects'));
    }

    let urlObj;

    try {
      urlObj = new URL(urlString);
    } catch {
      return reject(new Error(`Invalid URL: ${urlString}`));
    }

    const protocol = urlObj.protocol === 'https:' ? https : http;

    const headers = {
      'User-Agent': 'SRI-Detector/1.0',
      'Accept': '*/*'
    };

    if (cookies) {
      headers.Cookie = cookies;
    }

    const request = protocol.get(
      urlObj,
      {
        headers,
        timeout: 10000
      },
      (res) => {
        // Follow redirects
        if (
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          const redirectUrl = new URL(
            res.headers.location,
            urlString
          ).toString();

          res.resume();

          return fetchUrl(
            redirectUrl,
            cookies,
            redirectCount + 1
          )
            .then(resolve)
            .catch(reject);
        }

        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();

          return reject(
            new Error(
              `HTTP ${res.statusCode} while fetching ${urlString}`
            )
          );
        }

        const chunks = [];

        res.on('data', (chunk) => {
          chunks.push(chunk);
        });

        res.on('end', () => {
          resolve({
            data: Buffer.concat(chunks),
            url: urlString,
            statusCode: res.statusCode,
            headers: res.headers
          });
        });
      }
    );

    request.on('timeout', () => {
      request.destroy(new Error('Request timeout'));
    });

    request.on('error', reject);
  });
}

/**
 * Calculate an SRI hash.
 *
 * Supported algorithms:
 * sha256
 * sha384
 * sha512
 */
function calculateSRI(content, algorithm = 'sha384') {
  const supportedAlgorithms = [
    'sha256',
    'sha384',
    'sha512'
  ];

  if (!supportedAlgorithms.includes(algorithm)) {
    throw new Error(
      `Unsupported SRI algorithm: ${algorithm}`
    );
  }

  const hash = crypto.createHash(algorithm);

  hash.update(content);

  return `${algorithm}-${hash.digest('base64')}`;
}

/**
 * Extract valid hashes from an integrity attribute.
 *
 * Example:
 *
 * sha384-ABC... sha512-XYZ...
 */
function parseIntegrity(integrity) {
  if (!integrity) {
    return [];
  }

  return integrity
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .filter((value) => {
      return /^(sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}$/.test(
        value
      );
    });
}

/**
 * Verify SRI against the actual resource.
 *
 * If any declared hash matches the actual resource,
 * the SRI is considered valid.
 */
function verifySRI(content, integrity) {
  const declaredHashes = parseIntegrity(integrity);

  if (declaredHashes.length === 0) {
    return {
      valid: false,
      calculated: [],
      matchingHash: null
    };
  }

  const algorithms = [
    ...new Set(
      declaredHashes.map(
        (hash) => hash.split('-')[0]
      )
    )
  ];

  const calculated = algorithms.map(
    (algorithm) =>
      calculateSRI(content, algorithm)
  );

  const matchingHash = declaredHashes.find(
    (hash) => calculated.includes(hash)
  );

  return {
    valid: Boolean(matchingHash),
    calculated,
    matchingHash: matchingHash || null
  };
}

/**
 * Check if a domain should be excluded.
 */
function isExcludedDomain(
  urlString,
  customExclusions = new Set()
) {
  try {
    const urlObj = new URL(urlString);
    const hostname =
      urlObj.hostname.toLowerCase();

    if (customExclusions.has(hostname)) {
      return true;
    }

    return EXCLUDED_DOMAINS.some(
      (excluded) =>
        hostname === excluded ||
        hostname.endsWith(`.${excluded}`)
    );
  } catch {
    return false;
  }
}

/**
 * Get the integrity attribute from an HTML tag.
 */
function getIntegrityAttribute(tag) {
  const match = tag.match(
    /\bintegrity\s*=\s*["']([^"']+)["']/i
  );

  return match ? match[1].trim() : null;
}

/**
 * Check whether a tag has an integrity attribute.
 */
function hasSRI(tag) {
  return Boolean(
    getIntegrityAttribute(tag)
  );
}

/**
 * Extract external scripts and stylesheets.
 */
function extractResources(
  html,
  baseUrl,
  customExclusions = new Set()
) {
  const resources = [];

  let match;

  // Script tags
  const scriptRegex =
    /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;

  while (
    (match = scriptRegex.exec(html)) !== null
  ) {
    const src = match[1];

    try {
      const absoluteUrl = new URL(
        src,
        baseUrl
      ).toString();

      if (
        !isExcludedDomain(
          absoluteUrl,
          customExclusions
        )
      ) {
        resources.push({
          type: 'script',
          url: absoluteUrl,
          tag: match[0],
          integrity:
            getIntegrityAttribute(match[0]),
          hasSRI: hasSRI(match[0])
        });
      }
    } catch {
      // Ignore invalid URLs
    }
  }

  // Stylesheet links
  const linkRegex =
    /<link\b[^>]*\brel\s*=\s*["']stylesheet["'][^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi;

  while (
    (match = linkRegex.exec(html)) !== null
  ) {
    const href = match[1];

    try {
      const absoluteUrl = new URL(
        href,
        baseUrl
      ).toString();

      if (
        !isExcludedDomain(
          absoluteUrl,
          customExclusions
        )
      ) {
        resources.push({
          type: 'stylesheet',
          url: absoluteUrl,
          tag: match[0],
          integrity:
            getIntegrityAttribute(match[0]),
          hasSRI: hasSRI(match[0])
        });
      }
    } catch {
      // Ignore invalid URLs
    }
  }

  return resources;
}

/**
 * Extract same-domain links for crawling.
 */
function extractLinks(html, baseUrl) {
  const links = new Set();

  const linkRegex =
    /href\s*=\s*["']([^"']+)["']/gi;

  let match;

  while (
    (match = linkRegex.exec(html)) !== null
  ) {
    try {
      const link = match[1];

      if (
        !link ||
        link.startsWith('#') ||
        link.startsWith('javascript:') ||
        link.startsWith('mailto:') ||
        link.startsWith('tel:')
      ) {
        continue;
      }

      const absoluteUrl = new URL(
        link,
        baseUrl
      ).toString();

      const absoluteUrlObj =
        new URL(absoluteUrl);

      const baseUrlObj =
        new URL(baseUrl);

      if (
        absoluteUrlObj.hostname ===
        baseUrlObj.hostname
      ) {
        links.add(absoluteUrl);
      }
    } catch {
      // Ignore invalid URLs
    }
  }

  return Array.from(links);
}

/**
 * Resolve a relative URL.
 */
function resolveUrl(
  baseUrl,
  relativeUrl
) {
  return new URL(
    relativeUrl,
    baseUrl
  ).toString();
}

/**
 * Check one resource.
 */
async function checkResourceSRI(
  resource,
  cookies = null
) {
  if (!resource.hasSRI) {
    return {
      ...resource,
      status: 'MISSING',
      valid: false,
      calculated: []
    };
  }

  try {
    const response = await fetchUrl(
      resource.url,
      cookies
    );

    const verification =
      verifySRI(
        response.data,
        resource.integrity
      );

    return {
      ...resource,
      status: verification.valid
        ? 'VALID'
        : 'INVALID',
      valid: verification.valid,
      calculated:
        verification.calculated,
      matchingHash:
        verification.matchingHash
    };
  } catch (error) {
    return {
      ...resource,
      status: 'ERROR',
      valid: false,
      calculated: [],
      error: error.message
    };
  }
}

/**
 * Main SRI checker.
 */
async function checkSRI(
  urlString,
  options = {}
) {
  const {
    crawl = false,
    maxDepth = 2,
    filter = null,
    cookies = null
  } = options;

  const customExclusions = new Set();

  if (filter) {
    filter
      .split(',')
      .forEach((domain) => {
        const cleaned =
          domain.trim().toLowerCase();

        if (cleaned) {
          customExclusions.add(
            cleaned
          );
        }
      });
  }

  try {
    printTitle();

    const visitedUrls = new Set();
    const allResources = [];

    const urlQueue = [
      {
        url: urlString,
        depth: 0
      }
    ];

    while (urlQueue.length > 0) {
      const {
        url,
        depth
      } = urlQueue.shift();

      if (visitedUrls.has(url)) {
        continue;
      }

      visitedUrls.add(url);

      if (
        crawl &&
        depth > maxDepth
      ) {
        continue;
      }

      console.log(
        chalk.blue(
          `\n📥 Fetching ${url}...`
        )
      );

      let response;

      try {
        response = await fetchUrl(
          url,
          cookies
        );
      } catch (error) {
        console.log(
          chalk.red(
            `   ❌ Error fetching: ${error.message}`
          )
        );

        continue;
      }

      const html =
        response.data.toString(
          'utf8'
        );

      const resources =
        extractResources(
          html,
          url,
          customExclusions
        );

      console.log(
        chalk.gray(
          `   Found ${resources.length} external resources`
        )
      );

      for (
        const resource of resources
      ) {
        console.log(
          chalk.gray(
            `   🔍 Checking ${resource.type}: ${resource.url}`
          )
        );

        const result =
          await checkResourceSRI(
            resource,
            cookies
          );

        allResources.push({
          ...result,
          source: url
        });

        if (
          result.status === 'VALID'
        ) {
          console.log(
            chalk.green(
              '      ✓ Valid SRI'
            )
          );
        } else if (
          result.status === 'INVALID'
        ) {
          console.log(
            chalk.red(
              '      ✗ INVALID SRI'
            )
          );

          console.log(
            chalk.gray(
              `      Declared: ${resource.integrity}`
            )
          );

          if (
            result.calculated.length
          ) {
            console.log(
              chalk.yellow(
                `      Actual:   ${result.calculated.join(' ')}`
              )
            );
          }
        } else if (
          result.status === 'MISSING'
        ) {
          console.log(
            chalk.yellow(
              '      ⚠ Missing SRI'
            )
          );
        } else {
          console.log(
            chalk.red(
              `      ❌ ${result.error}`
            )
          );
        }
      }

      // Crawl same-domain pages
      if (
        crawl &&
        depth < maxDepth
      ) {
        const links =
          extractLinks(
            html,
            url
          );

        links.forEach(
          (link) => {
            if (
              !visitedUrls.has(
                link
              )
            ) {
              urlQueue.push({
                url: link,
                depth:
                  depth + 1
              });
            }
          }
        );
      }
    }

    // Results
    const valid =
      allResources.filter(
        (r) =>
          r.status === 'VALID'
      );

    const invalid =
      allResources.filter(
        (r) =>
          r.status === 'INVALID'
      );

    const missing =
      allResources.filter(
        (r) =>
          r.status === 'MISSING'
      );

    const errors =
      allResources.filter(
        (r) =>
          r.status === 'ERROR'
      );

    // Results summary
    console.log(
      chalk.cyan(
        '\n\n╔════════════════════════════════════════╗'
      )
    );

    console.log(
      chalk.cyan(
        '║          RESULTS SUMMARY              ║'
      )
    );

    console.log(
      chalk.cyan(
        '╚════════════════════════════════════════╝'
      )
    );

    // VALID
    console.log(
      chalk.green(
        `\n✅ VALID SRI (${valid.length}):`
      )
    );

    console.log(
      chalk.gray(
        '━'.repeat(50)
      )
    );

    if (valid.length === 0) {
      console.log(
        chalk.gray(
          '   None found.'
        )
      );
    } else {
      valid
        .slice(0, 10)
        .forEach(
          (resource) => {
            console.log(
              chalk.green(
                '   ✓'
              ) +
              ' ' +
              chalk.cyan(
                resource.type.padEnd(
                  12
                )
              ) +
              ' ' +
              chalk.white(
                resource.url
              )
            );
          }
        );
    }

    // INVALID
    console.log(
      chalk.red(
        `\n❌ INVALID SRI (${invalid.length}):`
      )
    );

    console.log(
      chalk.gray(
        '━'.repeat(50)
      )
    );

    if (invalid.length === 0) {
      console.log(
        chalk.green(
          '   None found.'
        )
      );
    } else {
      invalid
        .slice(0, 10)
        .forEach(
          (resource) => {
            console.log(
              chalk.red(
                '   ✗'
              ) +
              ' ' +
              chalk.cyan(
                resource.type.padEnd(
                  12
                )
              ) +
              ' ' +
              chalk.white(
                resource.url
              )
            );

            console.log(
              chalk.gray(
                `      Declared: ${resource.integrity}`
              )
            );

            if (
              resource.calculated
                .length > 0
            ) {
              console.log(
                chalk.yellow(
                  `      Actual:   ${resource.calculated.join(' ')}`
                )
              );
            }
          }
        );
    }

    // MISSING
    console.log(
      chalk.yellow(
        `\n⚠️  MISSING SRI (${missing.length}):`
      )
    );

    console.log(
      chalk.gray(
        '━'.repeat(50)
      )
    );

    if (missing.length === 0) {
      console.log(
        chalk.green(
          '   None found.'
        )
      );
    } else {
      missing
        .slice(0, 10)
        .forEach(
          (resource) => {
            console.log(
              chalk.yellow(
                '   !'
              ) +
              ' ' +
              chalk.cyan(
                resource.type.padEnd(
                  12
                )
              ) +
              ' ' +
              chalk.white(
                resource.url
              )
            );
          }
        );
    }

    // ERRORS
    if (errors.length > 0) {
      console.log(
        chalk.red(
          `\n🚨 ERRORS (${errors.length}):`
        )
      );

      console.log(
        chalk.gray(
          '━'.repeat(50)
        )
      );

      errors
        .slice(0, 10)
        .forEach(
          (resource) => {
            console.log(
              chalk.red(
                '   ✗'
              ) +
              ' ' +
              chalk.cyan(
                resource.type.padEnd(
                  12
                )
              ) +
              ' ' +
              chalk.white(
                resource.url
              )
            );

            console.log(
              chalk.gray(
                `      ${resource.error}`
              )
            );
          }
        );
    }

    // Statistics
    console.log(
      chalk.cyan(
        '\n╔════════════════════════════════════════╗'
      )
    );

    console.log(
      chalk.cyan(
        '║              STATISTICS               ║'
      )
    );

    console.log(
      chalk.cyan(
        '╠════════════════════════════════════════╣'
      )
    );

    console.log(
      chalk.white(
        '║ Total Resources:    '
      ) +
      chalk.yellow(
        String(
          allResources.length
        ).padStart(17)
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.white(
        '║ Valid SRI:          '
      ) +
      chalk.green(
        String(
          valid.length
        ).padStart(17)
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.white(
        '║ Invalid SRI:        '
      ) +
      chalk.red(
        String(
          invalid.length
        ).padStart(17)
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.white(
        '║ Missing SRI:        '
      ) +
      chalk.yellow(
        String(
          missing.length
        ).padStart(17)
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.white(
        '║ Errors:             '
      ) +
      chalk.red(
        String(
          errors.length
        ).padStart(17)
      ) +
      chalk.white(' ║')
    );

    // SRI coverage
    const coverage =
      allResources.length > 0
        ? Math.round(
            ((valid.length +
              invalid.length) /
              allResources.length) *
              100
          )
        : 0;

    console.log(
      chalk.white(
        '║ SRI Coverage:       '
      ) +
      (
        coverage >= 80
          ? chalk.green
          : coverage >= 50
            ? chalk.yellow
            : chalk.red
      )(
        `${coverage}%`.padStart(
          17
        )
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.cyan(
        '╚════════════════════════════════════════╝\n'
      )
    );

    return {
      total: allResources.length,
      valid: valid.length,
      invalid: invalid.length,
      missing: missing.length,
      errors: errors.length,
      coverage,
      resources: allResources
    };
  } catch (error) {
    console.error(
      chalk.red(
        `\n❌ Error: ${error.message}`
      )
    );

    throw error;
  }
}

module.exports = {
  checkSRI,
  calculateSRI,
  verifySRI,
  parseIntegrity,
  extractResources,
  extractLinks,
  fetchUrl,
  isExcludedDomain,
  hasSRI,
  getIntegrityAttribute,
  resolveUrl,
  checkResourceSRI,
  printTitle
};
```

