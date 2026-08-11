const https = require('https');
const http = require('http');
const crypto = require('crypto');
const chalk = require('chalk');

// Domains to exclude by default
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
 * Fetch URL and return the exact response bytes.
 *
 * SRI hashes must be calculated against the exact bytes
 * downloaded from the resource.
 */
async function fetchUrl(urlString, cookies = null) {
  return new Promise((resolve, reject) => {
    let protocol;

    try {
      protocol = new URL(urlString).protocol === 'https:'
        ? https
        : http;
    } catch {
      reject(new Error(`Invalid URL: ${urlString}`));
      return;
    }

    const options = {
      timeout: 10000,
      headers: {
        'User-Agent': 'SRI-Detector/1.0',
        'Accept': '*/*'
      }
    };

    if (cookies) {
      options.headers.Cookie = cookies;
    }

    const request = protocol.get(urlString, options, (res) => {
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

        fetchUrl(redirectUrl, cookies)
          .then(resolve)
          .catch(reject);

        return;
      }

      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();

        reject(
          new Error(
            `HTTP ${res.statusCode} while fetching ${urlString}`
          )
        );

        return;
      }

      const chunks = [];

      res.on('data', (chunk) => {
        chunks.push(chunk);
      });

      res.on('end', () => {
        resolve(Buffer.concat(chunks));
      });
    });

    request.setTimeout(10000, () => {
      request.destroy(
        new Error(`Request timed out: ${urlString}`)
      );
    });

    request.on('error', reject);
  });
}

/**
 * Calculate an SRI hash.
 *
 * Supported:
 *   sha256
 *   sha384
 *   sha512
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
 * Parse an integrity attribute.
 *
 * Example:
 *
 * sha256-ABC sha384-DEF sha512-GHI
 */
function parseIntegrity(integrity) {
  if (!integrity || typeof integrity !== 'string') {
    return [];
  }

  return integrity
    .trim()
    .split(/\s+/)
    .map((entry) => {
      const separator = entry.indexOf('-');

      if (separator === -1) {
        return null;
      }

      const algorithm = entry
        .slice(0, separator)
        .toLowerCase();

      const hash = entry.slice(separator + 1);

      if (
        !['sha256', 'sha384', 'sha512'].includes(algorithm)
      ) {
        return null;
      }

      if (!hash) {
        return null;
      }

      return {
        algorithm,
        hash
      };
    })
    .filter(Boolean);
}

/**
 * Extract the integrity attribute from an HTML tag.
 */
function getIntegrityAttribute(tag) {
  if (!tag) {
    return null;
  }

  const match = tag.match(
    /\bintegrity\s*=\s*["']([^"']+)["']/i
  );

  return match ? match[1].trim() : null;
}

/**
 * Check whether a tag contains an integrity attribute.
 */
function hasSRI(tag) {
  return getIntegrityAttribute(tag) !== null;
}

/**
 * Verify a downloaded resource against its SRI attribute.
 */
function verifySRI(content, integrity) {
  const hashes = parseIntegrity(integrity);

  if (hashes.length === 0) {
    return {
      valid: false,
      matchingHash: null,
      calculatedHashes: {}
    };
  }

  const calculatedHashes = {};

  for (const item of hashes) {
    const calculated = calculateSRI(
      content,
      item.algorithm
    );

    calculatedHashes[item.algorithm] = calculated;

    const expected = `${item.algorithm}-${item.hash}`;

    const expectedBuffer = Buffer.from(expected);
    const actualBuffer = Buffer.from(calculated);

    if (
      expectedBuffer.length === actualBuffer.length &&
      crypto.timingSafeEqual(
        expectedBuffer,
        actualBuffer
      )
    ) {
      return {
        valid: true,
        matchingHash: calculated,
        calculatedHashes
      };
    }
  }

  return {
    valid: false,
    matchingHash: null,
    calculatedHashes
  };
}

/**
 * Check whether a domain should be excluded.
 */
function isExcludedDomain(
  urlString,
  customExclusions = new Set()
) {
  try {
    const hostname = new URL(urlString)
      .hostname
      .toLowerCase();

    // Custom exclusions
    for (const excluded of customExclusions) {
      if (
        hostname === excluded ||
        hostname.endsWith(`.${excluded}`)
      ) {
        return true;
      }
    }

    // Default exclusions
    return EXCLUDED_DOMAINS.some((excluded) => {
      return (
        hostname === excluded ||
        hostname.endsWith(`.${excluded}`)
      );
    });
  } catch {
    return false;
  }
}

/**
 * Resolve a relative URL against a base URL.
 */
function resolveUrl(baseUrl, relativeUrl) {
  try {
    return new URL(
      relativeUrl,
      baseUrl
    ).toString();
  } catch {
    return relativeUrl;
  }
}

/**
 * Determine whether a resource is hosted externally.
 *
 * Example:
 *
 * Page:
 *   https://example.com
 *
 * Internal:
 *   https://example.com/app.js
 *
 * External:
 *   https://cdn.example.net/app.js
 *
 * Subdomains are considered external because they have
 * a different hostname:
 *
 *   example.com
 *   cdn.example.com
 */
function isExternalResource(resourceUrl, pageUrl) {
  try {
    const resourceHostname = new URL(resourceUrl)
      .hostname
      .toLowerCase();

    const pageHostname = new URL(pageUrl)
      .hostname
      .toLowerCase();

    return resourceHostname !== pageHostname;
  } catch {
    return false;
  }
}

/**
 * Extract external JavaScript and CSS resources.
 *
 * IMPORTANT:
 * Only resources hosted on a different hostname from
 * the page being scanned are returned.
 */
function extractResources(
  html,
  customExclusions = new Set(),
  baseUrl = null
) {
  const resources = [];

  if (!html) {
    return resources;
  }

  if (!baseUrl) {
    return resources;
  }

  /**
   * Add a resource if it is external and not excluded.
   */
  function addResource(
    type,
    originalUrl,
    tag
  ) {
    if (!originalUrl) {
      return;
    }

    const absoluteUrl = resolveUrl(
      baseUrl,
      originalUrl
    );

    if (!absoluteUrl) {
      return;
    }

    // Ignore same-host resources
    if (
      !isExternalResource(
        absoluteUrl,
        baseUrl
      )
    ) {
      return;
    }

    // Ignore excluded domains
    if (
      isExcludedDomain(
        absoluteUrl,
        customExclusions
      )
    ) {
      return;
    }

    const integrity =
      getIntegrityAttribute(tag);

    resources.push({
      type,
      url: absoluteUrl,
      originalUrl,
      tag,
      integrity,
      hasSRI: integrity !== null,
      status: integrity !== null
        ? 'pending'
        : 'missing'
    });
  }

  // External JavaScript
  const scriptRegex =
    /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;

  let match;

  while (
    (match = scriptRegex.exec(html)) !== null
  ) {
    addResource(
      'script',
      match[1],
      match[0]
    );
  }

  // External stylesheets
  const linkRegex =
    /<link\b[^>]*\brel\s*=\s*["']stylesheet["'][^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi;

  while (
    (match = linkRegex.exec(html)) !== null
  ) {
    addResource(
      'stylesheet',
      match[1],
      match[0]
    );
  }

  return resources;
}

/**
 * Extract same-host links for crawling.
 */
function extractLinks(html, baseUrl) {
  const links = new Set();

  const linkRegex =
    /\bhref\s*=\s*["']([^"']+)["']/gi;

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

      const absoluteUrl =
        resolveUrl(baseUrl, link);

      const absolute = new URL(
        absoluteUrl
      );

      const base = new URL(
        baseUrl
      );

      // Crawl only the exact same hostname
      if (
        absolute.hostname.toLowerCase() ===
        base.hostname.toLowerCase()
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
 * Download and verify one external resource.
 */
async function checkResourceSRI(
  resource,
  cookies = null
) {
  // No integrity attribute
  if (!resource.hasSRI) {
    return {
      ...resource,
      status: 'missing',
      valid: false,
      calculatedHashes: {},
      matchingHash: null,
      error: null
    };
  }

  try {
    const content = await fetchUrl(
      resource.url,
      cookies
    );

    const result = verifySRI(
      content,
      resource.integrity
    );

    return {
      ...resource,
      status: result.valid
        ? 'valid'
        : 'invalid',
      valid: result.valid,
      matchingHash: result.matchingHash,
      calculatedHashes:
        result.calculatedHashes,
      error: null
    };
  } catch (error) {
    return {
      ...resource,
      status: 'error',
      valid: false,
      matchingHash: null,
      calculatedHashes: {},
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

  // Validate starting URL
  let startingUrl;

  try {
    startingUrl = new URL(
      urlString
    ).toString();
  } catch {
    throw new Error(
      `Invalid URL: ${urlString}`
    );
  }

  // Custom exclusions
  const customExclusions = new Set();

  if (filter) {
    filter
      .split(',')
      .map((domain) =>
        domain.trim().toLowerCase()
      )
      .filter(Boolean)
      .forEach((domain) => {
        customExclusions.add(domain);
      });
  }

  try {
    printTitle();

    const visitedUrls = new Set();
    const allResources = [];

    const urlQueue = [
      {
        url: startingUrl,
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

      try {
        console.log(
          chalk.blue(
            `\n📥 Fetching ${url}...`
          )
        );

        const htmlBuffer =
          await fetchUrl(
            url,
            cookies
          );

        const html =
          htmlBuffer.toString('utf8');

        /*
         * IMPORTANT:
         *
         * Pass the current page URL to extractResources().
         * This allows it to remove same-host resources.
         */
        const resources =
          extractResources(
            html,
            customExclusions,
            url
          );

        for (const resource of resources) {
          console.log(
            chalk.gray(
              `   Checking ${resource.type}: ${resource.url}`
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
        }

        // Crawl same-host pages
        if (
          crawl &&
          depth < maxDepth
        ) {
          const links =
            extractLinks(
              html,
              url
            );

          for (const link of links) {
            if (
              !visitedUrls.has(link)
            ) {
              urlQueue.push({
                url: link,
                depth: depth + 1
              });
            }
          }
        }
      } catch (error) {
        console.log(
          chalk.red(
            `   ❌ Error fetching: ${error.message}`
          )
        );
      }
    }

    // Organize results
    const valid =
      allResources.filter(
        (resource) =>
          resource.status === 'valid'
      );

    const invalid =
      allResources.filter(
        (resource) =>
          resource.status === 'invalid'
      );

    const missing =
      allResources.filter(
        (resource) =>
          resource.status === 'missing'
      );

    const errors =
      allResources.filter(
        (resource) =>
          resource.status === 'error'
      );

    // ========================================
    // RESULTS SUMMARY
    // ========================================

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
          '   No valid SRI resources found.'
        )
      );
    } else {
      valid
        .slice(0, 20)
        .forEach((resource) => {
          console.log(
            chalk.green('   ✓') +
            ' ' +
            chalk.cyan(
              resource.type.padEnd(12)
            ) +
            ' ' +
            chalk.white(
              resource.url
            )
          );
        });

      if (valid.length > 20) {
        console.log(
          chalk.gray(
            `   ... and ${valid.length - 20} more`
          )
        );
      }
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
          '   No invalid SRI hashes found.'
        )
      );
    } else {
      invalid
        .slice(0, 20)
        .forEach((resource) => {
          console.log(
            chalk.red('   ✗') +
            ' ' +
            chalk.cyan(
              resource.type.padEnd(12)
            ) +
            ' ' +
            chalk.white(
              resource.url
            )
          );

          if (resource.integrity) {
            console.log(
              chalk.yellow(
                `      Declared: ${resource.integrity}`
              )
            );
          }

          const calculated =
            Object.values(
              resource.calculatedHashes
            );

          if (calculated.length > 0) {
            console.log(
              chalk.magenta(
                `      Actual:   ${calculated.join(', ')}`
              )
            );
          }
        });

      if (invalid.length > 20) {
        console.log(
          chalk.gray(
            `   ... and ${invalid.length - 20} more`
          )
        );
      }
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
          '   All external resources have SRI.'
        )
      );
    } else {
      missing
        .slice(0, 20)
        .forEach((resource) => {
          console.log(
            chalk.yellow('   !') +
            ' ' +
            chalk.cyan(
              resource.type.padEnd(12)
            ) +
            ' ' +
            chalk.white(
              resource.url
            )
          );
        });

      if (missing.length > 20) {
        console.log(
          chalk.gray(
            `   ... and ${missing.length - 20} more`
          )
        );
      }
    }

    // ERRORS
    console.log(
      chalk.magenta(
        `\n🚨 ERRORS (${errors.length}):`
      )
    );

    console.log(
      chalk.gray(
        '━'.repeat(50)
      )
    );

    if (errors.length === 0) {
      console.log(
        chalk.green(
          '   No resource errors.'
        )
      );
    } else {
      errors
        .slice(0, 20)
        .forEach((resource) => {
          console.log(
            chalk.magenta('   !') +
            ' ' +
            chalk.cyan(
              resource.type.padEnd(12)
            ) +
            ' ' +
            chalk.white(
              resource.url
            )
          );

          console.log(
            '      ' +
            chalk.red(
              resource.error
            )
          );
        });

      if (errors.length > 20) {
        console.log(
          chalk.gray(
            `   ... and ${errors.length - 20} more`
          )
        );
      }
    }

    // ========================================
    // STATISTICS
    // ========================================

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
        '║ Total External:    '
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
        '║ Valid SRI:         '
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
        '║ Invalid SRI:       '
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
        '║ Missing SRI:       '
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
        '║ Errors:            '
      ) +
      chalk.magenta(
        String(
          errors.length
        ).padStart(17)
      ) +
      chalk.white(' ║')
    );

    const percentage =
      allResources.length > 0
        ? Math.round(
            (valid.length /
              allResources.length) *
              100
          )
        : 0;

    const coverageColor =
      percentage >= 80
        ? chalk.green
        : percentage >= 50
          ? chalk.yellow
          : chalk.red;

    console.log(
      chalk.white(
        '║ Valid Coverage:    '
      ) +
      coverageColor(
        `${percentage}%`.padStart(17)
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.cyan(
        '╚════════════════════════════════════════╝\n'
      )
    );

    // Recommendations
    if (invalid.length > 0) {
      console.log(
        chalk.red(
          '\n🚨 Action required: invalid SRI hashes were found.'
        )
      );

      console.log(
        chalk.gray(
          '   The declared integrity hash does not match the downloaded resource.'
        )
      );
    }

    if (missing.length > 0) {
      console.log(
        chalk.yellow(
          '\n💡 Tip: External resources without SRI should be reviewed and protected with an appropriate integrity hash.'
        )
      );
    }

    return {
      total: allResources.length,
      valid: valid.length,
      invalid: invalid.length,
      missing: missing.length,
      errors: errors.length,
      coverage: percentage,
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
  checkResourceSRI,
  verifySRI,
  calculateSRI,
  parseIntegrity,
  getIntegrityAttribute,
  extractResources,
  extractLinks,
  fetchUrl,
  isExcludedDomain,
  hasSRI,
  resolveUrl,
  isExternalResource,
  printTitle
};

