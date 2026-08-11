
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const chalk = require('chalk');

/*
 * Services that should not be checked for SRI.
 *
 * IMPORTANT:
 * Do NOT exclude general CDN providers such as:
 *   - cdn.jsdelivr.net
 *   - cdnjs.cloudflare.com
 *   - unpkg.com
 *   - code.jquery.com
 *
 * Those are exactly the external resources we want to check.
 */
const EXCLUDED_HOSTS = [
  // Social media
  'facebook.com',
  'twitter.com',
  'x.com',
  'instagram.com',
  'tiktok.com',
  'pinterest.com',
  'linkedin.com',
  'youtube.com',

  // Analytics / tracking
  'google-analytics.com',
  'googletagmanager.com',
  'googleadservices.com',
  'doubleclick.net',
  'googlesyndication.com',
  'connect.facebook.net',

  // Google services that commonly cannot/should not use SRI
  'gstatic.com',
  'googleapis.com'
];

/*
 * Specific URL patterns to exclude.
 *
 * This lets us exclude things like reCAPTCHA without
 * excluding all of google.com.
 */
const EXCLUDED_URL_PATTERNS = [
  /google\.com\/recaptcha/i,
  /google\.com\/maps/i,
  /google\.com\/tagmanager/i,
  /google\.com\/analytics/i,
  /googletagmanager\.com/i,
  /google-analytics\.com/i,
  /connect\.facebook\.net/i,
  /platform\.twitter\.com/i,
  /platform\.linkedin\.com/i
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
 * Fetch a URL and return the raw response body as a Buffer.
 *
 * Redirects are followed automatically.
 */
async function fetchResource(urlString, cookies = null, redirectCount = 0) {
  const MAX_REDIRECTS = 10;

  if (redirectCount > MAX_REDIRECTS) {
    throw new Error('Too many redirects');
  }

  return new Promise((resolve, reject) => {
    let urlObj;

    try {
      urlObj = new URL(urlString);
    } catch {
      reject(new Error(`Invalid URL: ${urlString}`));
      return;
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
        timeout: 15000,
        headers
      },
      (res) => {
        /*
         * Follow HTTP redirects.
         */
        if (
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          const redirectUrl = new URL(
            res.headers.location,
            urlObj
          ).toString();

          res.resume();

          fetchResource(
            redirectUrl,
            cookies,
            redirectCount + 1
          )
            .then(resolve)
            .catch(reject);

          return;
        }

        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();

          reject(
            new Error(
              `HTTP ${res.statusCode} ${res.statusMessage || ''}`.trim()
            )
          );

          return;
        }

        const chunks = [];

        res.on('data', (chunk) => {
          chunks.push(chunk);
        });

        res.on('end', () => {
          resolve({
            body: Buffer.concat(chunks),
            finalUrl: urlObj.toString(),
            contentType: res.headers['content-type'] || ''
          });
        });
      }
    );

    request.setTimeout(15000, () => {
      request.destroy(
        new Error(`Request timed out: ${urlString}`)
      );
    });

    request.on('error', reject);
  });
}

/**
 * Backwards-compatible fetchUrl().
 *
 * Returns text, as older code expects.
 */
async function fetchUrl(urlString, cookies = null) {
  const result = await fetchResource(urlString, cookies);
  return result.body.toString('utf8');
}

/**
 * Calculate an SRI hash.
 *
 * Example:
 *
 * calculateSRI(buffer, 'sha384')
 *
 * returns:
 *
 * sha384-BASE64_HASH
 */
function calculateSRI(content, algorithm = 'sha384') {
  const supportedAlgorithms = ['sha256', 'sha384', 'sha512'];

  if (!supportedAlgorithms.includes(algorithm)) {
    throw new Error(
      `Unsupported SRI algorithm: ${algorithm}`
    );
  }

  const hash = crypto.createHash(algorithm);

  /*
   * IMPORTANT:
   * Hash the exact bytes downloaded from the server.
   */
  hash.update(
    Buffer.isBuffer(content)
      ? content
      : Buffer.from(content)
  );

  return `${algorithm}-${hash.digest('base64')}`;
}

/**
 * Parse integrity attribute.
 *
 * Supports:
 *
 * sha256-...
 * sha384-...
 * sha512-...
 *
 * and multiple hashes.
 */
function parseIntegrity(integrity) {
  if (!integrity || typeof integrity !== 'string') {
    return [];
  }

  return integrity
    .trim()
    .split(/\s+/)
    .filter((token) => {
      return /^(sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}$/i.test(
        token
      );
    });
}

/**
 * Check whether an integrity attribute exists.
 */
function hasSRI(tag) {
  return /\bintegrity\s*=\s*["'][^"']+["']/i.test(tag);
}

/**
 * Extract the integrity attribute from an HTML tag.
 */
function getIntegrity(tag) {
  const match = tag.match(
    /\bintegrity\s*=\s*["']([^"']+)["']/i
  );

  return match ? match[1].trim() : null;
}

/**
 * Extract an attribute from an HTML tag.
 */
function getAttribute(tag, attribute) {
  const regex = new RegExp(
    `\\b${attribute}\\s*=\\s*["']([^"']+)["']`,
    'i'
  );

  const match = tag.match(regex);

  return match ? match[1] : null;
}

/**
 * Determine whether a URL belongs to an excluded service.
 */
function isExcludedDomain(
  urlString,
  customExclusions = new Set()
) {
  try {
    const urlObj = new URL(urlString);
    const hostname = urlObj.hostname.toLowerCase();

    /*
     * Custom exclusions.
     */
    for (const exclusion of customExclusions) {
      const clean = exclusion
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '');

      if (
        hostname === clean ||
        hostname.endsWith(`.${clean}`)
      ) {
        return true;
      }
    }

    /*
     * Host exclusions.
     */
    for (const excludedHost of EXCLUDED_HOSTS) {
      if (
        hostname === excludedHost ||
        hostname.endsWith(`.${excludedHost}`)
      ) {
        return true;
      }
    }

    /*
     * URL-specific exclusions.
     */
    for (const pattern of EXCLUDED_URL_PATTERNS) {
      if (pattern.test(urlObj.toString())) {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}

/**
 * Determine whether a resource is external to the page.
 *
 * Example:
 *
 * Page:
 * https://example.com
 *
 * This is NOT external:
 * https://example.com/js/app.js
 *
 * This IS external:
 * https://cdn.jsdelivr.net/npm/foo.js
 */
function isExternalResource(resourceUrl, pageUrl) {
  try {
    const resource = new URL(resourceUrl);
    const page = new URL(pageUrl);

    /*
     * Compare origins, not just hostnames.
     *
     * This means:
     *
     * https://example.com
     * https://example.com:443
     *
     * are considered the same origin.
     */
    return resource.origin !== page.origin;
  } catch {
    return false;
  }
}

/**
 * Extract external scripts and stylesheets.
 */
function extractResources(
  html,
  customExclusions = new Set(),
  baseUrl = null
) {
  const resources = [];

  /*
   * SCRIPT TAGS
   */
  const scriptRegex = /<script\b[^>]*>/gi;

  let match;

  while ((match = scriptRegex.exec(html)) !== null) {
    const tag = match[0];

    const src = getAttribute(tag, 'src');

    if (!src) {
      continue;
    }

    let absoluteUrl;

    try {
      absoluteUrl = resolveUrl(baseUrl, src);
    } catch {
      continue;
    }

    /*
     * Only external resources.
     */
    if (
      baseUrl &&
      !isExternalResource(absoluteUrl, baseUrl)
    ) {
      continue;
    }

    /*
     * Ignore known services.
     */
    if (
      isExcludedDomain(
        absoluteUrl,
        customExclusions
      )
    ) {
      continue;
    }

    const integrity = getIntegrity(tag);

    resources.push({
      type: 'script',
      url: absoluteUrl,
      tag,
      integrity,
      hasSRI: Boolean(integrity),
      source: baseUrl
    });
  }

  /*
   * STYLESHEETS
   */
  const linkRegex = /<link\b[^>]*>/gi;

  while ((match = linkRegex.exec(html)) !== null) {
    const tag = match[0];

    const rel = getAttribute(tag, 'rel');
    const href = getAttribute(tag, 'href');

    if (!href || !rel) {
      continue;
    }

    /*
     * Only stylesheet links.
     */
    if (!/\bstylesheet\b/i.test(rel)) {
      continue;
    }

    let absoluteUrl;

    try {
      absoluteUrl = resolveUrl(baseUrl, href);
    } catch {
      continue;
    }

    /*
     * Only external resources.
     */
    if (
      baseUrl &&
      !isExternalResource(absoluteUrl, baseUrl)
    ) {
      continue;
    }

    /*
     * Ignore known services.
     */
    if (
      isExcludedDomain(
        absoluteUrl,
        customExclusions
      )
    ) {
      continue;
    }

    const integrity = getIntegrity(tag);

    resources.push({
      type: 'stylesheet',
      url: absoluteUrl,
      tag,
      integrity,
      hasSRI: Boolean(integrity),
      source: baseUrl
    });
  }

  /*
   * Remove duplicates.
   */
  const seen = new Set();

  return resources.filter((resource) => {
    const key = `${resource.type}:${resource.url}`;

    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}

/**
 * Extract same-domain links for crawling.
 */
function extractLinks(html, baseUrl) {
  const links = new Set();

  const linkRegex =
    /\bhref\s*=\s*["']([^"']+)["']/gi;

  let match;

  while ((match = linkRegex.exec(html)) !== null) {
    const link = match[1];

    if (!link) {
      continue;
    }

    if (
      link.startsWith('#') ||
      /^javascript:/i.test(link) ||
      /^mailto:/i.test(link) ||
      /^tel:/i.test(link) ||
      /^data:/i.test(link)
    ) {
      continue;
    }

    try {
      const absoluteUrl = resolveUrl(
        baseUrl,
        link
      );

      const absoluteObj = new URL(absoluteUrl);
      const baseObj = new URL(baseUrl);

      /*
       * Only crawl the same origin.
       */
      if (absoluteObj.origin !== baseObj.origin) {
        continue;
      }

      /*
       * Remove fragments.
       */
      absoluteObj.hash = '';

      links.add(absoluteObj.toString());
    } catch {
      /*
       * Ignore invalid URLs.
       */
    }
  }

  return Array.from(links);
}

/**
 * Resolve relative URLs.
 */
function resolveUrl(baseUrl, relativeUrl) {
  if (!relativeUrl) {
    throw new Error('Empty URL');
  }

  /*
   * Already absolute.
   */
  if (/^https?:\/\//i.test(relativeUrl)) {
    return new URL(relativeUrl).toString();
  }

  /*
   * Protocol-relative.
   */
  if (relativeUrl.startsWith('//')) {
    const base = new URL(baseUrl);

    return `${base.protocol}${relativeUrl}`;
  }

  /*
   * Relative URL.
   */
  return new URL(
    relativeUrl,
    baseUrl
  ).toString();
}

/**
 * Verify the integrity attribute against
 * the actual downloaded resource.
 */
async function verifySRI(resource, cookies = null) {
  if (!resource.integrity) {
    return {
      status: 'missing',
      expected: [],
      actual: []
    };
  }

  const integrityTokens = parseIntegrity(
    resource.integrity
  );

  if (integrityTokens.length === 0) {
    return {
      status: 'invalid',
      expected: resource.integrity,
      actual: [],
      error: 'Invalid SRI format'
    };
  }

  try {
    const result = await fetchResource(
      resource.url,
      cookies
    );

    const actualHashes = [];

    /*
     * Calculate every algorithm declared
     * by the site's integrity attribute.
     */
    for (const token of integrityTokens) {
      const algorithm = token
        .split('-')[0]
        .toLowerCase();

      const calculated = calculateSRI(
        result.body,
        algorithm
      );

      actualHashes.push(calculated);
    }

    /*
     * A resource is valid when ANY valid
     * integrity token matches.
     */
    const valid = integrityTokens.some(
      (expected, index) => {
        return crypto.timingSafeEqual(
          Buffer.from(expected),
          Buffer.from(actualHashes[index])
        );
      }
    );

    return {
      status: valid ? 'valid' : 'invalid',
      expected: integrityTokens,
      actual: actualHashes,
      finalUrl: result.finalUrl
    };
  } catch (error) {
    return {
      status: 'error',
      expected: integrityTokens,
      actual: [],
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

  /*
   * Parse custom exclusions.
   */
  const customExclusions = new Set();

  if (filter) {
    filter
      .split(',')
      .map((domain) => domain.trim().toLowerCase())
      .filter(Boolean)
      .forEach((domain) => {
        customExclusions.add(domain);
      });
  }

  try {
    printTitle();

    const visitedUrls = new Set();
    const resourceMap = new Map();

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

      /*
       * Fetch page.
       */
      console.log(
        chalk.blue(`📥 Fetching ${url}...`)
      );

      let html;

      try {
        html = await fetchUrl(
          url,
          cookies
        );
      } catch (error) {
        console.log(
          chalk.red(
            `   ❌ Error fetching page: ${error.message}`
          )
        );

        continue;
      }

      /*
       * Extract only external resources.
       */
      const resources = extractResources(
        html,
        customExclusions,
        url
      );

      /*
       * Store resources uniquely.
       */
      for (const resource of resources) {
        const key =
          `${resource.type}:${resource.url}`;

        if (!resourceMap.has(key)) {
          resourceMap.set(
            key,
            resource
          );
        }
      }

      /*
       * Crawl same-domain pages.
       */
      if (
        crawl &&
        depth < maxDepth
      ) {
        const links = extractLinks(
          html,
          url
        );

        for (const link of links) {
          if (!visitedUrls.has(link)) {
            urlQueue.push({
              url: link,
              depth: depth + 1
            });
          }
        }
      }
    }

    const allResources =
      Array.from(resourceMap.values());

    /*
     * Verify every external resource.
     */
    const results = [];

    for (const resource of allResources) {
      console.log(
        chalk.gray(
          `Checking ${resource.type}: ${resource.url}`
        )
      );

      const verification =
        await verifySRI(
          resource,
          cookies
        );

      results.push({
        ...resource,
        ...verification
      });
    }

    /*
     * Categorize results.
     */
    const valid = results.filter(
      (resource) =>
        resource.status === 'valid'
    );

    const invalid = results.filter(
      (resource) =>
        resource.status === 'invalid'
    );

    const missing = results.filter(
      (resource) =>
        resource.status === 'missing'
    );

    const errors = results.filter(
      (resource) =>
        resource.status === 'error'
    );

    /*
     * RESULTS
     */
    console.log(
      chalk.cyan(
        '\n╔════════════════════════════════════════╗'
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

    /*
     * VALID
     */
    console.log(
      chalk.green(
        `\n✅ VALID SRI (${valid.length}):`
      )
    );

    console.log(
      chalk.gray('━'.repeat(50))
    );

    if (valid.length === 0) {
      console.log(
        chalk.yellow(
          'No valid SRI resources found.'
        )
      );
    } else {
      valid.forEach((resource) => {
        console.log(
          chalk.green('✓') +
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
    }

    /*
     * INVALID
     */
    console.log(
      chalk.red(
        `\n❌ INVALID SRI (${invalid.length}):`
      )
    );

    console.log(
      chalk.gray('━'.repeat(50))
    );

    if (invalid.length === 0) {
      console.log(
        chalk.green(
          'No invalid SRI hashes found.'
        )
      );
    } else {
      invalid.forEach((resource) => {
        console.log(
          chalk.red('✗') +
          ' ' +
          chalk.cyan(
            resource.type.padEnd(12)
          ) +
          ' ' +
          chalk.white(
            resource.url
          )
        );

        if (resource.expected) {
          console.log(
            chalk.yellow(
              `    Expected: ${Array.isArray(resource.expected)
                ? resource.expected.join(' ')
                : resource.expected}`
            )
          );
        }

        if (resource.actual?.length) {
          console.log(
            chalk.gray(
              `    Calculated: ${resource.actual.join(' ')}`
            )
          );
        }
      });
    }

    /*
     * MISSING
     */
    console.log(
      chalk.yellow(
        `\n⚠️  MISSING SRI (${missing.length}):`
      )
    );

    console.log(
      chalk.gray('━'.repeat(50))
    );

    if (missing.length === 0) {
      console.log(
        chalk.green(
          'All external resources have SRI.'
        )
      );
    } else {
      missing.forEach((resource) => {
        console.log(
          chalk.yellow('!') +
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
    }

    /*
     * ERRORS
     */
    console.log(
      chalk.red(
        `\n🚨 ERRORS (${errors.length}):`
      )
    );

    console.log(
      chalk.gray('━'.repeat(50))
    );

    if (errors.length === 0) {
      console.log(
        chalk.green(
          'No resource errors.'
        )
      );
    } else {
      errors.forEach((resource) => {
        console.log(
          chalk.red('!') +
          ' ' +
          chalk.cyan(
            resource.type.padEnd(12)
          ) +
          ' ' +
          chalk.white(
            resource.url
          ) +
          '\n    ' +
          chalk.red(
            resource.error || 'Unknown error'
          )
        );
      });
    }

    /*
     * STATISTICS
     */
    const total = results.length;

    const coverage =
      total > 0
        ? Math.round(
            (valid.length / total) * 100
          )
        : 0;

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
        String(total).padStart(20)
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.white(
        '║ Valid SRI:         '
      ) +
      chalk.green(
        String(valid.length).padStart(20)
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.white(
        '║ Invalid SRI:       '
      ) +
      chalk.red(
        String(invalid.length).padStart(20)
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.white(
        '║ Missing SRI:       '
      ) +
      chalk.yellow(
        String(missing.length).padStart(20)
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.white(
        '║ Errors:            '
      ) +
      chalk.red(
        String(errors.length).padStart(20)
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.white(
        '║ Valid Coverage:    '
      ) +
      (
        coverage >= 80
          ? chalk.green
          : coverage >= 50
            ? chalk.yellow
            : chalk.red
      )(
        `${coverage}%`.padStart(20)
      ) +
      chalk.white(' ║')
    );

    console.log(
      chalk.cyan(
        '╚════════════════════════════════════════╝\n'
      )
    );

    return {
      resources: results,
      valid,
      invalid,
      missing,
      errors,
      statistics: {
        total,
        valid: valid.length,
        invalid: invalid.length,
        missing: missing.length,
        errors: errors.length,
        coverage
      }
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
  extractResources,
  extractLinks,
  fetchUrl,
  fetchResource,
  isExcludedDomain,
  isExternalResource,
  hasSRI,
  getIntegrity,
  parseIntegrity,
  verifySRI,
  resolveUrl,
  printTitle
};


