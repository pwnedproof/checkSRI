
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const chalk = require('chalk');

/*
 * Domains/services that should NOT be checked.
 *
 * These are generally services where SRI is not practical or
 * where the resource is dynamically generated.
 */
const EXCLUDED_DOMAINS = [
  // Social media
  'facebook.com',
  'twitter.com',
  'x.com',
  'instagram.com',
  'tiktok.com',
  'pinterest.com',
  'linkedin.com',
  'youtube.com',

  // Google / analytics / tracking
  'google.com',
  'googleapis.com',
  'google-analytics.com',
  'googletagmanager.com',
  'googleadservices.com',
  'googlesyndication.com',
  'gstatic.com',

  // reCAPTCHA
  'recaptcha.net',
  'www.google.com/recaptcha',

  // Fonts
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'fonts.google.com',

  // Common analytics / tracking
  'doubleclick.net',
  'facebook.net',
  'connect.facebook.net',
  'hotjar.com',
  'clarity.ms',

  // Common dynamic/security services
  'incapsula.com',
  'imperva.com',

  // Known dynamic/CDN resources where SRI is generally not useful
  'cdn.jsdelivr.net'
];

/*
 * Print title
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

/*
 * Fetch URL.
 *
 * Returns a Buffer because SRI hashes must be calculated
 * from the exact bytes downloaded.
 */
async function fetchUrl(urlString, cookies = null) {
  return new Promise((resolve, reject) => {
    let parsedUrl;

    try {
      parsedUrl = new URL(urlString);
    } catch (error) {
      reject(new Error(`Invalid URL: ${urlString}`));
      return;
    }

    const protocol = parsedUrl.protocol === 'https:' ? https : http;

    const headers = {
      'User-Agent': 'SRI-Detector/1.0'
    };

    if (cookies) {
      headers.Cookie = cookies;
    }

    const options = {
      timeout: 15000,
      headers
    };

    const request = protocol.get(urlString, options, (res) => {
      const chunks = [];

      res.on('data', (chunk) => {
        chunks.push(chunk);
      });

      res.on('end', () => {
        const body = Buffer.concat(chunks);

        resolve({
          body,
          statusCode: res.statusCode,
          headers: res.headers,
          finalUrl: res.headers.location || urlString
        });
      });
    });

    request.on('timeout', () => {
      request.destroy(new Error('Request timed out'));
    });

    request.on('error', reject);
  });
}

/*
 * Calculate SRI hash from exact downloaded bytes.
 */
function calculateSRI(content, algorithm = 'sha384') {
  const hash = crypto.createHash(algorithm);

  if (Buffer.isBuffer(content)) {
    hash.update(content);
  } else {
    hash.update(Buffer.from(content));
  }

  return `${algorithm}-${hash.digest('base64')}`;
}

/*
 * Parse an integrity attribute.
 *
 * Supports:
 *
 * sha256-...
 * sha384-...
 * sha512-...
 *
 * and multiple hashes:
 *
 * sha384-... sha512-...
 */
function parseIntegrity(integrity) {
  if (!integrity || typeof integrity !== 'string') {
    return [];
  }

  return integrity
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map(value => {
      const separator = value.indexOf('-');

      if (separator === -1) {
        return null;
      }

      const algorithm = value.slice(0, separator).toLowerCase();
      const digest = value.slice(separator + 1);

      if (!['sha256', 'sha384', 'sha512'].includes(algorithm)) {
        return null;
      }

      return {
        algorithm,
        digest,
        value
      };
    })
    .filter(Boolean);
}

/*
 * Determine whether a URL belongs to an excluded service.
 */
function isExcludedDomain(urlString, customExclusions = new Set()) {
  try {
    const urlObj = new URL(urlString);
    const hostname = urlObj.hostname.toLowerCase();

    for (const exclusion of customExclusions) {
      const clean = exclusion
        .replace(/^https?:\/\//i, '')
        .split('/')[0]
        .toLowerCase()
        .trim();

      if (
        hostname === clean ||
        hostname.endsWith(`.${clean}`)
      ) {
        return true;
      }
    }

    return EXCLUDED_DOMAINS.some(excluded => {
      const clean = excluded
        .replace(/^https?:\/\//i, '')
        .toLowerCase();

      return (
        hostname === clean ||
        hostname.endsWith(`.${clean}`)
      );
    });
  } catch {
    return false;
  }
}

/*
 * Normalize URL for deduplication.
 */
function normalizeUrl(urlString) {
  try {
    const url = new URL(urlString);

    // Remove fragments.
    url.hash = '';

    // Remove default ports.
    if (
      (url.protocol === 'https:' && url.port === '443') ||
      (url.protocol === 'http:' && url.port === '80')
    ) {
      url.port = '';
    }

    // Remove trailing slash except root.
    if (url.pathname.length > 1) {
      url.pathname = url.pathname.replace(/\/+$/, '');
    }

    return url.toString();
  } catch {
    return urlString;
  }
}

/*
 * Check whether resource is external to the website being scanned.
 */
function isExternalResource(resourceUrl, pageUrl) {
  try {
    const resource = new URL(resourceUrl);
    const page = new URL(pageUrl);

    return resource.hostname.toLowerCase() !== page.hostname.toLowerCase();
  } catch {
    return false;
  }
}

/*
 * Get integrity attribute from an HTML tag.
 */
function getIntegrity(tag) {
  const match = tag.match(
    /\bintegrity\s*=\s*["']([^"']+)["']/i
  );

  return match ? match[1].trim() : null;
}

/*
 * Check whether tag has SRI.
 */
function hasSRI(tag) {
  return Boolean(getIntegrity(tag));
}

/*
 * Extract external resources.
 *
 * IMPORTANT:
 * Resources hosted on the same domain are ignored.
 *
 * Example:
 *
 * https://example.com/js/app.js
 *
 * will NOT be checked when scanning:
 *
 * https://example.com
 *
 * But:
 *
 * https://cdnjs.cloudflare.com/...
 *
 * will be checked.
 */
function extractResources(
  html,
  pageUrl,
  customExclusions = new Set()
) {
  const resources = [];

  /*
   * SCRIPT TAGS
   */
  const scriptRegex = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;

  let match;

  while ((match = scriptRegex.exec(html)) !== null) {
    const src = match[1];

    try {
      const absoluteUrl = normalizeUrl(
        new URL(src, pageUrl).toString()
      );

      if (!isExternalResource(absoluteUrl, pageUrl)) {
        continue;
      }

      if (isExcludedDomain(absoluteUrl, customExclusions)) {
        continue;
      }

      resources.push({
        type: 'script',
        url: absoluteUrl,
        tag: match[0],
        integrity: getIntegrity(match[0]),
        hasSRI: hasSRI(match[0])
      });
    } catch {
      // Ignore invalid URLs.
    }
  }

  /*
   * STYLESHEETS
   */
  const linkRegex = /<link\b[^>]*\brel\s*=\s*["']([^"']+)["'][^>]*>/gi;

  while ((match = linkRegex.exec(html)) !== null) {
    const tag = match[0];
    const rel = match[1].toLowerCase();

    if (!rel.split(/\s+/).includes('stylesheet')) {
      continue;
    }

    const hrefMatch = tag.match(
      /\bhref\s*=\s*["']([^"']+)["']/i
    );

    if (!hrefMatch) {
      continue;
    }

    const href = hrefMatch[1];

    try {
      const absoluteUrl = normalizeUrl(
        new URL(href, pageUrl).toString()
      );

      if (!isExternalResource(absoluteUrl, pageUrl)) {
        continue;
      }

      if (isExcludedDomain(absoluteUrl, customExclusions)) {
        continue;
      }

      resources.push({
        type: 'stylesheet',
        url: absoluteUrl,
        tag,
        integrity: getIntegrity(tag),
        hasSRI: hasSRI(tag)
      });
    } catch {
      // Ignore invalid URLs.
    }
  }

  return resources;
}

/*
 * Extract same-domain links for crawling.
 */
function extractLinks(html, baseUrl) {
  const links = new Set();

  const linkRegex = /\bhref\s*=\s*["']([^"']+)["']/gi;

  let match;

  while ((match = linkRegex.exec(html)) !== null) {
    const rawLink = match[1].trim();

    if (
      !rawLink ||
      rawLink.startsWith('#') ||
      rawLink.startsWith('javascript:') ||
      rawLink.startsWith('mailto:') ||
      rawLink.startsWith('tel:') ||
      rawLink.startsWith('data:')
    ) {
      continue;
    }

    try {
      const absoluteUrl = normalizeUrl(
        new URL(rawLink, baseUrl).toString()
      );

      const absoluteObj = new URL(absoluteUrl);
      const baseObj = new URL(baseUrl);

      /*
       * Only crawl HTTP(S).
       */
      if (
        absoluteObj.protocol !== 'http:' &&
        absoluteObj.protocol !== 'https:'
      ) {
        continue;
      }

      /*
       * Only crawl same hostname.
       */
      if (
        absoluteObj.hostname.toLowerCase() !==
        baseObj.hostname.toLowerCase()
      ) {
        continue;
      }

      links.add(absoluteUrl);
    } catch {
      // Ignore invalid links.
    }
  }

  return Array.from(links);
}

/*
 * Resolve relative URLs.
 */
function resolveUrl(baseUrl, relativeUrl) {
  try {
    return new URL(relativeUrl, baseUrl).toString();
  } catch {
    return relativeUrl;
  }
}

/*
 * Validate the SRI hash against downloaded content.
 */
async function validateSRI(resource) {
  try {
    const response = await fetchUrl(resource.url);

    if (
      !response.statusCode ||
      response.statusCode < 200 ||
      response.statusCode >= 400
    ) {
      return {
        status: 'error',
        error: `HTTP ${response.statusCode || 'unknown'}`
      };
    }

    if (!resource.integrity) {
      return {
        status: 'missing'
      };
    }

    const hashes = parseIntegrity(resource.integrity);

    if (hashes.length === 0) {
      return {
        status: 'invalid',
        error: 'Invalid or unsupported integrity attribute'
      };
    }

    for (const hash of hashes) {
      const calculated = calculateSRI(
        response.body,
        hash.algorithm
      );

      if (calculated === hash.value) {
        return {
          status: 'valid',
          matchedHash: calculated
        };
      }
    }

    return {
      status: 'invalid',
      error: 'SRI hash does not match downloaded resource'
    };
  } catch (error) {
    return {
      status: 'error',
      error: error.message
    };
  }
}

/*
 * Main SRI checker.
 */
async function checkSRI(urlString, options = {}) {
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
      .map(domain => domain.trim().toLowerCase())
      .filter(Boolean)
      .forEach(domain => customExclusions.add(domain));
  }

  printTitle();

  let startingUrl;

  try {
    startingUrl = normalizeUrl(urlString);
    new URL(startingUrl);
  } catch {
    console.error(chalk.red(`\n❌ Invalid URL: ${urlString}`));
    return;
  }

  /*
   * Page crawler state.
   */
  const visitedPages = new Set();
  const queuedPages = new Set([startingUrl]);

  const urlQueue = [
    {
      url: startingUrl,
      depth: 0
    }
  ];

  /*
   * Resource deduplication.
   *
   * The same external JS/CSS can appear on many pages.
   * We only check it once.
   */
  const resourceMap = new Map();

  let deepestDepthReached = 0;

  while (urlQueue.length > 0) {
    const current = urlQueue.shift();

    const pageUrl = current.url;
    const depth = current.depth;

    if (visitedPages.has(pageUrl)) {
      continue;
    }

    visitedPages.add(pageUrl);
    deepestDepthReached = Math.max(
      deepestDepthReached,
      depth
    );

    console.log(
      chalk.blue(
        `\n📥 Fetching [depth ${depth}] ${pageUrl}...`
      )
    );

    let response;

    try {
      response = await fetchUrl(pageUrl, cookies);

      if (
        !response.statusCode ||
        response.statusCode < 200 ||
        response.statusCode >= 400
      ) {
        console.log(
          chalk.red(
            `   ❌ HTTP ${response.statusCode || 'unknown'}`
          )
        );

        continue;
      }
    } catch (error) {
      console.log(
        chalk.red(`   ❌ Error: ${error.message}`)
      );

      continue;
    }

    const html = response.body.toString('utf8');

    /*
     * Find external SRI resources.
     */
    const resources = extractResources(
      html,
      pageUrl,
      customExclusions
    );

    for (const resource of resources) {
      const key = `${resource.type}|${resource.url}`;

      if (!resourceMap.has(key)) {
        resourceMap.set(key, {
          ...resource,
          sourcePages: [pageUrl]
        });

        console.log(
          chalk.gray(
            `   Checking ${resource.type}: ${resource.url}`
          )
        );
      } else {
        const existing = resourceMap.get(key);

        if (!existing.sourcePages.includes(pageUrl)) {
          existing.sourcePages.push(pageUrl);
        }
      }
    }

    /*
     * Crawl links.
     */
    if (crawl && depth < maxDepth) {
      const links = extractLinks(html, pageUrl);

      for (const link of links) {
        if (
          !visitedPages.has(link) &&
          !queuedPages.has(link)
        ) {
          queuedPages.add(link);

          urlQueue.push({
            url: link,
            depth: depth + 1
          });
        }
      }
    }
  }

  /*
   * Tell the user when the crawl ended naturally.
   */
  if (crawl) {
    const pendingPages = urlQueue.length;

    if (
      deepestDepthReached < maxDepth &&
      pendingPages === 0
    ) {
      console.log(
        chalk.yellow(
          `\n⚠️ Crawl finished before requested depth.`
        )
      );

      console.log(
        chalk.gray(
          `   Requested depth: ${maxDepth}`
        )
      );

      console.log(
        chalk.gray(
          `   Deepest reachable depth: ${deepestDepthReached}`
        )
      );

      console.log(
        chalk.gray(
          `   No additional same-domain pages were found.`
        )
      );
    } else if (deepestDepthReached >= maxDepth) {
      console.log(
        chalk.green(
          `\n✓ Crawl reached requested maximum depth: ${maxDepth}`
        )
      );
    }
  }

  /*
   * Validate every unique external resource.
   */
  const allResources = Array.from(resourceMap.values());

  const validSRI = [];
  const invalidSRI = [];
  const missingSRI = [];
  const errors = [];

  console.log(
    chalk.blue(
      `\n🔐 Validating ${allResources.length} unique external resources...`
    )
  );

  for (const resource of allResources) {
    const result = await validateSRI(resource);

    resource.status = result.status;

    if (result.matchedHash) {
      resource.matchedHash = result.matchedHash;
    }

    if (result.error) {
      resource.error = result.error;
    }

    if (result.status === 'valid') {
      validSRI.push(resource);
    } else if (result.status === 'invalid') {
      invalidSRI.push(resource);
    } else if (result.status === 'missing') {
      missingSRI.push(resource);
    } else if (result.status === 'error') {
      errors.push(resource);
    }
  }

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
      `\n✅ VALID SRI (${validSRI.length}):`
    )
  );

  console.log(chalk.gray('━'.repeat(50)));

  if (validSRI.length === 0) {
    console.log(
      chalk.yellow('   No valid SRI resources found.')
    );
  } else {
    validSRI.forEach(resource => {
      console.log(
        chalk.green('   ✓') +
        ' ' +
        chalk.cyan(resource.type.padEnd(12)) +
        ' ' +
        chalk.white(resource.url)
      );
    });
  }

  /*
   * INVALID
   */
  console.log(
    chalk.red(
      `\n❌ INVALID SRI (${invalidSRI.length}):`
    )
  );

  console.log(chalk.gray('━'.repeat(50)));

  if (invalidSRI.length === 0) {
    console.log(
      chalk.green('   No invalid SRI hashes found.')
    );
  } else {
    invalidSRI.forEach(resource => {
      console.log(
        chalk.red('   ✗') +
        ' ' +
        chalk.cyan(resource.type.padEnd(12)) +
        ' ' +
        chalk.white(resource.url)
      );

      console.log(
        chalk.gray(
          `      ${resource.error}`
        )
      );
    });
  }

  /*
   * MISSING
   */
  console.log(
    chalk.yellow(
      `\n⚠️  MISSING SRI (${missingSRI.length}):`
    )
  );

  console.log(chalk.gray('━'.repeat(50)));

  if (missingSRI.length === 0) {
    console.log(
      chalk.green(
        '   All external resources have SRI.'
      )
    );
  } else {
    missingSRI.forEach(resource => {
      console.log(
        chalk.yellow('   !') +
        ' ' +
        chalk.cyan(resource.type.padEnd(12)) +
        ' ' +
        chalk.white(resource.url)
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

  console.log(chalk.gray('━'.repeat(50)));

  if (errors.length === 0) {
    console.log(
      chalk.green('   No resource errors.')
    );
  } else {
    errors.forEach(resource => {
      console.log(
        chalk.red('   !') +
        ' ' +
        chalk.cyan(resource.type.padEnd(12)) +
        ' ' +
        chalk.white(resource.url)
      );

      console.log(
        chalk.gray(
          `      ${resource.error}`
        )
      );
    });
  }

  /*
   * STATISTICS
   */
  const total = allResources.length;

  const percentage = total > 0
    ? Math.round(
        (validSRI.length / total) * 100
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
    chalk.white('║ Total External:    ') +
    chalk.yellow(
      String(total).padStart(20)
    ) +
    chalk.white(' ║')
  );

  console.log(
    chalk.white('║ Valid SRI:         ') +
    chalk.green(
      String(validSRI.length).padStart(20)
    ) +
    chalk.white(' ║')
  );

  console.log(
    chalk.white('║ Invalid SRI:       ') +
    chalk.red(
      String(invalidSRI.length).padStart(20)
    ) +
    chalk.white(' ║')
  );

  console.log(
    chalk.white('║ Missing SRI:       ') +
    chalk.yellow(
      String(missingSRI.length).padStart(20)
    ) +
    chalk.white(' ║')
  );

  console.log(
    chalk.white('║ Errors:            ') +
    chalk.red(
      String(errors.length).padStart(20)
    ) +
    chalk.white(' ║')
  );

  console.log(
    chalk.white('║ Valid Coverage:    ') +
    (
      percentage >= 80
        ? chalk.green
        : percentage >= 50
          ? chalk.yellow
          : chalk.red
    )(
      `${percentage}%`.padStart(20)
    ) +
    chalk.white(' ║')
  );

  if (crawl) {
    console.log(
      chalk.white('║ Pages Crawled:     ') +
      chalk.cyan(
        String(visitedPages.size).padStart(20)
      ) +
      chalk.white(' ║')
    );
  }

  console.log(
    chalk.cyan(
      '╚════════════════════════════════════════╝'
    )
  );

  return {
    resources: allResources,
    validSRI,
    invalidSRI,
    missingSRI,
    errors,
    pagesCrawled: visitedPages.size,
    deepestDepthReached
  };
}

module.exports = {
  checkSRI,
  calculateSRI,
  extractResources,
  extractLinks,
  fetchUrl,
  isExcludedDomain,
  hasSRI,
  resolveUrl,
  normalizeUrl,
  isExternalResource,
  parseIntegrity,
  validateSRI,
  printTitle
};



