```js
const https = require('https');
const http = require('http');

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
    'fonts.google',
];

/**
 * Fetch content from URL
 */
async function fetchUrl(urlString) {
    return new Promise((resolve, reject) => {
        const protocol = urlString.startsWith('https') ? https : http;

        protocol.get(urlString, { timeout: 10000 }, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                resolve(data);
            });
        }).on('error', reject);
    });
}

/**
 * Check if domain should be excluded
 */
function isExcludedDomain(urlString) {
    try {
        const urlObj = new URL(urlString);
        const hostname = urlObj.hostname.toLowerCase();

        return EXCLUDED_DOMAINS.some(excluded =>
            hostname.includes(excluded.toLowerCase())
        );
    } catch {
        return false;
    }
}

/**
 * Check whether an HTML tag contains an integrity attribute
 */
function hasSRI(tag) {
    return /\bintegrity\s*=\s*["'][^"']+["']/i.test(tag);
}

/**
 * Extract external resources from HTML
 */
function extractResources(html) {
    const resources = [];

    // Match script tags with src
    const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
    let match;

    while ((match = scriptRegex.exec(html)) !== null) {
        const src = match[1];

        if (src && !isExcludedDomain(src)) {
            resources.push({
                type: 'script',
                url: src,
                tag: match[0],
                hasSRI: hasSRI(match[0])
            });
        }
    }

    // Match stylesheet link tags
    const linkRegex =
        /<link[^>]*rel=["']stylesheet["'][^>]*href=["']([^"']+)["'][^>]*>/gi;

    while ((match = linkRegex.exec(html)) !== null) {
        const href = match[1];

        if (href && !isExcludedDomain(href)) {
            resources.push({
                type: 'stylesheet',
                url: href,
                tag: match[0],
                hasSRI: hasSRI(match[0])
            });
        }
    }

    return resources;
}

/**
 * Resolve relative URLs to absolute
 */
function resolveUrl(baseUrl, relativeUrl) {
    if (
        relativeUrl.startsWith('http://') ||
        relativeUrl.startsWith('https://')
    ) {
        return relativeUrl;
    }

    if (relativeUrl.startsWith('//')) {
        const baseObj = new URL(baseUrl);
        return `${baseObj.protocol}${relativeUrl}`;
    }

    return new URL(relativeUrl, baseUrl).toString();
}

/**
 * Main function to check SRI
 */
async function checkSRI(urlString) {
    try {
        console.log(`📥 Fetching ${urlString}...\n`);

        const html = await fetchUrl(urlString);
        const resources = extractResources(html);

        if (resources.length === 0) {
            console.log(
                'ℹ️ No external resources found (excluding social media, analytics, and fonts)'
            );
            return;
        }

        const withSRI = resources.filter(resource => resource.hasSRI);
        const withoutSRI = resources.filter(resource => !resource.hasSRI);

        // ==============================
        // WITH SRI
        // ==============================

        console.log('\n');
        console.log('========================================');
        console.log('              WITH SRI');
        console.log('========================================\n');

        if (withSRI.length === 0) {
            console.log('No resources with SRI found.\n');
        } else {
            for (const resource of withSRI) {
                console.log(
                    `✅ ${resource.type.toUpperCase()}: ${resource.url}`
                );
            }

            console.log(`\nTotal with SRI: ${withSRI.length}\n`);
        }

        // ==============================
        // NO SRI
        // ==============================

        console.log('\n');
        console.log('========================================');
        console.log('               NO SRI');
        console.log('========================================\n');

        if (withoutSRI.length === 0) {
            console.log('All resources have SRI.\n');
        } else {
            for (const resource of withoutSRI) {
                console.log(
                    `❌ ${resource.type.toUpperCase()}: ${resource.url}`
                );
            }

            console.log(`\nTotal without SRI: ${withoutSRI.length}\n`);
        }

        // ==============================
        // SUMMARY
        // ==============================

        console.log('========================================');
        console.log('                 SUMMARY');
        console.log('========================================');
        console.log(`Total resources: ${resources.length}`);
        console.log(`With SRI:        ${withSRI.length}`);
        console.log(`Without SRI:     ${withoutSRI.length}`);
        console.log('========================================\n');

    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
}

module.exports = {
    checkSRI,
    extractResources,
    fetchUrl,
    isExcludedDomain,
    hasSRI
};
```
