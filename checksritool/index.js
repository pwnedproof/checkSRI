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
    'fonts.google'
];

/**
 * Fetch content from URL
 */
async function fetchUrl(urlString) {
    return new Promise(function(resolve, reject) {
        var protocol = urlString.startsWith('https') ? https : http;

        protocol.get(urlString, { timeout: 10000 }, function(res) {
            var data = '';

            res.on('data', function(chunk) {
                data += chunk;
            });

            res.on('end', function() {
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
        var urlObj = new URL(urlString);
        var hostname = urlObj.hostname.toLowerCase();

        return EXCLUDED_DOMAINS.some(function(excluded) {
            return hostname.includes(excluded.toLowerCase());
        });
    } catch (error) {
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
    var resources = [];

    // Match script tags with src
    var scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
    var match;

    while ((match = scriptRegex.exec(html)) !== null) {
        var src = match[1];

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
    var linkRegex = /<link[^>]*rel=["']stylesheet["'][^>]*href=["']([^"']+)["'][^>]*>/gi;

    while ((match = linkRegex.exec(html)) !== null) {
        var href = match[1];

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
        var baseObj = new URL(baseUrl);
        return baseObj.protocol + relativeUrl;
    }

    return new URL(relativeUrl, baseUrl).toString();
}

/**
 * Main function to check SRI
 */
async function checkSRI(urlString) {
    try {
        console.log('Fetching ' + urlString + '...\n');

        var html = await fetchUrl(urlString);
        var resources = extractResources(html);

        if (resources.length === 0) {
            console.log(
                'No external resources found (excluding social media, analytics, and fonts)'
            );
            return;
        }

        var withSRI = resources.filter(function(resource) {
            return resource.hasSRI;
        });

        var withoutSRI = resources.filter(function(resource) {
            return !resource.hasSRI;
        });

        // ========================================
        // WITH SRI
        // ========================================

        console.log('');
        console.log('========================================');
        console.log('              WITH SRI');
        console.log('========================================');
        console.log('');

        if (withSRI.length === 0) {
            console.log('No resources with SRI found.');
            console.log('');
        } else {
            for (var i = 0; i < withSRI.length; i++) {
                console.log(
                    '[+] ' +
                    withSRI[i].type.toUpperCase() +
                    ': ' +
                    withSRI[i].url
                );
            }

            console.log('');
            console.log('Total with SRI: ' + withSRI.length);
            console.log('');
        }

        // ========================================
        // NO SRI
        // ========================================

        console.log('');
        console.log('========================================');
        console.log('               NO SRI');
        console.log('========================================');
        console.log('');

        if (withoutSRI.length === 0) {
            console.log('All resources have SRI.');
            console.log('');
        } else {
            for (var j = 0; j < withoutSRI.length; j++) {
                console.log(
                    '[-] ' +
                    withoutSRI[j].type.toUpperCase() +
                    ': ' +
                    withoutSRI[j].url
                );
            }

            console.log('');
            console.log('Total without SRI: ' + withoutSRI.length);
            console.log('');
        }

        // ========================================
        // SUMMARY
        // ========================================

        console.log('========================================');
        console.log('                 SUMMARY');
        console.log('========================================');
        console.log('Total resources: ' + resources.length);
        console.log('With SRI:        ' + withSRI.length);
        console.log('Without SRI:     ' + withoutSRI.length);
        console.log('========================================');
        console.log('');

    } catch (error) {
        console.error('Error: ' + error.message);
        process.exit(1);
    }
}

module.exports = {
    checkSRI: checkSRI,
    extractResources: extractResources,
    fetchUrl: fetchUrl,
    isExcludedDomain: isExcludedDomain,
    hasSRI: hasSRI,
    resolveUrl: resolveUrl
};
