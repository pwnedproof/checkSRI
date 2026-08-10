const https = require('https');
const http = require('http');
const crypto = require('crypto');
const url = require('url');

// Domains to exclude (social media, analytics, fonts)
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
  'cdn.jsdelivr.net', // often used for fonts
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
 * Calculate SRI hash for content
 */
function calculateSRI(content, algorithm = 'sha384') {
  const hash = crypto.createHash(algorithm);
  hash.update(content);
  const digest = hash.digest('base64');
  return `${algorithm}-${digest}`;
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
      resources.push({ type: 'script', url: src, tag: match[0] });
    }
  }
  
  // Match link tags with rel="stylesheet"
  const linkRegex = /<link[^>]*rel=["']stylesheet["'][^>]*href=["']([^"']+)["'][^>]*>/gi;
  
  while ((match = linkRegex.exec(html)) !== null) {
    const href = match[1];
    if (href && !isExcludedDomain(href)) {
      resources.push({ type: 'stylesheet', url: href, tag: match[0] });
    }
  }
  
  return resources;
}

/**
 * Resolve relative URLs to absolute
 */
function resolveUrl(baseUrl, relativeUrl) {
  if (relativeUrl.startsWith('http://') || relativeUrl.startsWith('https://')) {
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
      console.log('ℹ️  No external resources found (excluding social media, analytics, and fonts)');
      return;
    }
    
    console.log(`Found ${resources.length} resource(s):\n`);
    
    for (const resource of resources) {
      const absoluteUrl = resolveUrl(urlString, resource.url);
      console.log(`📄 ${resource.type.toUpperCase()}: ${resource.url}`);
      
      try {
        const content = await fetchUrl(absoluteUrl);
        const sri = calculateSRI(content);
        console.log(`   SRI: ${sri}`);
        console.log(`   HTML: <${resource.type === 'script' ? 'script' : 'link'} ${resource.type === 'script' ? 'src' : 'href'}="${resource.url}" integrity="${sri}">\n`);
      } catch (error) {
        console.log(`   ❌ Error fetching: ${error.message}\n`);
      }
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

module.exports = { checkSRI, calculateSRI, extractResources, fetchUrl, isExcludedDomain };