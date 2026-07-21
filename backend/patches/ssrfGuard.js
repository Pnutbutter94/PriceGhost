"use strict";
// Blocks SSRF via user-supplied URLs (AI test-extraction endpoint lets any
// authenticated user make the backend fetch an arbitrary URL). Dropped into
// dist/utils/ at build time — see Dockerfile.backend. Source of truth is the
// TypeScript version at backend/src/utils/ssrfGuard.ts (not currently built
// into the deployed image, which runs the upstream prebuilt dist/ directly).
Object.defineProperty(exports, "__esModule", { value: true });
exports.assertSafeUrl = assertSafeUrl;

const dns = require('dns').promises;
const net = require('net');

function isPrivateOrReservedIPv4(ip) {
    const parts = ip.split('.').map(Number);
    const a = parts[0], b = parts[1];
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 0) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a >= 224) return true;
    return false;
}

function isPrivateOrReservedIPv6(ip) {
    const lower = ip.toLowerCase();
    if (lower === '::1') return true;
    if (lower.startsWith('fe80:')) return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateOrReservedIPv4(mapped[1]);
    return false;
}

function isBlockedIP(ip) {
    if (net.isIPv4(ip)) return isPrivateOrReservedIPv4(ip);
    if (net.isIPv6(ip)) return isPrivateOrReservedIPv6(ip);
    return true;
}

async function assertSafeUrl(rawUrl) {
    let parsed;
    try {
        parsed = new URL(rawUrl);
    }
    catch {
        throw new Error('Invalid URL');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('Only http/https URLs are allowed');
    }
    const hostname = parsed.hostname;
    if (hostname.toLowerCase() === 'localhost') {
        throw new Error('URL resolves to a blocked address');
    }
    const addresses = net.isIP(hostname)
        ? [hostname]
        : (await dns.lookup(hostname, { all: true })).map((r) => r.address);
    if (addresses.length === 0) {
        throw new Error('Could not resolve host');
    }
    for (const addr of addresses) {
        if (isBlockedIP(addr)) {
            throw new Error('URL resolves to a blocked address');
        }
    }
}
