// Trust anchors for verifying OID4VP Verifier request objects and (later)
// Wallet/Issuer trust. The primary source is the Trusted List module
// (LOTL mock) served by the backend; the bundled trusted-anchors.json is a
// fallback when that endpoint is unreachable.
//
// HAIP leaves trust-anchor management out of scope, so this layer is the
// ecosystem-specific glue: it turns the Trusted Lists into a flat set of PEM
// roots that requestObject.ts checks the verifier's x5c chain against.

import bundled from './trusted-anchors.json';
import { TRUSTLIST_BASE } from './constants';

interface TrustAnchorEntry {
    trust_anchor?: { root_pem?: string };
    root_pem?: string;
}

const BUNDLED_ANCHORS: string[] = bundled.anchors.map(a => a.root_pem);

let cache: string[] | null = null;

/** Extract root_pem values from a Trusted List document (issuers/verifiers/...). */
function collectPems(doc: unknown, key: string): string[] {
    const list = (doc as Record<string, unknown>)?.[key];
    if (!Array.isArray(list)) return [];
    return list
        .map((e: TrustAnchorEntry) => e.trust_anchor?.root_pem ?? e.root_pem)
        .filter((p): p is string => typeof p === 'string');
}

/**
 * Resolve the set of trusted root PEMs. Fetches the Verifier + Issuer + Wallet
 * Provider lists from the Trusted List module; falls back to the bundled
 * anchors on any failure. Result is cached for the session.
 */
export async function getTrustedAnchors(): Promise<string[]> {
    if (cache) return cache;

    const sources: Array<[string, string]> = [
        ['/verifiers', 'verifiers'],
        ['/issuers', 'issuers'],
        ['/wallet-providers', 'wallet_providers'],
    ];

    const pems = new Set<string>();
    try {
        await Promise.all(sources.map(async ([path, key]) => {
            const res = await fetch(TRUSTLIST_BASE + path);
            if (!res.ok) return;
            const doc = await res.json();
            for (const pem of collectPems(doc, key)) pems.add(pem);
        }));
    } catch {
        // network error — fall through to bundled
    }

    if (pems.size === 0) {
        cache = BUNDLED_ANCHORS;
    } else {
        // union with bundled so an offline/dev anchor still works
        for (const p of BUNDLED_ANCHORS) pems.add(p);
        cache = Array.from(pems);
    }
    return cache;
}
