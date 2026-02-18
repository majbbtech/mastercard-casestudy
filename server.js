/**
 * Click to Pay — Backend API Server (Full Integration)
 *
 * Endpoints:
 *   POST /api/checkout/complete      — Full flow: receive SDK response -> call MC API -> decrypt -> return credentials
 *   POST /api/checkout/decrypt       — Decrypt an encryptedPayload JWE directly
 *   POST /api/checkout/confirm       — Call POST /confirmations to report transaction result
 *   GET  /api/health                 — Health check
 */

import express from 'express';
import cors from 'cors';
import { compactDecrypt, importPKCS8 } from 'jose';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import https from 'https';
import { fileURLToPath } from 'url';
import OAuth from 'oauth-1.0a';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// ── Configuration ────────────────────────────────────────────
const PORT = 3001;
const KEYS_DIR = __dirname;

const MC_SANDBOX_BASE = 'https://sandbox.api.mastercard.com';
const MC_CHECKOUT_PATH = '/srci/api/checkout';
const MC_CONFIRM_PATH = '/srci/api/checkout/confirmations';
const SRC_DPA_ID = 'e72821e5-b6c1-46aa-9569-8df51aa9c703';

// Consumer Key from Mastercard Developer Portal (set via env or hardcode for sandbox)
// Format: <client_id>!<key_id>
const CONSUMER_KEY = process.env.MC_CONSUMER_KEY || '';

// ── Load Keys ────────────────────────────────────────────────
let decryptionPrivateKey = null;   // For JWE decryption (payload encryption private key)
let oauthSigningKeyPem = null;     // For OAuth 1.0a signing (API signing private key)

async function loadKeys() {
    // 1. Payload decryption key
    const decryptKeyFile = path.join(KEYS_DIR, 'payload_decryption_key.pem');
    if (fs.existsSync(decryptKeyFile)) {
        try {
            const keyPem = fs.readFileSync(decryptKeyFile, 'utf-8');
            decryptionPrivateKey = await importPKCS8(keyPem, 'RSA-OAEP-256');
            console.log('[KEY] Payload decryption key loaded');
        } catch (e) {
            console.warn(`[KEY] Failed to load decryption key: ${e.message}`);
        }
    } else {
        console.warn('[KEY] No payload_decryption_key.pem found');
    }

    // 2. OAuth signing key
    const oauthKeyFile = path.join(KEYS_DIR, 'oauth_signing_key.pem');
    if (fs.existsSync(oauthKeyFile)) {
        oauthSigningKeyPem = fs.readFileSync(oauthKeyFile, 'utf-8');
        console.log('[KEY] OAuth signing key loaded');
    } else {
        console.warn('[KEY] No oauth_signing_key.pem found — Mastercard API calls will not work');
    }
}

// ── OAuth 1.0a Signing ───────────────────────────────────────
function generateOAuthHeader(method, url, body = '') {
    if (!oauthSigningKeyPem || !CONSUMER_KEY) {
        return null;
    }

    // Compute SHA-256 body hash (required by Mastercard OAuth 1.0a)
    const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
    const bodyHash = crypto.createHash('sha256').update(bodyStr || '').digest('base64');

    const oauth = OAuth({
        consumer: { key: CONSUMER_KEY, secret: '' },
        signature_method: 'RSA-SHA256',
        hash_function(baseString) {
            return crypto.sign('RSA-SHA256', Buffer.from(baseString), {
                key: oauthSigningKeyPem,
                padding: crypto.constants.RSA_PKCS1_PADDING,
            }).toString('base64');
        },
    });

    const requestData = { url, method, data: { oauth_body_hash: bodyHash } };
    const authHeader = oauth.toHeader(oauth.authorize(requestData));

    // The oauth_body_hash must be in the Authorization header, not as a query param.
    // oauth-1.0a library puts extra data into the signature but not the header, so inject it.
    const headerStr = authHeader.Authorization;
    if (!headerStr.includes('oauth_body_hash')) {
        const injection = `oauth_body_hash="${encodeURIComponent(bodyHash)}"`;
        return headerStr.replace(/oauth_signature="/, `${injection}, oauth_signature="`);
    }
    return headerStr;
}

// ── HTTPS Request Helper ─────────────────────────────────────
function httpsRequest(method, fullUrl, body, authHeader, extraHeaders = {}) {
    return new Promise((resolve, reject) => {
        const url = new URL(fullUrl);
        const postData = body ? JSON.stringify(body) : '';

        const options = {
            hostname: url.hostname,
            port: 443,
            path: url.pathname + url.search,
            method,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                ...(authHeader ? { 'Authorization': authHeader } : {}),
                ...(postData ? { 'Content-Length': Buffer.byteLength(postData) } : {}),
                ...extraHeaders,
            },
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                resolve({ status: res.statusCode, headers: res.headers, body: data });
            });
        });

        req.on('error', reject);
        if (postData) req.write(postData);
        req.end();
    });
}

// ── Helper: Parse JWS ────────────────────────────────────────
function parseJWS(jwsToken) {
    try {
        const parts = jwsToken.split('.');
        if (parts.length !== 3) return { error: 'Not a valid JWS' };
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        return { header, payload, hasEncryptedPayload: !!payload.encryptedPayload };
    } catch (e) {
        return { error: `JWS parse failed: ${e.message}` };
    }
}

// ── Helper: Decrypt JWE ──────────────────────────────────────
async function decryptJWE(jweCompact) {
    if (!decryptionPrivateKey) return { error: 'No decryption key loaded' };
    try {
        const { plaintext, protectedHeader } = await compactDecrypt(jweCompact, decryptionPrivateKey);
        return { success: true, protectedHeader, decrypted: JSON.parse(new TextDecoder().decode(plaintext)) };
    } catch (e) {
        return { error: `JWE decryption failed: ${e.message}` };
    }
}

// ════════════════════════════════════════════════════════════════
// ENDPOINT: POST /api/checkout/complete
// Full flow: receive SDK response -> call MC POST /checkout -> decrypt -> return
// ════════════════════════════════════════════════════════════════
app.post('/api/checkout/complete', async (req, res) => {
    console.log('\n[API] POST /api/checkout/complete');
    const startTime = Date.now();

    try {
        const body = req.body;
        if (!body.checkoutActionCode || !body.checkoutResponse) {
            return res.status(400).json({ success: false, error: 'Missing checkoutActionCode or checkoutResponse' });
        }

        const merchantTransactionId = body.headers?.['merchant-transaction-id'] || null;
        const network = body.network || 'unknown';

        // Parse the JS SDK's checkoutResponse JWS
        const sdkJws = parseJWS(body.checkoutResponse);

        // Extract masked data from SDK response
        const responseData = body.checkoutResponseData || {};
        const maskedCard = responseData.maskedCard || {};
        const maskedConsumer = responseData.maskedConsumer || {};
        const assuranceData = responseData.assuranceData || {};

        // ── Step 5: Call Mastercard POST /checkout API ──
        let mcApiResult = null;
        let decryptedCredentials = null;

        if (merchantTransactionId && oauthSigningKeyPem && CONSUMER_KEY) {
            console.log(`[MC-API] Calling POST /checkout with merchantTransactionId: ${merchantTransactionId}`);

            const checkoutUrl = `${MC_SANDBOX_BASE}${MC_CHECKOUT_PATH}`;
            const checkoutBody = {
                srcDpaId: SRC_DPA_ID,
                checkoutType: 'CLICK_TO_PAY',
                checkoutReference: {
                    type: 'MERCHANT_TRANSACTION_ID',
                    data: { merchantTransactionId },
                },
            };
            const authHeader = generateOAuthHeader('POST', checkoutUrl, JSON.stringify(checkoutBody));

            try {
                const mcRes = await httpsRequest('POST', checkoutUrl, checkoutBody, authHeader, {
                    'x-openapi-clientid': SRC_DPA_ID,
                    'merchant-transaction-id': merchantTransactionId,
                    'x-src-cx-flow-id': body.headers?.['x-src-cx-flow-id'] || '',
                });
                console.log(`[MC-API] Response status: ${mcRes.status}`);

                mcApiResult = {
                    status: mcRes.status,
                    success: mcRes.status >= 200 && mcRes.status < 300,
                };

                if (mcRes.body) {
                    try {
                        const mcBody = JSON.parse(mcRes.body);
                        mcApiResult.response = mcBody;

                        // Check for encryptedPayload — either directly in response or inside a JWS
                        let encPayload = mcBody.encryptedPayload;

                        if (!encPayload) {
                            const jwsField = mcBody.checkoutResponseJWS || mcBody.checkoutResponse;
                            if (jwsField) {
                                console.log('[MC-API] Found checkoutResponseJWS — parsing...');
                                const apiJws = parseJWS(jwsField);
                                if (apiJws.hasEncryptedPayload) {
                                    encPayload = apiJws.payload.encryptedPayload;
                                }
                            }
                        }

                        if (encPayload) {
                            console.log('[MC-API] Found encryptedPayload — decrypting...');
                            const decResult = await decryptJWE(encPayload);
                            if (decResult.success) {
                                decryptedCredentials = decResult.decrypted;
                                console.log('[MC-API] Decryption successful — payment credentials extracted');
                            } else {
                                mcApiResult.decryptionError = decResult.error;
                                console.log(`[MC-API] Decryption failed: ${decResult.error}`);
                            }
                        } else {
                            mcApiResult.note = 'No encryptedPayload found in response';
                        }
                    } catch (parseErr) {
                        mcApiResult.rawBody = mcRes.body.substring(0, 500);
                    }
                }
            } catch (apiErr) {
                mcApiResult = { success: false, error: apiErr.message };
                console.error(`[MC-API] Error: ${apiErr.message}`);
            }
        } else {
            const missing = [];
            if (!merchantTransactionId) missing.push('merchantTransactionId');
            if (!oauthSigningKeyPem) missing.push('OAuth signing key');
            if (!CONSUMER_KEY) missing.push('Consumer Key (set MC_CONSUMER_KEY env var)');
            mcApiResult = { skipped: true, reason: `Missing: ${missing.join(', ')}` };
        }

        // ── Build response ──
        const result = {
            success: true,
            timestamp: new Date().toISOString(),
            processingTimeMs: Date.now() - startTime,

            transaction: {
                merchantTransactionId,
                srciTransactionId: responseData.srciTransactionId || null,
                srcCorrelationId: responseData.srcCorrelationId || null,
                srcCxFlowId: body.headers?.['x-src-cx-flow-id'] || null,
                checkoutActionCode: body.checkoutActionCode,
                network,
            },

            card: {
                srcDigitalCardId: maskedCard.srcDigitalCardId || null,
                panBin: maskedCard.panBin || null,
                panLastFour: maskedCard.panLastFour || null,
                brand: maskedCard.paymentCardDescriptor || null,
                type: maskedCard.paymentCardType || null,
                expiryMonth: maskedCard.panExpirationMonth || null,
                expiryYear: maskedCard.panExpirationYear || null,
                issuer: maskedCard.digitalCardData?.descriptorName || null,
                artUri: maskedCard.digitalCardData?.artUri || null,
            },

            consumer: {
                srcConsumerId: maskedConsumer.srcConsumerId || null,
                maskedEmail: maskedConsumer.maskedEmailAddress || null,
                maskedPhone: maskedConsumer.maskedMobileNumber || null,
                countryCode: maskedConsumer.countryCode || null,
            },

            billingAddress: maskedCard.maskedBillingAddress || null,

            assurance: {
                cardVerificationEntity: assuranceData.cardVerificationEntity || null,
                cardVerificationMethod: assuranceData.cardVerificationMethod || null,
                cardVerificationResults: assuranceData.cardVerificationResults || null,
            },

            jws: {
                parsed: !sdkJws.error,
                signingKeyId: sdkJws.header?.kid || null,
                algorithm: sdkJws.header?.alg || null,
                hasEncryptedPayload: sdkJws.hasEncryptedPayload || false,
            },

            // Mastercard API call result
            mastercardApi: mcApiResult,

            // Decrypted payment credentials (if available)
            decryptedCredentials: decryptedCredentials ? {
                token: decryptedCredentials.token || null,
                dynamicData: decryptedCredentials.dynamicData || null,
                card: decryptedCredentials.card || null,
                fullPayload: decryptedCredentials,
            } : null,
        };

        console.log(`[API] Complete: merchantTxnId=${merchantTransactionId}, card=****${maskedCard.panLastFour}`);
        res.json(result);

    } catch (e) {
        console.error(`[API] Error: ${e.message}`);
        res.status(500).json({ success: false, error: e.message });
    }
});

// ════════════════════════════════════════════════════════════════
// ENDPOINT: POST /api/checkout/decrypt
// Decrypt an encryptedPayload JWE directly
// ════════════════════════════════════════════════════════════════
app.post('/api/checkout/decrypt', async (req, res) => {
    console.log('\n[API] POST /api/checkout/decrypt');
    try {
        const { checkoutResponse, encryptedPayload } = req.body;

        let jweToDecrypt = encryptedPayload;

        // If checkoutResponse provided, extract encryptedPayload from it
        if (!jweToDecrypt && checkoutResponse) {
            const parsed = parseJWS(checkoutResponse);
            if (parsed.error) return res.status(400).json({ success: false, error: parsed.error });
            jweToDecrypt = parsed.payload?.encryptedPayload;
        }

        if (!jweToDecrypt) {
            return res.json({
                success: false,
                message: 'No encryptedPayload found. In sandbox, this comes from the POST /checkout API, not the JS SDK response.',
            });
        }

        const result = await decryptJWE(jweToDecrypt);
        if (result.error) return res.status(400).json({ success: false, error: result.error });

        res.json({
            success: true,
            encryptionAlgorithm: result.protectedHeader?.alg,
            contentEncryption: result.protectedHeader?.enc,
            paymentCredentials: {
                token: result.decrypted.token || null,
                dynamicData: result.decrypted.dynamicData || null,
                card: result.decrypted.card || null,
            },
            fullDecryptedPayload: result.decrypted,
        });
    } catch (e) {
        console.error(`[API] Decrypt error: ${e.message}`);
        res.status(500).json({ success: false, error: e.message });
    }
});

// ════════════════════════════════════════════════════════════════
// ENDPOINT: POST /api/checkout/confirm
// Call Mastercard POST /confirmations to report transaction result
// ════════════════════════════════════════════════════════════════
app.post('/api/checkout/confirm', async (req, res) => {
    console.log('\n[API] POST /api/checkout/confirm');
    try {
        const { merchantTransactionId, checkoutEventType, checkoutEventStatus } = req.body;

        if (!merchantTransactionId) {
            return res.status(400).json({ success: false, error: 'Missing merchantTransactionId' });
        }

        if (!oauthSigningKeyPem || !CONSUMER_KEY) {
            return res.status(400).json({
                success: false,
                error: 'OAuth signing not configured. Set MC_CONSUMER_KEY env var.',
            });
        }

        const confirmUrl = `${MC_SANDBOX_BASE}${MC_CONFIRM_PATH}`;
        const authHeader = generateOAuthHeader('POST', confirmUrl);

        const confirmBody = {
            correlationId: req.body.correlationId || crypto.randomUUID(),
            merchantTransactionId,
            confirmationData: {
                checkoutEventType: checkoutEventType || '01',       // 01 = Authorise
                checkoutEventStatus: checkoutEventStatus || '02',   // 02 = Confirmed
                confirmationStatus: req.body.confirmationStatus || '01', // 01 = Success
                confirmationTimestamp: new Date().toISOString(),
            },
        };

        console.log(`[MC-API] POST /confirmations: ${JSON.stringify(confirmBody)}`);
        const mcRes = await httpsRequest('POST', confirmUrl, confirmBody, authHeader, {
            'x-openapi-clientid': SRC_DPA_ID,
            'merchant-transaction-id': merchantTransactionId,
        });

        console.log(`[MC-API] Confirmations response: ${mcRes.status}`);
        res.json({
            success: mcRes.status === 204 || (mcRes.status >= 200 && mcRes.status < 300),
            status: mcRes.status,
            message: mcRes.status === 204
                ? 'Confirmation accepted by Mastercard'
                : `Response: ${mcRes.body?.substring(0, 500)}`,
        });
    } catch (e) {
        console.error(`[API] Confirm error: ${e.message}`);
        res.status(500).json({ success: false, error: e.message });
    }
});

// ════════════════════════════════════════════════════════════════
// ENDPOINT: GET /api/health
// ════════════════════════════════════════════════════════════════
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        keys: {
            decryptionKeyLoaded: !!decryptionPrivateKey,
            oauthSigningKeyLoaded: !!oauthSigningKeyPem,
            consumerKeyConfigured: !!CONSUMER_KEY,
        },
        endpoints: [
            'POST /api/checkout/complete  — Full flow: SDK response -> MC API -> decrypt',
            'POST /api/checkout/decrypt   — Decrypt encryptedPayload JWE',
            'POST /api/checkout/confirm   — Report transaction result to Mastercard',
            'GET  /api/health             — This endpoint',
        ],
    });
});

// ── Start ────────────────────────────────────────────────────
async function start() {
    await loadKeys();

    app.listen(PORT, () => {
        console.log(`\n╔════════════════════════════════════════════════════════╗`);
        console.log(`║  Click to Pay — Backend API Server (Full Integration) ║`);
        console.log(`║  http://localhost:${PORT}                                ║`);
        console.log(`║                                                       ║`);
        console.log(`║  Keys:                                                ║`);
        console.log(`║    Decryption:  ${decryptionPrivateKey ? 'LOADED' : 'MISSING'}                                  ║`);
        console.log(`║    OAuth Sign:  ${oauthSigningKeyPem ? 'LOADED' : 'MISSING'}                                  ║`);
        console.log(`║    Consumer:    ${CONSUMER_KEY ? 'SET' : 'NOT SET (need MC_CONSUMER_KEY)'}              ║`);
        console.log(`╚════════════════════════════════════════════════════════╝\n`);
    });
}

start();
