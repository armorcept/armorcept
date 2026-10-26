#!/usr/bin/env node
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as https from 'node:https';
import * as os from 'node:os';
import * as path from 'node:path';

function base64UrlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function postForm(urlString, params) {
  const body = new URLSearchParams(params).toString();
  const url = new URL(urlString);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(JSON.parse(text));
            } catch {
              reject(new Error(`Invalid JSON from token endpoint: ${text}`));
            }
          } else {
            reject(
              new Error(`Token endpoint HTTP ${res.statusCode}: ${text}`)
            );
          }
        });
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function main() {
  const allowAdcFallback =
    (process.env.ARMORCEPT_ALLOW_GCLOUD_ADC || '').trim().toLowerCase() === 'true';

  let keyFile = process.argv[2] || process.env.GOOGLE_APPLICATION_CREDENTIALS || '';
  keyFile = keyFile.trim().replace(/^["']|["']$/g, '');

  if (keyFile.startsWith('~/')) {
    keyFile = path.join(os.homedir(), keyFile.slice(2));
  }

  // Convert Windows path (e.g. C:\Users\...) to /mnt/c/Users/... when running inside WSL
  if (/^[A-Za-z]:\\/.test(keyFile) && process.platform === 'linux') {
    const drive = keyFile[0].toLowerCase();
    const rest = keyFile.slice(2).replace(/\\/g, '/');
    keyFile = `/mnt/${drive}${rest}`;
  }

  if (!keyFile && allowAdcFallback) {
    const defaultAdc = path.join(
      os.homedir(),
      '.config',
      'gcloud',
      'application_default_credentials.json'
    );
    if (fs.existsSync(defaultAdc)) {
      keyFile = defaultAdc;
    }
  }

  if (!keyFile) {
    throw new Error(
      'GOOGLE_APPLICATION_CREDENTIALS is not set (set GOOGLE_APPLICATION_CREDENTIALS, or set ARMORCEPT_ALLOW_GCLOUD_ADC=true to allow default gcloud ADC credentials).'
    );
  }

  if (!fs.existsSync(keyFile)) {
    throw new Error(`Credentials file not found at path: "${keyFile}"`);
  }

  const rawJson = fs.readFileSync(keyFile, 'utf8');
  const creds = JSON.parse(rawJson);

  if (creds.type === 'service_account' || (creds.client_email && creds.private_key)) {
    const now = Math.floor(Date.now() / 1000);
    const tokenUri = creds.token_uri || 'https://oauth2.googleapis.com/token';
    const header = { alg: 'RS256', typ: 'JWT' };
    const claimSet = {
      iss: creds.client_email,
      scope: 'https://www.googleapis.com/auth/cloud-platform',
      aud: tokenUri,
      iat: now,
      exp: now + 3600,
    };

    const unsignedJwt = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(
      JSON.stringify(claimSet)
    )}`;
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(unsignedJwt);
    signer.end();
    const signature = signer.sign(creds.private_key);
    const assertion = `${unsignedJwt}.${base64UrlEncode(signature)}`;

    const tokenResp = await postForm(tokenUri, {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    });

    if (!tokenResp.access_token) {
      throw new Error(`No access_token in response: ${JSON.stringify(tokenResp)}`);
    }
    const expiresInSec = Number(tokenResp.expires_in) || 3600;
    process.stdout.write(
      JSON.stringify({
        access_token: tokenResp.access_token,
        expires_in: expiresInSec,
      })
    );
    return;
  }

  if (
    creds.type === 'authorized_user' ||
    (creds.client_id && creds.client_secret && creds.refresh_token)
  ) {
    const tokenUri = creds.token_uri || 'https://oauth2.googleapis.com/token';
    const tokenResp = await postForm(tokenUri, {
      client_id: creds.client_id,
      client_secret: creds.client_secret,
      refresh_token: creds.refresh_token,
      grant_type: 'refresh_token',
    });

    if (!tokenResp.access_token) {
      throw new Error(`No access_token in response: ${JSON.stringify(tokenResp)}`);
    }
    const expiresInSec = Number(tokenResp.expires_in) || 3600;
    process.stdout.write(
      JSON.stringify({
        access_token: tokenResp.access_token,
        expires_in: expiresInSec,
      })
    );
    return;
  }

  throw new Error(
    `Unsupported credentials JSON type "${creds.type ?? 'unknown'}" in ${keyFile}. Expected "service_account" or "authorized_user".`
  );
}

main().catch((err) => {
  process.stderr.write(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
