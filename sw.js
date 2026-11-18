'use strict';

const site = new URL(self.registration.scope);
const root = new URL('../', site);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const mime = {
  bin: 'application/octet-stream',
  css: 'text/css; charset=utf-8',
  html: 'text/html; charset=utf-8',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  js: 'text/javascript; charset=utf-8',
  json: 'application/json',
  mp4: 'video/mp4',
  png: 'image/png',
  txt: 'text/plain; charset=utf-8',
  woff2: 'font/woff2',
};

let sessionKey, recovering;

self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

function isLanding(client) {
  if (!client?.url || client.type !== 'window') return false;
  const url = new URL(client.url);
  return url.origin === root.origin && (url.pathname === root.pathname || url.pathname === root.pathname + 'index.html');
}

async function decrypt(path, key) {
  const aad = encoder.encode(path);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', aad));
  const id = Array.from(digest, n => n.toString(16).padStart(2, '0')).join('');
  const response = await fetch(new URL('_sealed/' + id.slice(0, 2) + '/' + id.slice(2) + '.bin', root), {
    referrerPolicy: 'no-referrer',
  });
  if (!response.ok) return null;
  const sealed = new Uint8Array(await response.arrayBuffer());
  const plain = new Uint8Array(await crypto.subtle.decrypt(
    {name: 'AES-GCM', iv: sealed.subarray(0, 12), additionalData: aad},
    key,
    sealed.subarray(12),
  ));
  const body = plain.subarray(1);
  if (plain[0] === 0) return body;
  if (plain[0] !== 1) throw new Error('Invalid asset format');
  const stream = new Blob([body]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function validate(token) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  try {
    const raw = Uint8Array.from(atob(token.replace(/-/g, '+').replace(/_/g, '/') + '='), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    const check = await decrypt('check', key);
    return check && decoder.decode(check) === 'EVGT preview' ? key : null;
  } catch {
    return null;
  }
}

self.addEventListener('message', event => {
  if (event.data?.type !== 'unlock' || !event.ports[0] || !isLanding(event.source)) return;
  event.waitUntil((async () => {
    const key = await validate(event.data.key);
    if (key) sessionKey = key;
    event.ports[0].postMessage(Boolean(key));
  })());
});

function ask(client) {
  return new Promise(resolve => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => {
      channel.port1.close();
      resolve(null);
    }, 1200);
    channel.port1.onmessage = ({data}) => {
      clearTimeout(timer);
      channel.port1.close();
      resolve(data);
    };
    client.postMessage('request-key', [channel.port2]);
  });
}

async function recover() {
  const windows = await self.clients.matchAll({type: 'window', includeUncontrolled: true});
  const candidates = await Promise.all(windows.filter(isLanding).map(ask));
  for (const candidate of candidates) {
    const key = await validate(candidate);
    if (key) return key;
  }
  return null;
}

function rangeBounds(range, length) {
  const match = /^bytes=(\d*)-(\d*)$/.exec(range);
  if (!match || !(match[1] || match[2])) return null;
  const start = match[1] ? Number(match[1]) : Math.max(0, length - Number(match[2]));
  const end = match[1] && match[2] ? Math.min(length - 1, Number(match[2])) : length - 1;
  return start <= end && end < length ? [start, end] : null;
}

async function serve(request, rawPath) {
  if (!sessionKey) {
    recovering ??= recover().finally(() => { recovering = null; });
    sessionKey = await recovering;
  }
  const headers = new Headers({'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Robots-Tag': 'noindex'});
  if (!sessionKey) return new Response('Open the invitation link to view this preview.', {status: 403, headers});
  const path = rawPath.endsWith('/') || !rawPath ? rawPath + 'index.html' : rawPath;
  const extension = path.split('.').pop();
  let data;
  try {
    data = await decrypt(path, sessionKey);
  } catch {
    return new Response('The preview asset could not be verified.', {status: 502, headers});
  }
  if (!data) return new Response('Preview asset not found.', {status: 404, headers});
  if (extension === 'html' || extension === 'css' || extension === 'js') {
    data = encoder.encode(decoder.decode(data).replaceAll('__EVGT_SITE_ROOT__', site.pathname.slice(0, -1)));
  }
  headers.set('Content-Type', mime[extension] || 'application/octet-stream');
  headers.set('Accept-Ranges', 'bytes');
  const range = request.headers.get('Range');
  let result = data, status = 200;
  if (range) {
    const bounds = rangeBounds(range, data.length);
    if (!bounds) {
      headers.set('Content-Range', 'bytes */' + data.length);
      return new Response(null, {status: 416, headers});
    }
    const [start, end] = bounds;
    result = data.subarray(start, end + 1);
    headers.set('Content-Range', `bytes ${start}-${end}/${data.length}`);
    status = 206;
  }
  headers.set('Content-Length', result.length);
  return new Response(request.method === 'HEAD' ? null : result, {status, headers});
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin !== site.origin || !url.pathname.startsWith(site.pathname)) return;
  if (event.request.method !== 'GET' && event.request.method !== 'HEAD') return;
  event.respondWith(serve(event.request, url.pathname.slice(site.pathname.length)));
});
