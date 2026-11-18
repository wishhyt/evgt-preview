'use strict';

const access = document.getElementById('access');
const input = document.getElementById('key');
const status = document.getElementById('status');
const submit = access.querySelector('button');
const iframe = document.getElementById('preview');
const fragment = new URLSearchParams(location.hash.slice(1));

let registration, verifiedKey;

function activatedWorker(reg) {
  if (reg.active?.state === 'activated') return Promise.resolve(reg.active);
  const installing = reg.installing || reg.waiting || reg.active;
  if (!installing) throw new Error('Could not start the site viewer.');
  return new Promise((resolve, reject) => {
    function update() {
      if (installing.state === 'activated') resolve(installing);
      if (installing.state === 'redundant') reject(new Error('Could not start the site viewer.'));
    }
    installing.addEventListener('statechange', update);
    update();
  });
}

function verify(worker, key) {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => {
      channel.port1.close();
      reject(new Error('The connection timed out. Please try again.'));
    }, 20000);
    channel.port1.onmessage = ({data}) => {
      clearTimeout(timer);
      channel.port1.close();
      resolve(data === true);
    };
    worker.postMessage({type: 'unlock', key}, [channel.port2]);
  });
}

async function openPreview(key) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(key)) {
    status.textContent = 'Enter the access key from your invitation.';
    return;
  }
  if (!('serviceWorker' in navigator) || !isSecureContext) {
    status.textContent = 'Open the preview in a browser with service worker support and a secure connection.';
    return;
  }
  submit.disabled = true;
  status.textContent = 'Opening preview…';
  try {
    registration ??= await navigator.serviceWorker.register('sw.js', {scope: 'site/'});
    const worker = await activatedWorker(registration);
    if (!(await verify(worker, key))) {
      status.textContent = 'The access key could not be verified.';
      return;
    }
    verifiedKey = key;
    input.value = '';
    const section = fragment.get('section');
    iframe.src = 'site/v2/' + (/^[a-z][a-z-]*$/.test(section || '') ? '#' + section : '');
    iframe.hidden = false;
    document.getElementById('gate').hidden = true;
  } catch (error) {
    status.textContent = error.message;
  } finally {
    submit.disabled = false;
  }
}

navigator.serviceWorker?.addEventListener('message', event => {
  if (!verifiedKey || event.source !== registration?.active || event.data !== 'request-key') return;
  event.ports[0]?.postMessage(verifiedKey);
});
access.addEventListener('submit', event => {
  event.preventDefault();
  openPreview(input.value.trim());
});
if (fragment.has('key')) openPreview(fragment.get('key'));
