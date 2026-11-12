/**
 * Zaslon Browser — Air-gapped Windows/Electron Worker Shim for Bergamot WASM NMT
 *
 * Fixes Windows `file://` URL pathname handling inside `node:worker_threads`,
 * resolves unpacked ASAR paths when packaged, and restricts `fetch` strictly
 * to local worker assets so zero outbound network requests can occur.
 */

const { parentPort } = require('node:worker_threads');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { fileURLToPath, pathToFileURL } = require('node:url');

function resolveBergamotWorkerDir() {
  const pkgEntry = require.resolve('@mkljczk/bergamot-translator/package.json');
  let workerDir = path.join(path.dirname(pkgEntry), 'worker');
  if (workerDir.includes('app.asar') && !workerDir.includes('app.asar.unpacked')) {
    const unpacked = workerDir.replace('app.asar', 'app.asar.unpacked');
    if (fs.existsSync(unpacked)) {
      workerDir = unpacked;
    }
  }
  return workerDir;
}

const workerDir = resolveBergamotWorkerDir();
const workerEntry = path.join(workerDir, 'translator-worker.js');

global.Module = {};

const localOnlyFetch = async input => {
  const raw = typeof input === 'string' ? input : input && input.href ? input.href : String(input);
  let targetPath;
  if (raw.startsWith('file:')) {
    targetPath = path.resolve(fileURLToPath(raw));
  } else if (/^https?:/i.test(raw)) {
    throw new Error(`Air-gapped WASM worker blocked remote fetch: ${raw}`);
  } else {
    targetPath = path.resolve(workerDir, path.basename(raw));
  }

  // Allow reading only inside the Bergamot worker directory
  const normalizedWorkerDir = path.resolve(workerDir);
  if (
    targetPath !== normalizedWorkerDir &&
    !targetPath.startsWith(normalizedWorkerDir + path.sep)
  ) {
    throw new Error(`Air-gapped WASM worker denied path outside worker directory: ${targetPath}`);
  }

  const buf = await fsp.readFile(targetPath);
  const contentType = targetPath.endsWith('.wasm')
    ? 'application/wasm'
    : 'application/octet-stream';
  return new Response(buf, {
    status: 200,
    statusText: 'OK',
    headers: {
      'Content-Type': contentType,
      'Content-Length': String(buf.length)
    }
  });
};

globalThis.fetch = localOnlyFetch;

global.self = {
  addEventListener(eventName, callback) {
    parentPort.on(eventName, data => callback({ data }));
  },
  postMessage(message) {
    parentPort.postMessage(message);
  },
  importScripts(...scripts) {
    if (global.self && global.self.Module) {
      global.Module = global.self.Module;
    }
    for (const scriptName of scripts) {
      const safeName = path.basename(scriptName);
      const code = fs.readFileSync(path.join(workerDir, safeName), 'utf8');
      eval.call(global, code);
    }
  },
  fetch: localOnlyFetch,
  get location() {
    return pathToFileURL(workerEntry);
  }
};

require(workerEntry);
