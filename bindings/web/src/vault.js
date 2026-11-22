// Reusable browser vault backed by IndexedDB and a non-extractable WebCrypto AES-256-GCM key.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function idbRequest(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("IndexedDB request failed"));
  });
}

function idbTransactionDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error || new Error("IndexedDB transaction failed"));
    tx.onabort = () => reject(tx.error || new Error("IndexedDB transaction aborted"));
  });
}

export function createIndexedDbVault({
  dbName = "tendril-vault-v1",
  storeName = "vault",
  wrappingKeyId = "wrapping-key",
  aadPrefix = "tendril.vault.v1",
  isSecureContext = undefined,
  cryptoSubtle = undefined,
  getRandomValues = undefined,
  indexedDB = undefined,
} = {}) {
  let dbPromise = null;

  function resolveEnv() {
    const secure =
      isSecureContext !== undefined
        ? Boolean(isSecureContext)
        : Boolean(globalThis.window ? globalThis.window.isSecureContext : globalThis.isSecureContext);
    const subtle = cryptoSubtle || globalThis.crypto?.subtle;
    const rng =
      getRandomValues ||
      (globalThis.crypto?.getRandomValues
        ? (buf) => globalThis.crypto.getRandomValues(buf)
        : null);
    const idb = indexedDB || globalThis.indexedDB;
    if (!secure || !subtle || !rng || !idb) {
      throw new Error("Secure WebCrypto AES-GCM and IndexedDB context required for Tendril vault");
    }
    return { subtle, rng, idb };
  }

  function openDb() {
    const { idb } = resolveEnv();
    if (!dbPromise) {
      dbPromise = new Promise((resolve, reject) => {
        const req = idb.open(dbName, 1);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains(storeName)) {
            db.createObjectStore(storeName);
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => {
          dbPromise = null;
          reject(req.error || new Error("failed opening IndexedDB vault"));
        };
      });
    }
    return dbPromise;
  }

  async function getOrCreateWrappingKey(db, subtle) {
    const readTx = db.transaction(storeName, "readonly");
    const existing = await idbRequest(readTx.objectStore(storeName).get(wrappingKeyId));
    await idbTransactionDone(readTx);
    if (existing) {
      return existing;
    }
    const generated = await subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    const writeTx = db.transaction(storeName, "readwrite");
    const store = writeTx.objectStore(storeName);
    const current = await idbRequest(store.get(wrappingKeyId));
    if (current) {
      await idbTransactionDone(writeTx);
      return current;
    }
    store.put(generated, wrappingKeyId);
    await idbTransactionDone(writeTx);
    return generated;
  }

  async function writeBytes(entryId, plaintextBytes) {
    if (!(plaintextBytes instanceof Uint8Array)) {
      throw new TypeError("writeBytes expects a Uint8Array");
    }
    const { subtle, rng } = resolveEnv();
    const db = await openDb();
    const key = await getOrCreateWrappingKey(db, subtle);
    const iv = rng(new Uint8Array(12));
    const aad = encoder.encode(`${aadPrefix}:${entryId}`);
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      key,
      plaintextBytes
    );
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).put({ iv, ct: new Uint8Array(ct) }, entryId);
    await idbTransactionDone(tx);
  }

  async function readBytes(entryId) {
    const { subtle } = resolveEnv();
    const db = await openDb();
    const key = await getOrCreateWrappingKey(db, subtle);
    const tx = db.transaction(storeName, "readonly");
    const record = await idbRequest(tx.objectStore(storeName).get(entryId));
    await idbTransactionDone(tx);
    if (!record || !record.iv || !record.ct) {
      return null;
    }
    const aad = encoder.encode(`${aadPrefix}:${entryId}`);
    const ptBuf = await subtle.decrypt(
      { name: "AES-GCM", iv: record.iv, additionalData: aad },
      key,
      record.ct
    );
    return new Uint8Array(ptBuf);
  }

  async function writeString(entryId, value) {
    const bytes = encoder.encode(value);
    try {
      await writeBytes(entryId, bytes);
    } finally {
      bytes.fill(0);
    }
  }

  async function readString(entryId) {
    const bytes = await readBytes(entryId);
    if (!bytes) {
      return null;
    }
    try {
      return decoder.decode(bytes);
    } finally {
      bytes.fill(0);
    }
  }

  async function del(entryId) {
    const db = await openDb();
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).delete(entryId);
    await idbTransactionDone(tx);
  }

  async function clear() {
    const db = await openDb();
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).clear();
    await idbTransactionDone(tx);
  }

  async function close() {
    if (!dbPromise) {
      return;
    }
    const db = await dbPromise;
    dbPromise = null;
    if (typeof db.close === "function") {
      db.close();
    }
  }

  return {
    readString,
    writeString,
    readBytes,
    writeBytes,
    delete: del,
    clear,
    close,
  };
}

export const openTendrilVault = createIndexedDbVault;
