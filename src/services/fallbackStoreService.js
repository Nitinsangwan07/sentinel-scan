import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const storeFile = path.resolve(__dirname, "../../data/fallback/store.json");

let cache = null;

function createEmptyStore() {
  return {
    users: [],
    scans: [],
    reports: [],
    updatedAt: new Date().toISOString(),
  };
}

async function ensureFile() {
  await fs.mkdir(path.dirname(storeFile), { recursive: true });

  try {
    await fs.access(storeFile);
  } catch {
    await fs.writeFile(storeFile, JSON.stringify(createEmptyStore(), null, 2), "utf8");
  }
}

async function loadStore() {
  if (cache) {
    return cache;
  }

  await ensureFile();

  try {
    const contents = await fs.readFile(storeFile, "utf8");
    const parsed = JSON.parse(contents);
    cache = {
      ...createEmptyStore(),
      ...parsed,
    };
  } catch {
    cache = createEmptyStore();
  }

  return cache;
}

async function saveStore(store) {
  cache = {
    ...store,
    updatedAt: new Date().toISOString(),
  };
  await ensureFile();
  await fs.writeFile(storeFile, JSON.stringify(cache, null, 2), "utf8");
}

export async function getFallbackCollection(name) {
  const store = await loadStore();
  return store[name];
}

export async function setFallbackCollection(name, value) {
  const store = await loadStore();
  store[name] = value;
  await saveStore(store);
  return store[name];
}

export function createFallbackId() {
  return crypto.randomUUID();
}
