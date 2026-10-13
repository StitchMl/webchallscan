"use strict";

const MESSAGE_TYPE = "webchallscan.capture-session.v1";
const SCHEMA = "webchallscan/browser-session-v1";
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost"]);
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,256}$/;

function validateEndpoint(rawEndpoint) {
  let endpoint;
  try {
    endpoint = new URL(rawEndpoint);
  } catch {
    throw new Error("Invalid listener URL.");
  }

  if (
    endpoint.protocol !== "http:" ||
    !LOOPBACK_HOSTS.has(endpoint.hostname) ||
    !endpoint.port ||
    endpoint.pathname !== "/v1/session/import" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash
  ) {
    throw new Error(
      "Listener must be http://127.0.0.1:PORT/v1/session/import or localhost."
    );
  }
  return endpoint.href;
}

function validateToken(token) {
  if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) {
    throw new Error("One-shot token must contain 32-256 base64url characters.");
  }
  return token;
}

function normalizePartitionKey(partitionKey) {
  if (!partitionKey || typeof partitionKey !== "object") {
    return null;
  }
  return {
    top_level_site: partitionKey.topLevelSite || "",
    has_cross_site_ancestor: Boolean(partitionKey.hasCrossSiteAncestor)
  };
}

function normalizeCookie(cookie) {
  return {
    name: cookie.name,
    value: cookie.value,
    domain: cookie.domain,
    path: cookie.path,
    secure: Boolean(cookie.secure),
    http_only: Boolean(cookie.httpOnly),
    same_site: cookie.sameSite || "unspecified",
    session: Boolean(cookie.session),
    expiration_date: Number.isFinite(cookie.expirationDate)
      ? cookie.expirationDate
      : null,
    store_id: cookie.storeId || "",
    partition_key: normalizePartitionKey(cookie.partitionKey)
  };
}

function cookieSortKey(cookie) {
  const partition = cookie.partition_key
    ? `${cookie.partition_key.top_level_site}:${cookie.partition_key.has_cross_site_ancestor}`
    : "";
  return [cookie.store_id, cookie.domain, cookie.path, cookie.name, partition].join("\u0000");
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function activeHttpTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab || !tab.url) {
    throw new Error("No active browser tab is available.");
  }

  const url = new URL(tab.url);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Active tab must use HTTP or HTTPS.");
  }
  return { tab, url };
}

async function activeCookieStoreId(tabId) {
  const stores = await chrome.cookies.getAllCookieStores();
  const store = stores
    .slice()
    .sort((left, right) => compareText(left.id, right.id))
    .find((candidate) => candidate.tabIds.includes(tabId));
  if (!store) {
    throw new Error("Cannot identify the active tab cookie store.");
  }
  return store.id;
}

async function activeBrowserContext(tabId) {
  const results = await chrome.scripting.executeScript({
    target: { tabId },
    func: () => ({
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      mobile: Boolean(navigator.userAgentData?.mobile)
    })
  });
  const context = results[0]?.result;
  if (!context || typeof context !== "object") {
    return { userAgent: "", language: "", platform: "", mobile: false };
  }
  return context;
}

async function buildCapture() {
  const { tab, url } = await activeHttpTab();
  const storeId = await activeCookieStoreId(tab.id);
  const [unpartitionedCookies, partitionedCookies, browserContext] = await Promise.all([
    chrome.cookies.getAll({ url: url.href, storeId }),
    chrome.cookies
      .getAll({ url: url.href, storeId, partitionKey: { topLevelSite: url.origin } })
      .catch(() => []),
    activeBrowserContext(tab.id)
  ]);
  const cookiesByIdentity = new Map();
  for (const cookie of [...unpartitionedCookies, ...partitionedCookies]) {
    const normalized = normalizeCookie(cookie);
    cookiesByIdentity.set(cookieSortKey(normalized), normalized);
  }
  const cookies = [...cookiesByIdentity.values()];
  cookies.sort((left, right) => compareText(cookieSortKey(left), cookieSortKey(right)));

  return {
    schema: SCHEMA,
    active_tab: {
      url: url.href,
      origin: url.origin,
      incognito: Boolean(tab.incognito)
    },
    browser: {
      user_agent: browserContext.userAgent || "",
      accept_language: browserContext.language || "",
      platform: browserContext.platform || "",
      mobile: Boolean(browserContext.mobile)
    },
    cookies
  };
}

async function sendCapture(endpoint, token) {
  const capture = await buildCapture();
  const response = await fetch(validateEndpoint(endpoint), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Webchallscan-Token": validateToken(token)
    },
    body: JSON.stringify(capture),
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer"
  });

  if (!response.ok) {
    throw new Error(`Local listener rejected capture (HTTP ${response.status}).`);
  }
  return {};
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== MESSAGE_TYPE) {
    return false;
  }

  sendCapture(message.endpoint, message.token)
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: error.message }));
  return true;
});
