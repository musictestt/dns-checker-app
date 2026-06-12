const form = document.getElementById("dnsForm");
const domainInput = document.getElementById("domainInput");

const recordDropdown = document.getElementById("recordDropdown");
const recordTrigger = document.getElementById("recordTrigger");
const recordMenu = document.getElementById("recordMenu");
const selectedRecord = document.getElementById("selectedRecord");
const selectedRecordDesc = document.getElementById("selectedRecordDesc");

const continentDropdown = document.getElementById("continentDropdown");
const continentTrigger = document.getElementById("continentTrigger");
const continentMenu = document.getElementById("continentMenu");
const selectedContinent = document.getElementById("selectedContinent");

const checkButton = document.getElementById("checkButton");
const errorBox = document.getElementById("errorBox");
const resultsContainer = document.getElementById("resultsContainer");
const userIpText = document.getElementById("userIpText");
const currentLocationText = document.getElementById("currentLocationText");

let currentController = null;
let isChecking = false;
let selectedRecordType = "A";
let selectedContinentValue = "all";

let cooldownUntil = 0;
const COOLDOWN_MS = 1500;

function showError(message) {
  errorBox.style.display = "block";
  errorBox.textContent = message;
}

function hideError() {
  errorBox.style.display = "none";
  errorBox.textContent = "";
}

function formatDnsError(error) {
  if (!error) {
    return "DNS lookup failed.";
  }

  if (
    error === "ESERVFAIL" ||
    error === "SERVFAIL" ||
    error.includes("server failed")
  ) {
    return "Destination DNS server did not respond with a valid answer.";
  }

  if (error.includes("No") && error.includes("record found")) {
    return error;
  }

  if (error.includes("Domain not found")) {
    return "Domain was not found.";
  }

  if (error.includes("timed out") || error.includes("TIMEOUT")) {
    return "DNS lookup timed out.";
  }

  return error;
}

function isPrivateIp(ip) {
  if (typeof ip !== "string") return false;

  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(part => Number.isNaN(part))) {
    return false;
  }

  const a = parts[0];
  const b = parts[1];

  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

async function copyToClipboard(text, button) {
  const oldText = button.textContent;

  function showCopied() {
    button.textContent = "Copied";
    button.classList.add("copied");

    setTimeout(() => {
      button.textContent = oldText;
      button.classList.remove("copied");
    }, 1200);
  }

  function showFailed() {
    button.textContent = "Failed";

    setTimeout(() => {
      button.textContent = oldText;
    }, 1200);
  }

  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      showCopied();
      return;
    }

    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.top = "-9999px";
    textarea.style.left = "-9999px";

    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();

    const successful = document.execCommand("copy");
    document.body.removeChild(textarea);

    if (successful) {
      showCopied();
    } else {
      showFailed();
    }
  } catch (err) {
    showFailed();
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function createAnswersHtml(result) {
  if (result.status !== "success") {
    return `<div class="empty">${formatDnsError(result.error)}</div>`;
  }

  if (!result.answers || result.answers.length === 0) {
    return '<div class="empty">No records found.</div>';
  }

  return result.answers
    .map(answer => {
      const value =
        typeof answer === "object" ? JSON.stringify(answer) : String(answer);

      const warning = isPrivateIp(value)
        ? `<div class="answer-warning">Private / internal IP detected. This domain may be redirected by the local resolver or network.</div>`
        : "";

      return `
        <div class="answer">
          <div class="answer-main">
            <div class="answer-value">${escapeHtml(value)}</div>
            <button type="button" class="copy-button" data-copy="${escapeHtml(value)}">Copy</button>
          </div>
          ${warning}
        </div>
      `;
    })
    .join("");
}

function createResultCard(item, query) {
  const dcText = item.location.datacenter ? ` — ${item.location.datacenter}` : "";
  const locationText = `${item.location.country} / ${item.location.city}${dcText}`;
  const isSuccess = item.result.status === "success";

  return `
    <section class="card dns-result-card">
      <div class="result-header">
        <div>
          <div class="location">${escapeHtml(locationText)}</div>
          <div class="meta">${escapeHtml(query.domain)} · ${escapeHtml(query.type)}</div>
          <div class="source-badge">${escapeHtml(item.location.sourceLabel || item.location.sourceType || "DNS check")}</div>
        </div>
        <div class="status ${isSuccess ? "success" : "error"}">${isSuccess ? "success" : "error"}</div>
      </div>

      <div class="answers">
        ${createAnswersHtml(item.result)}
      </div>

      <div class="stats">
        <div class="stat">Response time: ${item.gatewayTimeMs ?? "-"} ms</div>
      </div>
    </section>
  `;
}

function renderResults(results, query) {
  resultsContainer.innerHTML = "";

  const ownedResults = results.filter(item => item.location.sourceType === "owned");
  const externalResults = results.filter(item => item.location.sourceType === "external");
  const globalResults = results.filter(item => item.location.sourceType === "global");

  if (ownedResults.length > 0) {
    resultsContainer.insertAdjacentHTML(
      "beforeend",
      `<div class="result-group-title">Our DNS checks</div>`
    );

    ownedResults.forEach(item => {
      resultsContainer.insertAdjacentHTML("beforeend", createResultCard(item, query));
    });
  }

  if (externalResults.length > 0) {
    resultsContainer.insertAdjacentHTML(
      "beforeend",
      `<div class="result-group-title">External DNS checks</div>`
    );

    externalResults.forEach(item => {
      resultsContainer.insertAdjacentHTML("beforeend", createResultCard(item, query));
    });
  }

  if (globalResults.length > 0) {
    resultsContainer.insertAdjacentHTML(
      "beforeend",
      `<div class="result-group-title">Global DNS checks</div>`
    );

    globalResults.forEach(item => {
      resultsContainer.insertAdjacentHTML("beforeend", createResultCard(item, query));
    });
  }

  resultsContainer.querySelectorAll(".copy-button").forEach(button => {
    button.addEventListener("click", () => {
      copyToClipboard(button.dataset.copy, button);
    });
  });
}

/* =========================
   Record dropdown
========================= */

recordTrigger.addEventListener("click", () => {
  recordDropdown.classList.toggle("open");

  if (continentDropdown) {
    continentDropdown.classList.remove("open");
  }
});

recordMenu.querySelectorAll(".select-option").forEach(option => {
  option.addEventListener("click", () => {
    selectedRecordType = option.dataset.value;

    selectedRecord.textContent = option.dataset.value;
    selectedRecordDesc.textContent = option.dataset.desc;

    recordMenu.querySelectorAll(".select-option").forEach(item => {
      item.classList.remove("active");
    });

    option.classList.add("active");
    recordDropdown.classList.remove("open");
  });
});

/* =========================
   Continent dropdown
========================= */

if (continentTrigger && continentDropdown && continentMenu && selectedContinent) {
  continentTrigger.addEventListener("click", () => {
    continentDropdown.classList.toggle("open");
    recordDropdown.classList.remove("open");
  });

  continentMenu.querySelectorAll(".select-option").forEach(option => {
    option.addEventListener("click", () => {
      selectedContinentValue = option.dataset.value || "all";

      const label = option.querySelector("strong")?.textContent?.trim() || "All Continents";
      selectedContinent.textContent = label;

      continentMenu.querySelectorAll(".select-option").forEach(item => {
        item.classList.remove("active");
      });

      option.classList.add("active");
      continentDropdown.classList.remove("open");
    });
  });
}

/* =========================
   Client info
========================= */

async function loadClientInfo() {
  try {
    const response = await fetch("/api/me");
    const data = await response.json();

    if (!response.ok || data.status !== "success") {
      throw new Error("Failed to load client info");
    }

    const country = data.location?.country || "Unknown";
    const city = data.location?.city || "Unknown";

    if (currentLocationText) {
      currentLocationText.textContent = `Current location: ${country} / ${city}`;
    }

    if (userIpText) {
      userIpText.textContent = `Your IP: ${data.ip || "Unknown"}`;
    }
  } catch (err) {
    if (currentLocationText) {
      currentLocationText.textContent = "Current location: Unknown";
    }

    if (userIpText) {
      userIpText.textContent = "Your IP: Unknown";
    }
  }
}

loadClientInfo();

document.addEventListener("click", event => {
  if (recordDropdown && !recordDropdown.contains(event.target)) {
    recordDropdown.classList.remove("open");
  }

  if (continentDropdown && !continentDropdown.contains(event.target)) {
    continentDropdown.classList.remove("open");
  }
});

/* =========================
   Form submit
========================= */

form.addEventListener("submit", async event => {
  event.preventDefault();

  if (isChecking && currentController) {
    currentController.abort();
    cooldownUntil = Date.now() + COOLDOWN_MS;
    return;
  }

  if (Date.now() < cooldownUntil) {
    showError("Please wait a moment before checking again.");
    return;
  }

  hideError();
  recordDropdown.classList.remove("open");

  if (continentDropdown) {
    continentDropdown.classList.remove("open");
  }

  const domain = domainInput.value.trim().toLowerCase();
  const type = selectedRecordType;
  const continent = selectedContinentValue;

  if (!domain) {
    showError("Please enter a domain.");
    return;
  }

  currentController = new AbortController();
  isChecking = true;

  checkButton.disabled = false;
  checkButton.textContent = "Cancel";
  checkButton.classList.add("cancel-mode");

  try {
    const response = await fetch(
      `/api/check?domain=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}&continent=${encodeURIComponent(continent)}`,
      {
        signal: currentController.signal
      }
    );

    const contentType = response.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
      throw new Error("Server returned a non-JSON response. Please try again later.");
    }

    const data = await response.json();

    if (!response.ok || data.status !== "success") {
      showError(data.error || "Request failed.");
      return;
    }

    renderResults(data.results, data.query);
  } catch (err) {
    if (err.name === "AbortError") {
      showError("Request canceled.");
      return;
    }

    showError(err.message || "Network error.");
  } finally {
    isChecking = false;
    currentController = null;
    cooldownUntil = Date.now() + COOLDOWN_MS;

    checkButton.textContent = "Check DNS";
    checkButton.classList.remove("cancel-mode");
    checkButton.disabled = true;

    setTimeout(() => {
      checkButton.disabled = false;
    }, COOLDOWN_MS);
  }
});

/* =========================
   Navbar scroll behavior
========================= */

const navbar = document.querySelector(".navbar");

let lastScrollY = window.scrollY;
let navbarTicking = false;

function handleNavbarScroll() {
  if (!navbar) return;

  const currentScrollY = window.scrollY;

  if (currentScrollY <= 40) {
    navbar.classList.remove("navbar-hidden");
    lastScrollY = currentScrollY;
    navbarTicking = false;
    return;
  }

  if (currentScrollY > lastScrollY && currentScrollY > 120) {
    navbar.classList.add("navbar-hidden");
  }

  if (currentScrollY < lastScrollY) {
    navbar.classList.remove("navbar-hidden");
  }

  lastScrollY = currentScrollY;
  navbarTicking = false;
}

window.addEventListener("scroll", () => {
  if (!navbarTicking) {
    window.requestAnimationFrame(handleNavbarScroll);
    navbarTicking = true;
  }
});
