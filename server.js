const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const net = require("net");
const { execFile } = require("child_process");

const app = express();
const PORT = process.env.PORT || 4000;

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(cors());

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"]
      }
    },
    referrerPolicy: {
      policy: "no-referrer"
    },
    frameguard: {
      action: "sameorigin"
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: "error",
    error: "Too many requests. Please try again later."
  }
});

const meLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: "error",
    error: "Too many requests. Please try again later."
  }
});

const ALLOWED_TYPES = new Set([
  "A",
  "AAAA",
  "NS",
  "CNAME",
  "MX",
  "PTR",
  "SRV",
  "SOA",
  "TXT",
  "CAA",
  "DS",
  "DNSKEY"
]);

const agents = [
  {
    id: "iran-tehran-parsvds",
    sourceType: "owned",
    sourceLabel: "Our server",
    priority: 1,
    country: "Iran",
    city: "Tehran",
    datacenter: "Parsvds",
    flag: "IR",
    url: "http://127.0.0.1:3000"
  }
];

const externalProviders = [
  {
    id: "google-public-dns",
    sourceType: "external",
    sourceLabel: "External check",
    priority: 100,
    country: "Global",
    city: "Google Public DNS",
    datacenter: "Google",
    flag: "GOOGLE",
    provider: "google-doh"
  }
];

const ipLocationCache = new Map();
const IP_LOCATION_CACHE_TTL_MS = 6 * 60 * 60 * 1000;

function isValidDomain(domain) {
  if (!domain || typeof domain !== "string") return false;

  const clean = domain.trim();

  if (clean.length > 253) return false;
  if (clean.includes("..")) return false;

  return /^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/.test(clean);
}

function isPrivateIp(ip) {
  if (!ip || typeof ip !== "string") return true;

  const clean = ip.replace("::ffff:", "");

  if (
    clean === "127.0.0.1" ||
    clean === "::1" ||
    clean.startsWith("10.") ||
    clean.startsWith("192.168.") ||
    clean.startsWith("172.16.") ||
    clean.startsWith("172.17.") ||
    clean.startsWith("172.18.") ||
    clean.startsWith("172.19.") ||
    clean.startsWith("172.20.") ||
    clean.startsWith("172.21.") ||
    clean.startsWith("172.22.") ||
    clean.startsWith("172.23.") ||
    clean.startsWith("172.24.") ||
    clean.startsWith("172.25.") ||
    clean.startsWith("172.26.") ||
    clean.startsWith("172.27.") ||
    clean.startsWith("172.28.") ||
    clean.startsWith("172.29.") ||
    clean.startsWith("172.30.") ||
    clean.startsWith("172.31.")
  ) {
    return true;
  }

  return false;
}

function getClientIp(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  const realIp = req.headers["x-real-ip"];
  const cfIp = req.headers["cf-connecting-ip"];

  let ip = "";

  if (typeof forwardedFor === "string" && forwardedFor.trim()) {
    ip = forwardedFor.split(",")[0].trim();
  } else if (typeof realIp === "string" && realIp.trim()) {
    ip = realIp.trim();
  } else if (typeof cfIp === "string" && cfIp.trim()) {
    ip = cfIp.trim();
  } else if (req.ip) {
    ip = req.ip;
  } else if (req.socket && req.socket.remoteAddress) {
    ip = req.socket.remoteAddress;
  }

  ip = ip.replace("::ffff:", "");

  if (!net.isIP(ip)) {
    return "";
  }

  return ip;
}

function execCurlJson(url, timeoutSeconds = 5) {
  return new Promise((resolve, reject) => {
    execFile(
      "curl",
      ["-sS", "-m", String(timeoutSeconds), url],
      {
        timeout: timeoutSeconds * 1000 + 1000
      },
      (error, stdout) => {
        if (error) {
          reject(error);
          return;
        }

        try {
          resolve(JSON.parse(stdout));
        } catch (parseError) {
          reject(parseError);
        }
      }
    );
  });
}

async function getIpLocation(ip) {
  if (!ip || isPrivateIp(ip)) {
    return {
      country: "Unknown",
      city: "Unknown"
    };
  }

  const cached = ipLocationCache.get(ip);

  if (cached && Date.now() - cached.createdAt < IP_LOCATION_CACHE_TTL_MS) {
    return cached.location;
  }

  let location = {
    country: "Unknown",
    city: "Unknown"
  };

  try {
    const data = await execCurlJson(`https://ipwho.is/${encodeURIComponent(ip)}`, 5);

    if (data && data.success !== false) {
      location = {
        country: data.country || "Unknown",
        city: data.city || "Unknown"
      };
    }
  } catch (error) {
    try {
      const data = await execCurlJson(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, 5);

      if (data && !data.error) {
        location = {
          country: data.country_name || "Unknown",
          city: data.city || "Unknown"
        };
      }
    } catch (secondError) {
      location = {
        country: "Unknown",
        city: "Unknown"
      };
    }
  }

  ipLocationCache.set(ip, {
    createdAt: Date.now(),
    location
  });

  return location;
}

function fetchJsonWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  return fetch(url, {
    signal: controller.signal,
    headers: {
      accept: "application/json"
    }
  })
    .then(async (response) => {
      const text = await response.text();

      let data = null;

      try {
        data = JSON.parse(text);
      } catch (error) {
        throw new Error("Invalid JSON response");
      }

      if (!response.ok) {
        throw new Error(data && data.error ? data.error : "Request failed");
      }

      return data;
    })
    .finally(() => clearTimeout(timer));
}

function normalizeGoogleAnswer(type, answer) {
  if (!Array.isArray(answer)) return [];

  return answer
    .filter((item) => item && typeof item.data === "string")
    .map((item) => {
      if (type === "MX") {
        return item.data.replace(/\.$/, "");
      }

      if (type === "NS" || type === "CNAME" || type === "PTR") {
        return item.data.replace(/\.$/, "");
      }

      return item.data;
    });
}

async function queryOwnedAgent(agent, domain, type) {
  const startedAt = process.hrtime.bigint();

  try {
    const url =
      `${agent.url}/resolve?domain=${encodeURIComponent(domain)}` +
      `&type=${encodeURIComponent(type)}`;

    const result = await fetchJsonWithTimeout(url, 10000);

    const finishedAt = process.hrtime.bigint();
    const gatewayTimeMs = Number(finishedAt - startedAt) / 1_000_000;

    return {
      location: {
        id: agent.id,
        sourceType: agent.sourceType,
        sourceLabel: agent.sourceLabel,
        priority: agent.priority,
        country: agent.country,
        city: agent.city,
        datacenter: agent.datacenter,
        flag: agent.flag
      },
      query: {
        domain,
        type
      },
      result: {
        status: result.status || "error",
        error: result.error || null,
        answers: Array.isArray(result.answers) ? result.answers : [],
        responseTimeMs:
          result.responseTimeMs !== undefined && result.responseTimeMs !== null
            ? result.responseTimeMs
            : null
      },
      gatewayTimeMs: Number(gatewayTimeMs.toFixed(2))
    };
  } catch (error) {
    const finishedAt = process.hrtime.bigint();
    const gatewayTimeMs = Number(finishedAt - startedAt) / 1_000_000;

    return {
      location: {
        id: agent.id,
        sourceType: agent.sourceType,
        sourceLabel: agent.sourceLabel,
        priority: agent.priority,
        country: agent.country,
        city: agent.city,
        datacenter: agent.datacenter,
        flag: agent.flag
      },
      query: {
        domain,
        type
      },
      result: {
        status: "error",
        error: "Internal DNS agent did not respond.",
        answers: [],
        responseTimeMs: null
      },
      gatewayTimeMs: Number(gatewayTimeMs.toFixed(2))
    };
  }
}

async function queryGoogleDns(provider, domain, type) {
  const startedAt = process.hrtime.bigint();

  try {
    const url =
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}` +
      `&type=${encodeURIComponent(type)}`;

    const data = await fetchJsonWithTimeout(url, 10000);

    const finishedAt = process.hrtime.bigint();
    const gatewayTimeMs = Number(finishedAt - startedAt) / 1_000_000;

    const answers = normalizeGoogleAnswer(type, data.Answer);

    let status = "success";
    let error = null;

    if (!answers.length) {
      status = "error";
      error = `No ${type} record found`;
    }

    return {
      location: {
        id: provider.id,
        sourceType: provider.sourceType,
        sourceLabel: provider.sourceLabel,
        priority: provider.priority,
        country: provider.country,
        city: provider.city,
        datacenter: provider.datacenter,
        flag: provider.flag
      },
      query: {
        domain,
        type
      },
      result: {
        status,
        error,
        answers,
        responseTimeMs: Number(gatewayTimeMs.toFixed(2))
      },
      gatewayTimeMs: Number(gatewayTimeMs.toFixed(2))
    };
  } catch (error) {
    const finishedAt = process.hrtime.bigint();
    const gatewayTimeMs = Number(finishedAt - startedAt) / 1_000_000;

    return {
      location: {
        id: provider.id,
        sourceType: provider.sourceType,
        sourceLabel: provider.sourceLabel,
        priority: provider.priority,
        country: provider.country,
        city: provider.city,
        datacenter: provider.datacenter,
        flag: provider.flag
      },
      query: {
        domain,
        type
      },
      result: {
        status: "error",
        error: "External DNS request timed out.",
        answers: [],
        responseTimeMs: null
      },
      gatewayTimeMs: Number(gatewayTimeMs.toFixed(2))
    };
  }
}

async function queryExternalProvider(provider, domain, type) {
  if (provider.provider === "google-doh") {
    return queryGoogleDns(provider, domain, type);
  }

  return {
    location: {
      id: provider.id,
      sourceType: provider.sourceType,
      sourceLabel: provider.sourceLabel,
      priority: provider.priority,
      country: provider.country,
      city: provider.city,
      datacenter: provider.datacenter,
      flag: provider.flag
    },
    query: {
      domain,
      type
    },
    result: {
      status: "error",
      error: "External provider is not supported.",
      answers: [],
      responseTimeMs: null
    },
    gatewayTimeMs: null
  };
}

app.get("/api/me", meLimiter, async (req, res) => {
  const ip = getClientIp(req);
  const location = await getIpLocation(ip);

  res.json({
    status: "success",
    ip: ip || "Unknown",
    location
  });
});

app.get("/api/client-ip", meLimiter, async (req, res) => {
  const ip = getClientIp(req);
  const location = await getIpLocation(ip);

  res.json({
    status: "success",
    ip: ip || "Unknown",
    location
  });
});

app.get("/api/locations", (req, res) => {
  res.json({
    status: "success",
    locations: [
      ...agents.map((agent) => ({
        id: agent.id,
        sourceType: agent.sourceType,
        sourceLabel: agent.sourceLabel,
        priority: agent.priority,
        country: agent.country,
        city: agent.city,
        datacenter: agent.datacenter,
        flag: agent.flag
      })),
      ...externalProviders.map((provider) => ({
        id: provider.id,
        sourceType: provider.sourceType,
        sourceLabel: provider.sourceLabel,
        priority: provider.priority,
        country: provider.country,
        city: provider.city,
        datacenter: provider.datacenter,
        flag: provider.flag
      }))
    ]
  });
});

app.get("/api/check", apiLimiter, async (req, res) => {
  const domain = String(req.query.domain || "").trim().toLowerCase();
  const type = String(req.query.type || "A").trim().toUpperCase();

  if (!ALLOWED_TYPES.has(type)) {
    return res.status(400).json({
      status: "error",
      error: "Unsupported DNS record type."
    });
  }

  if (!isValidDomain(domain)) {
    return res.status(400).json({
      status: "error",
      error: "Please enter a valid domain name."
    });
  }

  try {
    const ownedResults = await Promise.all(
      agents.map((agent) => queryOwnedAgent(agent, domain, type))
    );

    const externalResults = await Promise.all(
      externalProviders.map((provider) => queryExternalProvider(provider, domain, type))
    );

    const results = [...ownedResults, ...externalResults].sort((a, b) => {
      const firstPriority = a.location && a.location.priority ? a.location.priority : 999;
      const secondPriority = b.location && b.location.priority ? b.location.priority : 999;

      return firstPriority - secondPriority;
    });

    res.json({
      status: "success",
      query: {
        domain,
        type
      },
      results
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      error: "DNS check failed. Please try again."
    });
  }
});

app.get("/{*splat}", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, "127.0.0.1", () => {
  console.log(`DNS Checker backend running on port ${PORT}`);
});
