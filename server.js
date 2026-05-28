		const express = require("express");
const cors = require("cors");

const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = 4000;

app.disable("x-powered-by");

app.use(helmet({
  contentSecurityPolicy: {
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
  }
}));

app.use(cors());
app.use(express.json({ limit: "10kb" }));
app.use(express.static("public"));
app.use(express.static("public"));
app.set("trust proxy", true);



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

app.use("/api/check", apiLimiter);



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

const ALLOWED_TYPES = [
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
];

function isValidDomain(domain) {
  if (!domain || typeof domain !== "string") return false;
  if (domain.length > 253) return false;
  if (domain.includes("..")) return false;
  if (domain.startsWith(".") || domain.endsWith(".")) return false;

  return /^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/.test(domain);
}

function buildLocation(provider) {
  return {
    id: provider.id,
    sourceType: provider.sourceType,
    sourceLabel: provider.sourceLabel,
    priority: provider.priority,
    country: provider.country,
    city: provider.city,
    datacenter: provider.datacenter,
    flag: provider.flag
  };
}

function dnsTypeToGoogleType(type) {
  const map = {
    A: 1,
    NS: 2,
    CNAME: 5,
    MX: 15,
    AAAA: 28,
    PTR: 12,
    TXT: 16,
    SOA: 6,
    SRV: 33,
    CAA: 257,
    DS: 43,
    DNSKEY: 48
  	   };

  return map[type] || type;
}

function googleStatusToError(status, type) {
  const map = {
    0: `No ${type} record found`,
    1: "DNS query format error.",
    2: "Destination DNS server did not respond with a valid answer.",
    3: "Domain was not found.",
    4: "DNS request type is not supported.",
    5: "DNS request was refused."
  };

  return map[status] || `DNS error status ${status}`;
}

function parseGoogleAnswers(data, type) {
  if (!data.Answer || !Array.isArray(data.Answer)) {
    return [];
  }

  const typeMap = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  DS: 43,
  DNSKEY: 48,
  CAA: 257
};

  const wantedType = typeMap[type];

  return data.Answer
    .filter(answer => answer.type === wantedType)
    .map(answer => {
      if (type === "MX") {
        const parts = String(answer.data).trim().split(/\s+/);
        return {
          priority: Number(parts[0]),
          exchange: parts.slice(1).join(" ").replace(/\.$/, "")
        };
      }

      return String(answer.data).replace(/\.$/, "");
    });
}

async function fetchJsonWithTimeout(url, timeoutMs = 4000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        accept: "application/json"
      }
    });

    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function queryOwnedAgent(agent, domain, type) {
  const startTime = Date.now();

  try {
    const url =
      `${agent.url}/resolve?domain=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;

    const data = await fetchJsonWithTimeout(url, 8000);

    return {
      location: buildLocation(agent),
      query: {
        domain,
        type
      },
      result: data.result,
      gatewayTimeMs: Date.now() - startTime
    };
  } catch (err) {
    return {
      location: buildLocation(agent),
      query: {
        domain,
        type
      },
      result: {
        status: "error",
       error: err.name === "AbortError" ? "Agent request timed out." : "Agent request failed.",
        answers: [],
        responseTimeMs: null
      },
      gatewayTimeMs: Date.now() - startTime
    };
  }
}

async function queryGoogleDns(provider, domain, type) {
  const startTime = Date.now();

  try {
    const googleType = dnsTypeToGoogleType(type);
    const url =
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(googleType)}`;

    const data = await fetchJsonWithTimeout(url, 5000);

    const answers = parseGoogleAnswers(data, type);
    const success = data.Status === 0 && answers.length > 0;

    return {
      location: buildLocation(provider),
      query: {
        domain,
        type
      },
      result: {
        status: success ? "success" : "error",
        error: success ? null : googleStatusToError(data.Status, type),
        answers,
        responseTimeMs: Date.now() - startTime
      },
      gatewayTimeMs: Date.now() - startTime
    };
  } catch (err) {
    return {
      location: buildLocation(provider),
      query: {
        domain,
        type
      },
      result: {
        status: "error",
        error: err.name === "AbortError" ? "External DNS request timed out." : "External DNS request failed.",
        answers: [],
        responseTimeMs: null
      },
      gatewayTimeMs: Date.now() - startTime
    };
  }
}

app.get("/api/client-ip", (req, res) => {
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.ip ||
    req.socket.remoteAddress ||
    "Unknown";

  res.json({
    ip
  });
});


app.get("/api/locations", (req, res) => {
  res.json({
    locations: [...agents, ...externalProviders].map(provider => buildLocation(provider))
  });
});

app.get("/api/check", async (req, res) => {
  const domain = String(req.query.domain || "").trim().toLowerCase();
  const type = String(req.query.type || "A").toUpperCase();

  if (!domain) {
    return res.status(400).json({
      status: "error",
      error: "domain is required"
    });
  }

  if (!isValidDomain(domain)) {
    return res.status(400).json({
      status: "error",
      error: "invalid domain"
    });
  }

  if (!ALLOWED_TYPES.includes(type)) {
    return res.status(400).json({
      status: "error",
      error: "unsupported record type",
      allowedTypes: ALLOWED_TYPES
    });
  }

  const ownedResults = await Promise.all(
    agents.map(agent => queryOwnedAgent(agent, domain, type))
  );

  const externalResults = await Promise.all(
    externalProviders.map(provider => queryGoogleDns(provider, domain, type))
  );

  const results = [...ownedResults, ...externalResults];

  results.sort((a, b) => {
    return (a.location.priority || 999) - (b.location.priority || 999);
  });

  res.json({
    status: "success",
    query: {
      domain,
      type
    },
    results
  });
});

app.listen(PORT, "127.0.0.1", () => {
  console.log(`DNS Checker backend running on port ${PORT}`);
});
