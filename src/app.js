/* app.js — CKAN Swagger UX — standalone web service */

(() => {
  "use strict";

  /* ================================================================
     1. SECURITY HELPERS
     ================================================================ */

  /**
   * Escape a string for safe embedding in OpenAPI markdown/HTML descriptions.
   * Prevents XSS via Swagger UI's markdown renderer.
   */
  function escapeMarkdown(str) {
    if (str === null || str === undefined) return "";
    const s = String(str);
    return s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;")
      .replace(/`/g, "&#x60;")
      .replace(/\|/g, "&#124;")
      .replace(/\[/g, "&#91;")
      .replace(/\]/g, "&#93;")
      .replace(/\(/g, "&#40;")
      .replace(/\)/g, "&#41;")
      .replace(/\\/g, "&#92;");
  }

  /**
   * Escape a PostgreSQL identifier by doubling internal double-quotes.
   * Prevents SQL injection via malicious field names.
   */
  function safeSqlIdentifier(name) {
    return '"' + String(name).replace(/"/g, '""') + '"';
  }

  /**
   * Truncate a string to a maximum length.
   */
  function truncate(str, maxLen) {
    if (str === null || str === undefined) return "";
    const s = String(str);
    return s.length > maxLen ? s.substring(0, maxLen) + "\u2026" : s;
  }

  const MAX_FIELD_NAME_LEN = 100;
  const MAX_VALUE_LEN = 200;
  const MAX_INTROSPECT_FIELDS = 50;
  const MAX_CONCURRENT_SQL = 5;

  /* ================================================================
     2. URL PARSING + VALIDATION
     ================================================================ */

  const CKAN_RESOURCE_RE = /\/dataset\/([^/]+)\/resource\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;

  /**
   * Parse a CKAN resource URL into its components.
   * Returns { baseUrl, datasetName, resourceId } or null.
   */
  function parseCkanUrl(urlStr) {
    try {
      const url = new URL(urlStr.trim());

      // Enforce HTTPS only
      if (url.protocol !== "https:") return null;

      // Reject URLs with embedded credentials
      if (url.username || url.password) return null;

      // Reject private/reserved IP ranges
      const hostname = url.hostname;
      if (isPrivateHost(hostname)) return null;

      const m = url.pathname.match(CKAN_RESOURCE_RE);
      if (!m) return null;

      return {
        baseUrl: url.origin,
        datasetName: m[1],
        resourceId: m[2]
      };
    } catch (e) {
      return null;
    }
  }

  /**
   * Reject private/reserved IP ranges and localhost.
   */
  function isPrivateHost(hostname) {
    if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1") return true;
    // IPv4 private ranges
    const parts = hostname.split(".");
    if (parts.length === 4 && parts.every(p => /^\d+$/.test(p))) {
      const a = parseInt(parts[0], 10);
      const b = parseInt(parts[1], 10);
      if (a === 10) return true;                          // 10.0.0.0/8
      if (a === 172 && b >= 16 && b <= 31) return true;   // 172.16.0.0/12
      if (a === 192 && b === 168) return true;             // 192.168.0.0/16
      if (a === 169 && b === 254) return true;             // 169.254.0.0/16 (link-local / cloud metadata)
      if (a === 127) return true;                          // 127.0.0.0/8
      if (a === 0) return true;                            // 0.0.0.0/8
    }
    return false;
  }

  /* ================================================================
     3. CKAN API CLIENT
     ================================================================ */

  // Whether to route requests through the server-side CORS proxy.
  // Auto-detected on first request: if direct fetch fails with a network error
  // (CORS block), subsequent requests use the proxy.
  let useProxy = false;

  function authHeaders(username, password) {
    const h = {};
    if (username) h["Authorization"] = "Basic " + btoa(username + ":" + password);
    return h;
  }

  /**
   * Make a fetch request, falling back to the CORS proxy if direct fails.
   * The proxy routes through /proxy/api/action/... with X-CKAN-Target header.
   */
  async function ckanFetch(baseUrl, path, options) {
    if (!useProxy) {
      try {
        const resp = await fetch(`${baseUrl}${path}`, options);
        return resp;
      } catch (e) {
        // Network error = likely CORS block. Switch to proxy for all future requests.
        if (e.name === "TypeError" && e.message.includes("Failed to fetch")) {
          console.log("CORS blocked, switching to proxy mode");
          useProxy = true;
        } else {
          throw e;
        }
      }
    }

    // Proxy mode: route through our nginx CORS proxy at /proxy/...
    const proxyHeaders = { ...(options.headers || {}) };
    proxyHeaders["X-CKAN-Target"] = baseUrl;
    const proxyOpts = { ...options, headers: proxyHeaders };
    return fetch(`${window.location.origin}/proxy${path}`, proxyOpts);
  }

  async function ckanGet(baseUrl, path, headers) {
    const resp = await ckanFetch(baseUrl, path, { headers });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.success ? data.result : null;
  }

  async function ckanSql(baseUrl, sql, headers) {
    try {
      const resp = await ckanFetch(baseUrl, "/api/action/datastore_search_sql", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify({ sql })
      });
      if (!resp.ok) return null;
      const data = await resp.json();
      return data.success ? data.result : null;
    } catch (e) {
      return null;
    }
  }

  /* ================================================================
     4. DEEP INTROSPECTION
     ================================================================ */

  async function runWithConcurrency(tasks, limit) {
    const results = [];
    let index = 0;
    async function next() {
      const i = index++;
      if (i >= tasks.length) return;
      results[i] = await tasks[i]();
      await next();
    }
    const workers = Array.from({ length: Math.min(limit, tasks.length) }, () => next());
    await Promise.all(workers);
    return results;
  }

  async function deepIntrospect(baseUrl, resourceId, username, password, onProgress) {
    const headers = authHeaders(username, password);
    const tableName = safeSqlIdentifier(resourceId);

    if (onProgress) onProgress("Fetching schema metadata...");

    const [metaResult, sampleResult] = await Promise.all([
      ckanGet(baseUrl, `/api/action/datastore_search?resource_id=${encodeURIComponent(resourceId)}&limit=0`, headers),
      ckanGet(baseUrl, `/api/action/datastore_search?resource_id=${encodeURIComponent(resourceId)}&limit=5`, headers)
    ]);

    if (!metaResult || !metaResult.fields) return null;

    const fields = metaResult.fields.filter(f => f.id !== "_id");
    const totalRecords = metaResult.total || 0;
    const sampleRecords = (sampleResult && sampleResult.records) || [];

    const SAFE_FIELD_RE = /^[a-zA-Z0-9_\- .(),]+$/;
    const safeFields = fields.filter(f => SAFE_FIELD_RE.test(f.id) && f.id.length <= MAX_FIELD_NAME_LEN);

    const textFields = safeFields.filter(f =>
      f.type === "text" || f.type === "varchar" || f.type === "name"
    ).slice(0, MAX_INTROSPECT_FIELDS);

    const enumData = {};
    let completed = 0;
    const totalQueries = textFields.length + safeFields.filter(f =>
      ["int", "int4", "int8", "float8", "numeric", "timestamp"].includes(f.type)
    ).slice(0, MAX_INTROSPECT_FIELDS).length;

    const enumTasks = textFields.map((f) => async () => {
      const safeId = safeSqlIdentifier(f.id);
      const sql = `SELECT DISTINCT ${safeId} FROM ${tableName} WHERE ${safeId} IS NOT NULL ORDER BY ${safeId} LIMIT 51`;
      const result = await ckanSql(baseUrl, sql, headers);
      if (result && result.records) {
        const values = result.records
          .map(r => truncate(r[f.id], MAX_VALUE_LEN))
          .filter(v => v !== null && v !== "");
        enumData[f.id] = {
          values: values.slice(0, 50),
          isEnum: values.length <= 25,
          distinctCount: values.length >= 51 ? "50+" : values.length
        };
      }
      completed++;
      if (onProgress) onProgress(`Introspecting fields... (${completed}/${totalQueries})`);
    });

    const numericFields = safeFields.filter(f =>
      ["int", "int4", "int8", "float8", "numeric", "timestamp"].includes(f.type)
    ).slice(0, MAX_INTROSPECT_FIELDS);

    const rangeData = {};
    const rangeTasks = numericFields.map((f) => async () => {
      const safeId = safeSqlIdentifier(f.id);
      const sql = `SELECT MIN(${safeId}) as min_val, MAX(${safeId}) as max_val FROM ${tableName} WHERE ${safeId} IS NOT NULL`;
      const result = await ckanSql(baseUrl, sql, headers);
      if (result && result.records && result.records[0]) {
        rangeData[f.id] = {
          min: result.records[0].min_val,
          max: result.records[0].max_val
        };
      }
      completed++;
      if (onProgress) onProgress(`Introspecting fields... (${completed}/${totalQueries})`);
    });

    await runWithConcurrency([...enumTasks, ...rangeTasks], MAX_CONCURRENT_SQL);

    const enrichedFields = fields.map(f => {
      const enriched = {
        id: f.id,
        type: f.type,
        sample: sampleRecords.length > 0 ? sampleRecords[0][f.id] : null,
        samples: sampleRecords.map(r => r[f.id]).filter(v => v !== null)
      };
      if (enumData[f.id]) {
        enriched.distinctCount = enumData[f.id].distinctCount;
        enriched.isEnum = enumData[f.id].isEnum;
        enriched.enumValues = enumData[f.id].values;
      }
      if (rangeData[f.id]) {
        enriched.min = rangeData[f.id].min;
        enriched.max = rangeData[f.id].max;
      }
      return enriched;
    });

    return {
      fields: enrichedFields,
      totalRecords,
      sampleRecords
    };
  }

  /* ================================================================
     5. OPENAPI SPEC GENERATOR
     ================================================================ */

  // Per-domain configuration, loaded from /config.json at startup.
  let siteConfig = null;

  async function loadConfig() {
    try {
      const resp = await fetch("/config.json");
      if (resp.ok) {
        siteConfig = await resp.json();
      }
    } catch (e) {
      // Config file missing or invalid — use defaults
    }
  }

  /**
   * Returns the set of hidden fields for a given CKAN domain.
   * Falls back to config.default, then to ["_id"].
   */
  function getHiddenFields(ckanBaseUrl) {
    const fallback = ["_id"];
    if (!siteConfig) return new Set(fallback);

    try {
      const hostname = new URL(ckanBaseUrl).hostname;
      const domainConfig = siteConfig.domains && siteConfig.domains[hostname];
      if (domainConfig && Array.isArray(domainConfig.hiddenFields)) {
        return new Set(domainConfig.hiddenFields);
      }
    } catch (e) {
      // Invalid URL — use default
    }

    if (siteConfig.default && Array.isArray(siteConfig.default.hiddenFields)) {
      return new Set(siteConfig.default.hiddenFields);
    }

    return new Set(fallback);
  }

  function buildOpenApiSpec(resourceId, baseUrl, datasetName, introspection) {
    const allFields = (introspection && introspection.fields) || [];
    const totalRecords = (introspection && introspection.totalRecords) || 0;

    const hiddenFields = getHiddenFields(baseUrl);
    const userFields = allFields.filter(f => !hiddenFields.has(f.id));
    const fieldNames = userFields.map(f => f.id);

    const enumFields = userFields.filter(f => f.isEnum && f.enumValues && f.enumValues.length > 1);

    const tableName = safeSqlIdentifier(resourceId);
    const safeDatasetName = escapeMarkdown(datasetName.replace(/_/g, " "));

    // --- Info description with Data Dictionary ---
    let infoDesc = `**Dataset:** ${safeDatasetName}\n\n`;
    infoDesc += `**Source:** [${escapeMarkdown(baseUrl)}](${baseUrl})\n\n`;
    if (totalRecords) infoDesc += `**Total records:** ${totalRecords.toLocaleString()}\n\n`;

    if (allFields.length > 0) {
      infoDesc += `<details><summary><strong>Data Dictionary</strong> (${allFields.length} fields)</summary>\n\n`;
      infoDesc += `| Field | Type | Details |\n|---|---|---|\n`;
      allFields.forEach(f => {
        const safeId = escapeMarkdown(truncate(f.id, MAX_FIELD_NAME_LEN));
        const safeType = escapeMarkdown(f.type);
        let details = "";
        if (f.isEnum && f.enumValues) {
          const safeVals = f.enumValues.map(v => escapeMarkdown(truncate(v, MAX_VALUE_LEN)));
          details = `Values: ${safeVals.join(", ")}`;
        } else if (f.min !== undefined) {
          details = `Range: ${escapeMarkdown(String(f.min))} \u2014 ${escapeMarkdown(String(f.max))}`;
        } else if (f.distinctCount) {
          details = `${escapeMarkdown(String(f.distinctCount))} distinct values`;
        }
        if (f.sample !== null && f.sample !== undefined && !f.isEnum) {
          const safeSample = escapeMarkdown(truncate(f.sample, MAX_VALUE_LEN));
          details += details ? `. Sample: ${safeSample}` : `Sample: ${safeSample}`;
        }
        infoDesc += `| ${safeId} | ${safeType} | ${details} |\n`;
      });
      infoDesc += `\n</details>\n`;
    }

    // --- Enum filter params ---
    const enumFilterParams = enumFields.map(f => ({
      name: `filter_${f.id}`,
      in: "query",
      required: false,
      schema: { type: "string", enum: f.enumValues.map(v => truncate(v, MAX_VALUE_LEN)) },
      description: `Filter by ${escapeMarkdown(f.id)} (${f.enumValues.length} values)`
    }));

    const safeFieldNames = fieldNames.map(n => escapeMarkdown(n));
    const sortDesc = safeFieldNames.length
      ? `Sort string. Fields: ${safeFieldNames.join(", ")}. e.g. "${safeFieldNames[0]} asc"`
      : 'e.g. "field_name asc"';

    const fieldsDesc = safeFieldNames.length
      ? `Comma-separated fields to return. Available: ${safeFieldNames.join(", ")}`
      : "Comma-separated field names to return";

    // --- SQL examples ---
    const enumField = enumFields[0];
    const numericField = userFields.find(f => ["int", "int4", "int8", "float8", "numeric"].includes(f.type));
    const timestampField = userFields.find(f => f.type === "timestamp");
    const firstField = userFields[0] || { id: "column_name", sample: "value" };

    const sqlExamples = {
      "select_all": {
        summary: "First 10 records",
        value: { sql: `SELECT * FROM ${tableName} LIMIT 10` }
      }
    };

    if (enumField) {
      const safeEnumId = safeSqlIdentifier(enumField.id);
      const safeEnumVal = String(enumField.enumValues[0]).replace(/'/g, "''");
      sqlExamples["filter_by_category"] = {
        summary: `Filter by ${escapeMarkdown(enumField.id)}`,
        value: { sql: `SELECT * FROM ${tableName} WHERE ${safeEnumId} = '${safeEnumVal}' LIMIT 20` }
      };
    }

    if (numericField && enumField) {
      const safeEnumId = safeSqlIdentifier(enumField.id);
      const safeNumId = safeSqlIdentifier(numericField.id);
      sqlExamples["aggregate"] = {
        summary: `Aggregate ${escapeMarkdown(numericField.id)} by ${escapeMarkdown(enumField.id)}`,
        value: { sql: `SELECT ${safeEnumId}, COUNT(*) as cnt, AVG(${safeNumId}) as avg_val FROM ${tableName} GROUP BY ${safeEnumId} ORDER BY cnt DESC` }
      };
    } else if (enumField) {
      const safeEnumId = safeSqlIdentifier(enumField.id);
      sqlExamples["aggregate"] = {
        summary: `Count by ${escapeMarkdown(enumField.id)}`,
        value: { sql: `SELECT ${safeEnumId}, COUNT(*) as cnt FROM ${tableName} GROUP BY ${safeEnumId} ORDER BY cnt DESC` }
      };
    } else {
      const safeFirstId = safeSqlIdentifier(firstField.id);
      sqlExamples["aggregate"] = {
        summary: "Aggregate query (COUNT)",
        value: { sql: `SELECT ${safeFirstId}, COUNT(*) as cnt FROM ${tableName} GROUP BY ${safeFirstId} ORDER BY cnt DESC LIMIT 20` }
      };
    }

    if (timestampField) {
      const safeTsId = safeSqlIdentifier(timestampField.id);
      sqlExamples["time_series"] = {
        summary: `Recent records by ${escapeMarkdown(timestampField.id)}`,
        value: { sql: `SELECT * FROM ${tableName} ORDER BY ${safeTsId} DESC LIMIT 25` }
      };
    }

    // --- The spec ---
    return {
      openapi: "3.1.0",
      info: {
        title: safeDatasetName,
        description: infoDesc,
        version: "1.0.0"
      },
      servers: [{ url: baseUrl }],
      tags: [
        { name: "DataStore Search", description: "Query with search, filters, sort, and pagination" },
        { name: "SQL Query", description: "Run read-only SQL SELECT queries" }
      ],
      paths: {
        "/api/action/datastore_search": {
          get: {
            operationId: "datastoreSearchGet",
            summary: "Search DataStore",
            description: `Query with filters, full-text search, sorting, and pagination. Total records: **${totalRecords.toLocaleString()}**`,
            tags: ["DataStore Search"],
            parameters: [
              { name: "q", in: "query", schema: { type: "string" }, description: "Full-text search across all fields" },
              ...enumFilterParams,
              { name: "limit", in: "query", schema: { type: "integer", default: 10, maximum: 32000 }, description: "Max rows to return (max 32,000)" },
              { name: "offset", in: "query", schema: { type: "integer", default: 0 }, description: "Number of rows to skip" },
              { name: "fields", in: "query", schema: { type: "string" }, description: fieldsDesc },
              { name: "sort", in: "query", schema: { type: "string" }, description: sortDesc }
            ],
            responses: { "200": { description: "Success", content: { "application/json": { schema: { $ref: "#/components/schemas/SearchResponse" } } } } }
          }
        },
        "/api/action/datastore_search_sql": {
          get: {
            operationId: "datastoreSearchSqlGet",
            summary: "SQL Query",
            description: `Run a read-only SQL SELECT. Table name: ${escapeMarkdown(tableName)}`,
            tags: ["SQL Query"],
            parameters: [
              { name: "sql", in: "query", required: true, schema: { type: "string", default: `SELECT * FROM ${tableName} LIMIT 10` }, description: `SQL SELECT statement. Use ${tableName} as the table name.` }
            ],
            responses: { "200": { description: "Success", content: { "application/json": { schema: { $ref: "#/components/schemas/SearchResponse" } } } } }
          },
          post: {
            operationId: "datastoreSearchSqlPost",
            summary: "SQL Query (JSON body)",
            description: "Run a read-only SQL SELECT via JSON body.",
            tags: ["SQL Query"],
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/DatastoreSqlBody" },
                  examples: sqlExamples
                }
              }
            },
            responses: { "200": { description: "Success", content: { "application/json": { schema: { $ref: "#/components/schemas/SearchResponse" } } } } }
          }
        }
      },
      components: {
        schemas: {
          DatastoreSqlBody: {
            type: "object",
            required: ["sql"],
            properties: {
              sql: { type: "string", description: `SQL SELECT. Table: ${tableName}`, default: `SELECT * FROM ${tableName} LIMIT 10` }
            }
          },
          SearchResponse: {
            type: "object",
            properties: {
              success: { type: "boolean" },
              result: {
                type: "object",
                properties: {
                  records: { type: "array", items: { type: "object" }, description: "Row objects" },
                  fields: { type: "array", items: { type: "object" }, description: "Field metadata" },
                  total: { type: "integer" },
                  limit: { type: "integer" },
                  offset: { type: "integer" },
                  _links: { type: "object" }
                }
              }
            }
          }
        }
      }
    };
  }

  /* ================================================================
     6. REQUEST INTERCEPTOR
     ================================================================ */

  /**
   * Creates a Swagger UI requestInterceptor that:
   * - Injects resource_id into datastore_search calls
   * - Converts filter_* params into CKAN filters JSON
   * - Injects Basic Auth header if credentials are set
   */
  function makeRequestInterceptor(resourceId, baseUrl, username, password) {
    return (req) => {
      // Inject auth
      if (username) {
        req.headers["Authorization"] = "Basic " + btoa(username + ":" + password);
      }

      // Only intercept datastore_search GET requests
      if (req.method === "GET" && req.url.includes("/api/action/datastore_search") && !req.url.includes("datastore_search_sql")) {
        const u = new URL(req.url);

        // Inject resource_id
        if (!u.searchParams.has("resource_id")) {
          u.searchParams.set("resource_id", resourceId);
        }

        // Convert filter_* params to CKAN filters JSON
        const filters = {};
        const paramsToRemove = [];
        for (const [key, val] of u.searchParams.entries()) {
          if (key.startsWith("filter_") && val) {
            filters[key.substring(7)] = val;
            paramsToRemove.push(key);
          }
        }
        paramsToRemove.forEach(k => u.searchParams.delete(k));
        if (Object.keys(filters).length > 0) {
          u.searchParams.set("filters", JSON.stringify(filters));
        }

        req.url = u.toString();
      }

      // Route through CORS proxy if needed
      if (useProxy && req.url.startsWith(baseUrl)) {
        const apiPath = req.url.substring(baseUrl.length);
        req.headers["X-CKAN-Target"] = baseUrl;
        req.url = `${window.location.origin}/proxy${apiPath}`;
      }

      return req;
    };
  }

  /* ================================================================
     7. UI CONTROLLER
     ================================================================ */

  const $ = (sel) => document.querySelector(sel);

  function setStatus(text, type) {
    const el = $("#status-message");
    el.textContent = text;
    el.className = `status-message ${type || ""}`;
  }

  function showLanding() {
    $("#landing").classList.remove("hidden");
    $("#explorer").classList.add("hidden");
    $("#swagger-ui").innerHTML = "";
  }

  function showExplorer() {
    $("#landing").classList.add("hidden");
    $("#explorer").classList.remove("hidden");
  }

  async function launchExplorer(ckanUrl, username, password) {
    const parsed = parseCkanUrl(ckanUrl);
    if (!parsed) {
      setStatus("Invalid CKAN resource URL. Expected format: https://example.com/dataset/name/resource/uuid", "error");
      return;
    }

    // Show the target domain prominently before proceeding
    $("#target-domain").textContent = parsed.baseUrl;
    $("#target-info").classList.remove("hidden");

    setStatus("Connecting to " + parsed.baseUrl + "...", "loading");
    $("#btn-explore").disabled = true;

    try {
      // Test connectivity (auto-detects CORS block and switches to proxy)
      useProxy = false; // Reset proxy mode for each new exploration
      const testResp = await ckanFetch(
        parsed.baseUrl,
        `/api/action/datastore_search?resource_id=${encodeURIComponent(parsed.resourceId)}&limit=0`,
        { headers: authHeaders(username, password) }
      );

      if (!testResp.ok) {
        if (testResp.status === 401 || testResp.status === 403) {
          setStatus("Authentication required. Enter credentials and try again.", "error");
        } else {
          setStatus(`CKAN API returned HTTP ${testResp.status}. Check the URL and try again.`, "error");
        }
        $("#btn-explore").disabled = false;
        return;
      }

      if (useProxy) {
        console.log("Using CORS proxy for this CKAN instance");
      }

      const introspection = await deepIntrospect(
        parsed.baseUrl, parsed.resourceId, username, password,
        (msg) => setStatus(msg, "loading")
      );

      if (!introspection) {
        setStatus("Could not introspect this resource. It may not have the DataStore extension enabled.", "error");
        $("#btn-explore").disabled = false;
        return;
      }

      const spec = buildOpenApiSpec(parsed.resourceId, parsed.baseUrl, parsed.datasetName, introspection);

      // Update URL with parameters (for sharing)
      const shareUrl = new URL(window.location.href.split("?")[0]);
      shareUrl.searchParams.set("url", ckanUrl);
      window.history.replaceState(null, "", shareUrl.toString());

      setStatus("", "");
      showExplorer();

      // Render Swagger UI
      SwaggerUIBundle({
        spec: spec,
        domNode: document.getElementById("swagger-ui"),
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
        layout: "StandaloneLayout",
        tryItOutEnabled: true,
        docExpansion: "list",
        defaultModelsExpandDepth: 0,
        requestInterceptor: makeRequestInterceptor(parsed.resourceId, parsed.baseUrl, username, password)
      });

    } catch (err) {
      if (err.name === "TypeError" && err.message.includes("Failed to fetch")) {
        setStatus("Network error \u2014 likely a CORS block. The CKAN instance needs to allow requests from this domain.", "error");
      } else {
        setStatus("Error: " + err.message, "error");
      }
      $("#btn-explore").disabled = false;
    }
  }

  /* ================================================================
     8. INITIALISATION
     ================================================================ */

  document.addEventListener("DOMContentLoaded", async () => {
    // Load per-domain config (hidden fields, etc.)
    await loadConfig();

    const urlInput = $("#ckan-url");
    const usernameInput = $("#username");
    const passwordInput = $("#password");
    const btnExplore = $("#btn-explore");
    const btnBack = $("#btn-back");

    // Check for URL parameter (linked from CKAN or shared)
    const params = new URLSearchParams(window.location.search);
    const urlParam = params.get("url");
    if (urlParam) {
      urlInput.value = urlParam;
    }

    // Explore button
    btnExplore.addEventListener("click", () => {
      const url = urlInput.value.trim();
      if (!url) {
        setStatus("Please enter a CKAN resource URL.", "error");
        return;
      }
      launchExplorer(url, usernameInput.value.trim(), passwordInput.value);
    });

    // Enter key on URL input
    urlInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") btnExplore.click();
    });

    // Back button
    btnBack.addEventListener("click", () => {
      showLanding();
      $("#btn-explore").disabled = false;
      // Clear URL param
      window.history.replaceState(null, "", window.location.pathname);
    });

    // Auto-launch if URL parameter is present
    if (urlParam) {
      launchExplorer(urlParam, usernameInput.value.trim(), passwordInput.value);
    }
  });

})();
