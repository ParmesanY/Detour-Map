// Detour Map collector: takes probe reports, keeps aggregates, serves them to the map site.
// Never logs requests: they carry client IPs.
import { ingest, originOf } from "./ingest";
import { handleApi, QueryError } from "./api";
import { runMaintenance } from "./aggregate";
import { MAX_BODY_BYTES } from "./report";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
};

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS, ...extra },
  });
}

async function postReport(request: Request, env: Env): Promise<Response> {
  const length = Number(request.headers.get("Content-Length") ?? "0");
  if (length > MAX_BODY_BYTES) {
    return json({ accepted: false, error: "too large" }, 413);
  }
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) {
    return json({ accepted: false, error: "too large" }, 413);
  }
  const origin = originOf(request);
  if (!origin) {
    return json({ accepted: false, error: "no network data for this connection" }, 400);
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return json({ accepted: false, error: "not JSON" }, 400);
  }
  const result = await ingest(env, body, origin);
  return json(result.body, result.status);
}

async function get(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/v1/health") {
    return json({ ok: true });
  }
  const seconds = Number(env.CACHE_SECONDS) || 0;
  const cache = caches.default;
  if (seconds > 0) {
    const hit = await cache.match(request);
    if (hit) {
      return hit;
    }
  }
  let body: unknown;
  try {
    body = await handleApi(url, env);
  } catch (e) {
    if (e instanceof QueryError) {
      return json({ error: e.message }, 400);
    }
    throw e;
  }
  if (body === undefined) {
    return json({ error: "not found" }, 404);
  }
  const response = json(body, 200, seconds > 0 ? { "Cache-Control": `public, max-age=${seconds}` } : {});
  if (seconds > 0) {
    ctx.waitUntil(cache.put(request, response.clone()));
  }
  return response;
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }
    if (request.method === "POST" && url.pathname === "/v1/report") {
      return postReport(request, env);
    }
    if (request.method === "GET") {
      return get(request, env, ctx);
    }
    return json({ error: "method not allowed" }, 405);
  },

  async scheduled(_controller, env, ctx): Promise<void> {
    ctx.waitUntil(runMaintenance(env.DB));
  },
} satisfies ExportedHandler<Env>;
