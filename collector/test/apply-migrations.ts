import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach } from "vitest";

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM reports"),
    env.DB.prepare("DELETE FROM salts"),
    env.DB.prepare("DELETE FROM agg_daily"),
    env.DB.prepare("DELETE FROM strategy_reports"),
    env.DB.prepare("DELETE FROM strategy_daily"),
    env.DB.prepare("DELETE FROM transport_reports"),
    env.DB.prepare("DELETE FROM transport_daily"),
  ]);
});
