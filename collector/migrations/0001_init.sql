-- Raw reports. One row per report (results as JSON) keeps D1 writes low: 1 row instead of ~40.
-- No IP address anywhere. `pseudo` (HMAC of the IP with the day's salt) only rate-limits and counts distinct
-- reporters; the cron clears it after two days, and the salt itself is deleted when its day ends.
CREATE TABLE reports (
  id            INTEGER PRIMARY KEY,
  received_hour TEXT    NOT NULL,          -- '2026-11-16T14' (UTC), set by the server
  day           TEXT    NOT NULL,          -- '2026-11-16'
  pseudo        TEXT,                      -- cleared after 2 days
  asn           INTEGER NOT NULL,
  as_org        TEXT    NOT NULL,
  country       TEXT    NOT NULL,          -- ISO 3166-1, 'RU'
  region        TEXT    NOT NULL,          -- ISO 3166-2 subdivision, 'MOW'; '' when unknown
  net           TEXT    NOT NULL,          -- 'home' | 'mobile'
  client        TEXT    NOT NULL,
  targets_ver   INTEGER NOT NULL,
  whitelist     INTEGER NOT NULL DEFAULT 0, -- report flag: only domestic sites reachable
  verdicts      TEXT    NOT NULL,          -- {"youtube":"sni","x":"dns,sni",...}
  results       TEXT    NOT NULL           -- raw results array as sent, to recompute verdicts when rules change
);
CREATE INDEX reports_day ON reports(day);
CREATE INDEX reports_pseudo_hour ON reports(pseudo, received_hour);

-- One random salt per UTC day; deleted when the day is over, so old pseudonyms can't be recomputed.
CREATE TABLE salts (
  day  TEXT PRIMARY KEY,
  salt TEXT NOT NULL
);

-- What the site reads: per day, target, ISP, region and connection type. Rebuilt by the cron for today
-- and yesterday. Target '_whitelist' counts reports in whitelist mode.
CREATE TABLE agg_daily (
  day       TEXT    NOT NULL,
  target    TEXT    NOT NULL,
  asn       INTEGER NOT NULL,
  as_org    TEXT    NOT NULL,
  country   TEXT    NOT NULL,
  region    TEXT    NOT NULL,
  net       TEXT    NOT NULL,
  reporters INTEGER NOT NULL,  -- distinct pseudonyms
  probes    INTEGER NOT NULL,  -- reports
  blocked   INTEGER NOT NULL,  -- reports with any blocking verdict
  ok        INTEGER NOT NULL,
  dns       INTEGER NOT NULL,
  ip        INTEGER NOT NULL,
  sni       INTEGER NOT NULL,
  freeze    INTEGER NOT NULL,
  stall     INTEGER NOT NULL,
  throttle  INTEGER NOT NULL,
  quic      INTEGER NOT NULL,
  PRIMARY KEY (day, target, asn, country, region, net)
);
CREATE INDEX agg_target_day ON agg_daily(target, day);
