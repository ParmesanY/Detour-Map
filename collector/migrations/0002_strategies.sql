-- Registry (M8): which DPI bypass strategies work for which ISP. Same privacy rules as `reports`: no IP,
-- `pseudo` only rate-limits and counts distinct reporters and is cleared after two days.
-- One row per tune run; `results` holds the strategies as the collector normalized them:
-- [{"key":"winws:--dpi-desync=fake ...","passed":2,"total":2,"ms":620}, ...]
CREATE TABLE strategy_reports (
  id            INTEGER PRIMARY KEY,
  received_hour TEXT    NOT NULL,
  day           TEXT    NOT NULL,
  pseudo        TEXT,
  asn           INTEGER NOT NULL,
  as_org        TEXT    NOT NULL,
  country       TEXT    NOT NULL,
  region        TEXT    NOT NULL,
  net           TEXT    NOT NULL,          -- 'home' | 'mobile'
  client        TEXT    NOT NULL,
  engine        TEXT    NOT NULL,          -- 'winws' | 'byedpi'
  target        TEXT    NOT NULL,          -- a target ID from spec/targets.json, '' for any other site (never the site itself)
  results       TEXT    NOT NULL
);
CREATE INDEX strategy_reports_day ON strategy_reports(day);
CREATE INDEX strategy_reports_pseudo_hour ON strategy_reports(pseudo, received_hour);

-- Per day, strategy, target, ISP, country and connection type. Rebuilt by the cron for today and yesterday.
CREATE TABLE strategy_daily (
  day       TEXT    NOT NULL,
  engine    TEXT    NOT NULL,
  key       TEXT    NOT NULL,
  target    TEXT    NOT NULL,
  asn       INTEGER NOT NULL,
  as_org    TEXT    NOT NULL,
  country   TEXT    NOT NULL,
  net       TEXT    NOT NULL,
  reporters INTEGER NOT NULL,  -- distinct pseudonyms that tried it
  works     INTEGER NOT NULL,  -- ... for whom it passed every attempt
  fails     INTEGER NOT NULL,  -- ... for whom it never passed
  ms        INTEGER,           -- average time of passing attempts
  PRIMARY KEY (day, engine, key, target, asn, country, net)
);
CREATE INDEX strategy_daily_asn ON strategy_daily(asn, engine, day);
