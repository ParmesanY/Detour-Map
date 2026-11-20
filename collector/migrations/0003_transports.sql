-- VPN transports by ISP: which way of reaching a VPN server (VLESS REALITY, XHTTP, Hysteria2, AmneziaWG…) works on
-- which ISP right now. Same privacy rules as `reports`: no IP, no server address or name, `pseudo` only rate-limits
-- and counts distinct reporters and is cleared after two days.
-- One row per batch a client sends; `results` holds the outcomes as the collector checked them:
-- [{"transport":"vless-reality","ok":3,"frozen":1,"fail":0}, ...]
CREATE TABLE transport_reports (
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
  results       TEXT    NOT NULL
);
CREATE INDEX transport_reports_day ON transport_reports(day);
CREATE INDEX transport_reports_pseudo_hour ON transport_reports(pseudo, received_hour);

-- Per day, transport, ISP, country and connection type. Rebuilt by the cron for today and yesterday.
-- A reporter counts once per column: "ok" if any of their checks passed cleanly, "frozen" if any froze, and so on.
CREATE TABLE transport_daily (
  day       TEXT    NOT NULL,
  transport TEXT    NOT NULL,
  asn       INTEGER NOT NULL,
  as_org    TEXT    NOT NULL,
  country   TEXT    NOT NULL,
  net       TEXT    NOT NULL,
  reporters INTEGER NOT NULL,
  ok        INTEGER NOT NULL,  -- reporters with at least one clean pass
  frozen    INTEGER NOT NULL,  -- ... with at least one freeze (data stopped after a few KB)
  fail      INTEGER NOT NULL,  -- ... with at least one failure to connect
  checks    INTEGER NOT NULL,  -- all checks, for the shares
  ok_checks INTEGER NOT NULL,
  frozen_checks INTEGER NOT NULL,
  PRIMARY KEY (day, transport, asn, country, net)
);
CREATE INDEX transport_daily_asn ON transport_daily(asn, day);
