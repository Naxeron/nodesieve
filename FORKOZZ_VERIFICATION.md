# Forkozz live verification — 2026-10-04

> **2026-11-17 — historical record.** The checker no longer exports to Forkozz at
> all: the per-site checks were removed and the Forkozz/NetShift exporter was
> replaced by one for Steer (see the README). Everything below describes code
> that is gone; it is kept only as a record of what was verified at the time.
> Of the Steer deployment script, only the read-only checks have run against a
> live router.

Verified over SSH against the installed router:

- OpenWrt 24.10.5, aarch64.
- NetShift 0.9.9 and sing-box 1.14.1-extended-2.7.2.
- Existing `main` subscription routes the `geoblock` community list. No conflicting
  Twitter/Discord assignments, pending UCI edits, or proxy DNS detour were present.
- The router's native UCI parser accepted all five generated service sections in
  an isolated temporary configuration. Multiline domains and complete proxy URI
  query strings survived the commit/read roundtrip. The original subscription and
  geoblock assignment remained intact.
- The installed NetShift conversion functions generated VLESS, Trojan, and
  Shadowsocks outbounds, a Discord URLTest pool with zero tolerance, a selector,
  and a service domain rule. The router's `sing-box check` accepted this temporary
  configuration. Sample proxies used documentation addresses, with no connection
  attempts to those addresses.
- The existing live sing-box configuration also passed its native syntax check.
  The process and NetShift firewall table were present throughout verification.

The active UCI file's SHA-256 remained identical, the sing-box PID remained the
same, and there were zero pending UCI edits afterward. No configuration was
deployed and no service was restarted. Temporary validation files were removed.

Automated tests with socket access: **446 passed, 64 subtests passed**. Only the
separate legacy live-Mihomo smoke module was excluded; live Forkozz checks above
covered the installed engine directly.

Service-list follow-up verification on the same date:

- The installed catalog identifies Gemini as `google_ai`; Twitter and Discord
  retain their native community lists.
- All five staged service sections passed the router's UCI parser, including
  ChatGPT/Grok `remote_domain_lists` and Forkozz `zm_refs`. Grok precedes Twitter
  to give `grok.x.com` its own policy.
- Downloaded MetaCubeX `openai.json` and `xai.json` compiled with the installed
  sing-box rule-set compiler. The installed plain-list parser imported the
  maintained Google AI `.lst` into a temporary suffix rule set, which compiled.
- Installed NetShift handlers attached native JSON, built-in community, and
  plain-list sources to temporary route and DNS rules. `sing-box check` accepted
  the generated temporary configuration.
- Native helper inspection confirmed that JSON/SRS URLs with query strings or
  uppercase extensions would be treated as plain text, and matching filename
  stems would collide. Configuration validation now rejects those cases.
- The active UCI hash, sing-box PID, and pending edits were identical before and
  after these checks. No deployment or service restart occurred; temporary
router files were cleaned up.

Main-pool and location-score follow-up:

- Two existing proxies were checked with local temporary Mihomo instances and
  the bundled ipregion primary GeoIP probes. No subscriptions or node addresses
  were included in verification output.
- One returned seven Germany and seven Finland reports in 14.6 seconds. The
  tied country was rejected for main instead of trusting a single provider.
- Another returned nine Finland and six Türkiye reports in 17.0 seconds. Its
  60% agreement passed the configured main threshold. These observations are
  point-in-time GeoIP evidence, not service-access guarantees.
- On the live router, main currently assigns `meta` and `geoblock`. An isolated
  native UCI staging run replaced its subscription with a sample URLTest pool,
  removed stale subscription fields, and preserved every non-pool main option.
  It also retained the generated service precedence. The active UCI hash,
  sing-box PID, and pending edits stayed identical; no restart or deployment
  occurred.

Main-pool expansion follow-up:

- The previous scan had two selected main nodes and 26 otherwise-qualified
  nodes excluded only for having a lower location rank. Removed that cutoff;
  country exclusions and minimum evidence requirements remain unchanged.
- Targeted selection, exporter, pipeline and UI regression checks passed:
  **137 tests, 52 subtests**. Old highest-tier deployment artifacts are invalidated
  when main is managed by location.
- A fresh check of 36 nodes produced **27 qualifying main nodes**, with all
  required service pools resolved. The generated main URLTest links match the
  report's 27 distinct node identities. Deployment dry-run passed. These local
  artifacts were regenerated without deploying or restarting router services.

This verifies configuration compatibility, not the availability or country of
any particular real proxy. Fresh service probes are still required before
deployment. Discord measures HTTPS API latency, not voice latency. In Forkozz,
a manually selected individual proxy overrides URLTest until automatic selection
is restored.
