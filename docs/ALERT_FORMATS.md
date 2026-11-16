# Alert formats

Every alert read from Kafka (Alerts → Live (Kafka), `/api/consume_alerts`) or NATS
(Alerts → Live (NATS)) is decoded by `decode_message()` and then normalized by the first
adapter that accepts it (`core/intelligent_orchestration/enrichment/adapters/`). Each adapter
produces the same envelope (`_index`, `_id`, `_source` with `timestamp`, `observer`, `rule`,
`data`), which is what MongoDB stores and the orchestrator reads.

| Adapter | Input | `_adapter` |
|---|---|---|
| `MMTProbeAdapter` | native mmt-probe security reports: CSV text, JSON array, STIX 2.1 bundle | `mmt` |
| `MMTAdapter` | the ACAS `{type, payload}` object | `mmt` |
| `WazuhAdapter` | Wazuh / OpenSearch hits (`_source.rule`) | `wazuh` |

Other JSON objects are kept as they are (`generic`).

## MMT (Montimage Monitoring Tool)

mmt-probe publishes security alerts (report type 10) in one of three shapes, depending on its
`output.format` and build. All three are accepted, and one alert gives the same rule id, level,
description, source / destination IP, time (to the millisecond) and probe id whatever its shape.

**CSV** (default, `output.format=CSV`), one report per message:

```
10,<probe-id>,"<input source>",<ts.us>,<rule-id>,"<verdict>","<rule type>","<description>",{<event trace>}
```

**JSON array** (`output.format=JSON`): the same fields as a JSON list,
`[10, <probe-id>, "<input source>", <ts.us>, <rule-id>, "<verdict>", "<rule type>", "<description>", {...}]`.

**STIX 2.1 bundle** (mmt-probe built with `STIX_FORMAT`): `identity` (probe id and input source
in the `x-probe-id-ext` extension), `observed-data` (`first_observed`, description in
`x-observed-data-ext`), `ipv4-addr` / `ipv6-addr` / `mac-addr` objects, and an `x-attack-type`
object whose external reference `source_name: mmt-security` holds the rule id.

Other probe reports (type 1 version report, session reports, ...) are not alerts: they are
skipped, in CSV or JSON form, by the live views and by `/api/consume_alerts`.

**ACAS shape**: the `{"type": ..., "payload": {probeId, timestamp, code, status, category,
description, srcIp, dstIp, details}}` object built by the ACAS web server from probe CSV lines
is still supported, unchanged (`MMTAdapter`). It keeps times to the second.

### Field mapping

| Envelope | CSV / JSON | STIX |
|---|---|---|
| `observer.id`, `data.probe_id` | field 2 | `x-probe-id-ext.probe-id` |
| `timestamp` (ISO, ms) | field 4 | `observed-data.first_observed` |
| `rule.id`, `data.code` | field 5 | `external_id` of the `mmt-security` reference |
| `data.status` (verdict) | field 6 | `x-attack-type-ext.verdict`, else `detected` |
| `data.category` (rule type) | field 7 | `x-attack-type-ext.rule_type`, else `attack` |
| `rule.description` | field 8 | `x-observed-data-ext.description`, else the `x-attack-type` name |
| `data.srcip`, `data.dstip` | `ip.src` / `ip.dst` (or `ipv6.*`) of the event trace; ARP rules: `arp.ar_sip` | first / second IP object |
| `data.macs` | `arp.ar_sha`, `ethernet.src` of the trace | `mac-addr` objects |
| `data.priority` | — (empty) | `x-attack-type-ext.priority` |
| `data.mmt_format` | `csv` / `json` | `stix` |
| `data.stix_bundle_id` | — | bundle `id` |

MMT rules carry no MITRE technique, so `rule.mitre` is empty and the orchestrator uses
Paths B and C.

### Level

For STIX bundles, `rule.level` comes from the alert's priority when the bundle has one
(`x-attack-type-ext.priority`, proposed in
[mmt-probe#24](https://github.com/Montimage/mmt-probe/issues/24) for STIX only; values are not
case-sensitive, unknown values are ignored):

| Priority | `critical` | `high` | `medium` | `low` |
|---|---|---|---|---|
| `rule.level` | 15 | 12 | 7 | 3 |

Otherwise, and always for CSV / JSON, it comes from the rule type: `attack` 12, `evasion` 10, `anomaly` 7, `security` 5,
`warning` 5, `info` 3, others 5. STIX bundles without `rule_type` count as `attack` (12).

### Document id

Alerts are upserted by `_id`, so replaying a topic does not duplicate them.

- CSV / JSON: `mmt-<probe>-<ts>-<rule>` (microsecond timestamp).
- STIX: `mmt-<probe>-<ts>-<rule>-<bundle uuid>`. STIX times have millisecond precision, so two
  alerts of one rule raised in the same millisecond would otherwise share an id. The probe
  draws a new bundle id for each alert, so running the probe again on the same capture adds
  new documents, while replaying the same messages does not.
