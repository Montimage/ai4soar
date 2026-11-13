"""MMT-Probe native alerts (CSV text, JSON array, STIX bundle) -> one canonical envelope."""
import asyncio
import copy
import json
import queue
import sys
import types
import unittest
from unittest import mock

from core.intelligent_orchestration.enrichment.adapters.mmt_probe import decode_message
from core.intelligent_orchestration.enrichment.pipeline import normalize_alert

TRACE = ('{"event_1":{"timestamp":1683636843.615651,"counter":1577,"attributes":[["icmp.type",5],'
         '["ip.src","192.168.21.225"],["ip.dst","192.168.21.128"]]}}')
CSV = ('10,3,"/data/input/a2.pcap",1683636845.358700,20,"detected","attack",'
       '"4 consecutive ICMP redirect packets. Possibly ICMP redirect flood.",' + TRACE)
JSON_ARRAY = ('[10,3,"/data/input/a2.pcap",1683636845.358700,20,"detected","attack",'
              '"4 consecutive ICMP redirect packets. Possibly ICMP redirect flood.",' + TRACE + ']')
ARP_CSV = ('10,3,"/data/input/a2.pcap",1683637444.901316,5,"detected","attack",'
           '"IPv4 address conflict detection (RFC5227). Possible arp poisoning.",'
           '{"event_1":{"timestamp":1683637442.418093,"counter":3141,"attributes":[["arp.ar_op",2],'
           '["arp.ar_sha","9e:0f:77:4e:b5:80"],["arp.ar_sip","192.168.21.70"]]}}')
VERSION_CSV = '1,3,"/data/input/a2.pcap",1794572528.075135,"1.6.5 (fbf0c3d)","1.10.2 (8e6faf4)","1.2.20"'
STIX = {
    "type": "bundle", "id": "bundle--8dd19aea-1e3e-41be-8920-a5a5e6cdbcd3",
    "objects": [
        {"type": "identity", "id": "identity--1", "name": "MMT-Probe 3", "identity_class": "system",
         "extensions": {"x-probe-id-ext": {"extension_type": "property-extension", "probe-id": 3,
                                           "input-source": "/data/input/a2.pcap"}}},
        {"type": "observed-data", "id": "observed-data--1", "first_observed": "2023-05-09T12:54:05.358Z",
         "object_refs": ["ipv4-addr--s", "ipv4-addr--d", "x-attack-type--1"],
         "extensions": {"x-observed-data-ext": {
             "description": "4 consecutive ICMP redirect packets. Possibly ICMP redirect flood."}}},
        {"type": "ipv4-addr", "id": "ipv4-addr--s", "value": "192.168.21.225"},
        {"type": "ipv4-addr", "id": "ipv4-addr--d", "value": "192.168.21.128"},
        {"type": "x-attack-type", "id": "x-attack-type--1",
         "name": "4 consecutive ICMP redirect packets. Possibly ICMP redirect flood.",
         "external_references": [{"source_name": "mmt-security", "external_id": "20"}]},
    ],
}


def key(raw):
    norm, fmt = normalize_alert(decode_message(raw))
    src = norm["_source"]
    return fmt, (src["rule"]["id"], src["rule"]["level"], src["rule"]["description"],
                 src["data"]["srcip"], src["data"]["dstip"], src["observer"]["id"], src["timestamp"])


class MMTProbeAdapterTest(unittest.TestCase):
    def test_three_formats_give_the_same_alert(self):
        expected = ("20", 12, "4 consecutive ICMP redirect packets. Possibly ICMP redirect flood.",
                    "192.168.21.225", "192.168.21.128", "3", "2023-05-09T12:54:05.358Z")
        for raw in (CSV, JSON_ARRAY, json.dumps(STIX)):
            fmt, k = key(raw)
            self.assertEqual(fmt, "mmt")
            self.assertEqual(k, expected)

    def test_arp_alert_keeps_contested_ip_and_macs(self):
        norm, _ = normalize_alert(decode_message(ARP_CSV))
        self.assertEqual(norm["_source"]["data"]["srcip"], "192.168.21.70")
        self.assertIn("9e:0f:77:4e:b5:80", norm["_source"]["data"]["macs"])

    def test_non_alert_reports_are_skipped(self):
        self.assertIsNone(decode_message(VERSION_CSV))
        self.assertIsNone(decode_message("[1,3,\"x\",1.0,\"v\"]"))
        self.assertIsNone(decode_message(""))

    def test_other_text_still_rejected(self):
        with self.assertRaises(ValueError):
            decode_message("not json at all")

    def test_documented_mmt_schema_unchanged(self):
        ref = {"type": "security", "payload": {"probeId": 3, "timestamp": 1683636845.3587, "code": 20,
                                               "status": "detected", "category": "attack",
                                               "description": "x", "srcIp": "1.1.1.1", "dstIp": "2.2.2.2"}}
        norm, fmt = normalize_alert(ref)
        self.assertEqual(fmt, "mmt")
        self.assertEqual(norm["_raw"], ref)

    def test_wazuh_still_matched(self):
        _, fmt = normalize_alert({"_source": {"rule": {"id": "1", "mitre": {"id": ["T1110"]}}}})
        self.assertEqual(fmt, "wazuh")


def stix_with(**props):
    """STIX bundle whose x-attack-type-ext carries the mmt-probe#24 properties."""
    b = copy.deepcopy(STIX)
    ext = {"extension_type": "new-sdo", **props}
    b["objects"][4]["extensions"] = {"x-attack-type-ext": ext}
    return b


class PriorityTest(unittest.TestCase):
    def level(self, raw):
        norm, _ = normalize_alert(decode_message(raw))
        return norm["_source"]

    def test_stix_priority_sets_level(self):
        for prio, lvl in (("critical", 15), ("high", 12), ("medium", 7), ("low", 3), ("HIGH", 12)):
            src = self.level(json.dumps(stix_with(priority=prio)))
            self.assertEqual(src["rule"]["level"], lvl, prio)
            self.assertEqual(src["data"]["priority"], prio.lower())

    def test_stix_verdict_and_rule_type_used(self):
        src = self.level(json.dumps(stix_with(priority="medium", verdict="detected", rule_type="evasion")))
        self.assertEqual(src["data"]["category"], "evasion")
        self.assertEqual(src["data"]["status"], "detected")
        self.assertEqual(src["rule"]["groups"], ["evasion", "detected", "security"])
        self.assertEqual(src["rule"]["level"], 7)     # priority wins over the rule type (10)

    def test_stix_rule_type_without_priority(self):
        src = self.level(json.dumps(stix_with(rule_type="evasion")))
        self.assertEqual(src["rule"]["level"], 10)

    def test_stix_without_priority_unchanged(self):
        src = self.level(json.dumps(STIX))
        self.assertEqual((src["rule"]["level"], src["data"]["category"], src["data"]["status"],
                          src["data"]["priority"]), (12, "attack", "detected", ""))

    def test_unknown_priority_ignored(self):
        src = self.level(json.dumps(stix_with(priority="urgent")))
        self.assertEqual((src["rule"]["level"], src["data"]["priority"]), (12, ""))

    def test_csv_and_json_level_from_rule_type(self):
        for raw in (CSV, JSON_ARRAY):
            src = self.level(raw)
            self.assertEqual((src["rule"]["level"], src["data"]["priority"]), (12, ""))


class AlertIdTest(unittest.TestCase):
    def norm_id(self, raw):
        return normalize_alert(decode_message(raw))[0]["_id"]

    def test_csv_and_json_ids_unchanged(self):
        self.assertEqual(self.norm_id(CSV), "mmt-3-1683636845.3587-20")
        self.assertEqual(self.norm_id(JSON_ARRAY), "mmt-3-1683636845.3587-20")

    def test_stix_id_uses_bundle_id(self):
        other = copy.deepcopy(STIX)
        other["id"] = "bundle--50b495a8-1a72-405d-b65f-9c28c489d779"   # same rule, same ms
        a, b = self.norm_id(json.dumps(STIX)), self.norm_id(json.dumps(other))
        self.assertEqual(a, "mmt-3-1683636845.358-20-8dd19aea-1e3e-41be-8920-a5a5e6cdbcd3")
        self.assertNotEqual(a, b)
        self.assertEqual(a, self.norm_id(json.dumps(STIX)))             # replay: same _id

    def test_stix_without_bundle_id_falls_back(self):
        nob = copy.deepcopy(STIX)
        del nob["id"]
        self.assertEqual(self.norm_id(json.dumps(nob)), "mmt-3-1683636845.358-20")


class _Msg:
    def __init__(self, data: bytes):
        self.data = data


class NatsListenerTest(unittest.TestCase):
    """_nats_background_listener's handler, with a fake nats module (no network)."""

    def run_handler(self, payloads):
        from api.routes import alerts as routes
        subject = "test.mmt.alerts"
        handlers = []

        class FakeNC:
            async def subscribe(self, subj, cb):
                handlers.append(cb)

        async def connect(*_a, **_k):
            return FakeNC()

        async def stop(_s):                 # ends the listener's keep-alive loop
            raise RuntimeError("stop")

        q = queue.Queue()
        saved = []
        fake_nats = types.ModuleType("nats")
        fake_nats.connect = connect

        async def scenario():
            with mock.patch("asyncio.sleep", stop):
                await routes._nats_background_listener("nats://fake:4222", subject)
            for p in payloads:
                await handlers[0](_Msg(p.encode() if isinstance(p, str) else p))

        with mock.patch.dict(sys.modules, {"nats": fake_nats}), \
                mock.patch.object(routes.alert_service, "save_alert", side_effect=saved.append), \
                mock.patch.dict(routes._nats_subjects, {subject: {"queues": {"c": q}, "started": True}}):
            asyncio.run(scenario())         # also waits for the save executor
        out = []
        while not q.empty():
            out.append(q.get_nowait())
        return saved, out

    def test_native_formats_saved_and_broadcast(self):
        saved, out = self.run_handler([VERSION_CSV, CSV, JSON_ARRAY, json.dumps(STIX), ""])
        self.assertEqual([s["_source"]["data"]["mmt_format"] for s in saved], ["csv", "json", "stix"])
        self.assertTrue(all(s["_adapter"] == "mmt" for s in saved))
        self.assertEqual(len(out), 3)        # version report and empty message skipped
        self.assertEqual(json.loads(out[0])["_source"]["rule"]["id"], "20")

    def test_reference_shape_and_garbage(self):
        ref = {"type": "security", "payload": {"probeId": 3, "timestamp": 1683636845.3587, "code": 20}}
        saved, out = self.run_handler([json.dumps(ref), "not json\nat all"])
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["_raw"], ref)
        self.assertEqual(out[1], "not json at all")   # passed through raw, not saved


class KafkaAlertConsumerTest(unittest.TestCase):
    """consume_alerts with a fake KafkaConsumer that applies the real deserializer."""

    def consume(self, raws):
        from core.alerts_consumer import kafka_consumer as kc
        created = []

        class FakeConsumer:
            def __init__(self, topic, **cfg):
                self.topic, self.cfg, self.closed = topic, cfg, False
                created.append(self)

            def poll(self, timeout_ms):
                de = self.cfg["value_deserializer"]
                return {("t", 0): [types.SimpleNamespace(value=de(r)) for r in raws]}

            def close(self):
                self.closed = True

        with mock.patch.object(kc, "KafkaConsumer", FakeConsumer):
            value = kc.KafkaAlertConsumer().consume_alerts(topic="UC5.SECANOD.alerts")
        self.assertTrue(created[0].closed)
        self.assertEqual(created[0].topic, "UC5.SECANOD.alerts")
        return value

    def test_version_report_skipped(self):
        self.assertEqual(self.consume([VERSION_CSV.encode(), CSV.encode()]), CSV)

    def test_json_alert_returned(self):
        self.assertEqual(self.consume([b"[1,3,\"x\",1.0,\"v\"]", json.dumps(STIX).encode()]), STIX)

    def test_only_non_alerts_gives_none(self):
        self.assertIsNone(self.consume([VERSION_CSV.encode(), b""]))


if __name__ == "__main__":
    unittest.main()
