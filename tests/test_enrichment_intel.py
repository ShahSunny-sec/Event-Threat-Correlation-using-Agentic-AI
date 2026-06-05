import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from triage.enrichment_intel import fetch_enrichment_intel
from utils.schema import Incident, Event


def test_fetch_no_public_ips_returns_note():
    inc = Incident(primary_src_ip="10.0.0.1", events=[], detections=[])
    with patch("triage.enrichment_intel.VIRUSTOTAL_API_KEY", "x"), \
         patch("triage.enrichment_intel.ABUSEIPDB_API_KEY", "y"):
        out = fetch_enrichment_intel(inc)
    assert "note" in out


def test_fetch_skips_apis_without_keys():
    inc = Incident(primary_src_ip="8.8.8.8", events=[], detections=[])
    with patch("triage.enrichment_intel.VIRUSTOTAL_API_KEY", ""), \
         patch("triage.enrichment_intel.ABUSEIPDB_API_KEY", ""):
        out = fetch_enrichment_intel(inc)
    assert "8.8.8.8" in out["ips"]
    assert out["ips"]["8.8.8.8"]["virustotal"].get("skipped")
    assert out["ips"]["8.8.8.8"]["abuseipdb"].get("skipped")


def test_fetch_with_mocks():
    inc = Incident(
        primary_src_ip="8.8.8.8",
        events=[Event(src_ip="1.1.1.1")],
        detections=[],
    )

    def fake_get(url, **_kwargs):
        m = MagicMock()
        if "virustotal.com" in url:
            m.status_code = 200
            m.json.return_value = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 1,
                            "harmless": 50,
                            "undetected": 43,
                        },
                        "reputation": -1,
                        "country": "US",
                    }
                }
            }
        else:
            m.status_code = 200
            m.json.return_value = {
                "data": {
                    "abuseConfidenceScore": 12,
                    "totalReports": 3,
                    "numDistinctUsers": 2,
                    "countryCode": "US",
                    "usageType": "Hosting",
                    "isp": "Test ISP",
                }
            }
        return m

    with patch("triage.enrichment_intel.VIRUSTOTAL_API_KEY", "vt"), \
         patch("triage.enrichment_intel.ABUSEIPDB_API_KEY", "ab"), \
         patch("triage.enrichment_intel.requests.get", side_effect=fake_get), \
         patch("triage.enrichment_intel.time.sleep"):
        out = fetch_enrichment_intel(inc)

    assert set(out["ips"].keys()) == {"1.1.1.1", "8.8.8.8"}
    one = out["ips"]["8.8.8.8"]
    assert one["virustotal"]["last_analysis_stats"]["suspicious"] == 1
    assert one["abuseipdb"]["abuse_confidence_score"] == 12
