"""Threat-Intelligence Agent with MITRE ATT&CK Mapping and RFC1918 Privacy Guard.

Enriches public IOCs (IPs, hashes), respects privacy by strictly filtering internal/RFC1918
entities, maps behavior to MITRE ATT&CK techniques, and flags reputation anomalies.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.models.schemas import Alert
from backend.tools.threat_intel_tools import (
    is_rfc1918_private,
    lookup_file_hash_tool,
    lookup_ip_reputation_tool,
    search_mitre_attack_tool,
)

MITRE_CATALOG_PATH = Path("data/mitre_attack_catalog.json")


class MitreTechnique(BaseModel):
    """MITRE ATT&CK technique reference."""
    technique_id: str
    technique_name: str
    tactic: str
    evidence: str
    subtechniques: List[str] = Field(default_factory=list)


class EnrichedIOC(BaseModel):
    """Normalized IOC with reputation score and classification."""
    ioc_value: str
    ioc_type: str  # ipv4, domain, sha256, md5, user, host
    is_internal: bool
    reputation_score: float  # 0.0 (clean) to 1.0 (confirmed malicious)
    verdict: str  # malicious, suspicious, clean, internal_asset, unknown
    provider: str


class ThreatIntelResult(BaseModel):
    """Structured output from Threat-Intelligence Agent."""
    alert_id: str
    enriched_iocs: List[EnrichedIOC]
    mitre_attack_mappings: List[MitreTechnique]
    highest_threat_score: float
    threat_summary: str


class ThreatIntelligenceAgent:
    """Enriches indicators of compromise and correlates with MITRE ATT&CK framework."""

    def investigate(self, alert: Alert, extracted_iocs: List[str]) -> ThreatIntelResult:
        """Enrich extracted IOCs using threat intelligence tools and map to MITRE ATT&CK."""
        enriched: List[EnrichedIOC] = []
        max_threat = 0.0

        for ioc in extracted_iocs:
            ioc_clean = ioc.strip()

            # Check if IP
            if any(char.isdigit() for char in ioc_clean) and "." in ioc_clean and not any(c.isalpha() for c in ioc_clean):
                raw_res = json.loads(lookup_ip_reputation_tool.invoke({"ip": ioc_clean}))
                score = raw_res.get("threat_score", raw_res.get("abuse_confidence_score", 0.0))
                max_threat = max(max_threat, score)
                enriched.append(EnrichedIOC(
                    ioc_value=ioc_clean,
                    ioc_type="ipv4",
                    is_internal=raw_res.get("is_internal", False),
                    reputation_score=score,
                    verdict=raw_res.get("verdict", "unknown"),
                    provider=raw_res.get("provider", "Internal_Network_Policy"),
                ))
            elif len(ioc_clean) in (32, 64) and all(c in "0123456789abcdefABCDEF" for c in ioc_clean):
                # Hash lookup
                raw_res = json.loads(lookup_file_hash_tool.invoke({"sha256": ioc_clean}))
                score = 0.95 if raw_res.get("verdict") == "malicious" else 0.0
                max_threat = max(max_threat, score)
                enriched.append(EnrichedIOC(
                    ioc_value=ioc_clean,
                    ioc_type="sha256" if len(ioc_clean) == 64 else "md5",
                    is_internal=False,
                    reputation_score=score,
                    verdict=raw_res.get("verdict", "unknown"),
                    provider=raw_res.get("provider", "VirusTotal_Community_API"),
                ))
            else:
                # User account or Host entity (strictly internal)
                enriched.append(EnrichedIOC(
                    ioc_value=ioc_clean,
                    ioc_type="identity_or_host",
                    is_internal=True,
                    reputation_score=0.0,
                    verdict="internal_asset",
                    provider="Active_Directory_Inventory",
                ))

        # Query MITRE ATT&CK STIX database
        mappings: List[MitreTechnique] = []
        search_terms = []
        if alert.failed_attempts and alert.failed_attempts > 3:
            search_terms.append("brute force")
        if "scan" in alert.event_type.lower() or "port" in alert.description.lower():
            search_terms.append("network service discovery")
        if "powershell" in alert.description.lower() or "cmd.exe" in alert.description.lower() or "exec" in alert.description.lower():
            search_terms.append("command and script")
        if "outbound" in alert.description.lower() or "beacon" in alert.description.lower():
            search_terms.append("application layer protocol")
        if "account" in alert.description.lower() or "off-hours" in alert.description.lower():
            search_terms.append("valid accounts")

        if not search_terms:
            search_terms.append("brute force")

        for term in search_terms:
            raw_match = json.loads(search_mitre_attack_tool.invoke({"keyword": term}))
            for item in raw_match:
                if "technique_id" in item:
                    mappings.append(MitreTechnique(
                        technique_id=item["technique_id"],
                        technique_name=item["name"],
                        tactic=item["tactic"],
                        evidence=f"Observed behavioral match with alert description: {alert.description[:90]}...",
                        subtechniques=item.get("subtechniques", []),
                    ))

        # Deduplicate techniques
        seen = set()
        dedup_mappings = []
        for m in mappings:
            if m.technique_id not in seen:
                seen.add(m.technique_id)
                dedup_mappings.append(m)

        summary = (
            f"Enriched {len(enriched)} IOCs. Found {sum(1 for e in enriched if e.verdict == 'malicious')} "
            f"malicious public entities. Mapped {len(dedup_mappings)} MITRE ATT&CK techniques from STIX catalog."
        )

        return ThreatIntelResult(
            alert_id=alert.alert_id,
            enriched_iocs=enriched,
            mitre_attack_mappings=dedup_mappings,
            highest_threat_score=max_threat,
            threat_summary=summary,
        )


threat_intel_agent = ThreatIntelligenceAgent()
