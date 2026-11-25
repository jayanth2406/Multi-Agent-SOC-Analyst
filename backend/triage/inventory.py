"""The asset inventory (data/poc/asset_inventory.yaml): hosts, accounts, approved activity."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml

from backend.triage.rubric import max_tier


class Inventory:
    def __init__(self, path: Path):
        data = yaml.safe_load(Path(path).read_text())
        self.hosts = {h["name"]: h for h in data["hosts"]}
        self.accounts = {a["name"]: a for a in data["accounts"]}
        self.approved = {a["id"]: a for a in data["approved_activity"]}
        self.critical_list = set(data.get("critical_asset_list", []))
        self.networks = [ipaddress.ip_network(n) for n in data["internal_networks"]]

    def ip(self, host: str) -> str:
        return self.hosts[host]["ip"]

    def tier(self, host=None, users=()) -> str:
        """The most critical tier among the host and accounts. Raises ValueError if none is in the inventory."""
        tiers = [self.hosts[host]["tier"]] if host in self.hosts else []
        tiers += [self.accounts[u]["tier"] for u in users if u in self.accounts]
        return max_tier(*tiers)

    def by_role(self, *roles):
        return [n for n, h in self.hosts.items() if h["role"] in roles]

    def workstations(self):
        return self.by_role("workstation")

    def owner(self, host):
        return self.hosts.get(host, {}).get("owner")
