"""Answer two network questions for a VPC workload: is it open inbound, and can it reach out?"""

from __future__ import annotations

from typing import Any

from agent_identity.aws.base import CoverageLog, attempt, quiet
from agent_identity.aws.session import client
from agent_identity.models import Domain, NetworkProfile


class RegionNetwork:
    def __init__(self, session: Any, region: str, coverage: CoverageLog | None = None) -> None:
        self.ec2 = client(session, "ec2", region)
        self.region = region
        self.coverage = coverage or CoverageLog()
        self._routes: list[dict] | None = None
        self._subnets: dict[str, dict] | None = None
        self._groups: dict[str, dict] = {}
        self._endpoints: list[dict] | None = None

    def _read(self, source: str, call: Any) -> list[dict]:
        found, _ = attempt(
            self.coverage, source, self.region, call, [], [Domain.NETWORK], record_ok=False
        )
        return found

    def _load(self) -> None:
        if self._routes is None:
            self._routes = self._read(
                "VPC route tables",
                lambda: self.ec2.describe_route_tables().get("RouteTables", []),
            )
            subnets = self._read(
                "VPC subnets", lambda: self.ec2.describe_subnets().get("Subnets", [])
            )
            self._subnets = {s["SubnetId"]: s for s in subnets}

    def vpc_of(self, subnet_id: str) -> str | None:
        self._load()
        return (self._subnets or {}).get(subnet_id, {}).get("VpcId")

    def _route_table(self, subnet_id: str) -> dict | None:
        self._load()
        main = None
        vpc = self.vpc_of(subnet_id)
        for table in self._routes or []:
            for assoc in table.get("Associations", []):
                if assoc.get("SubnetId") == subnet_id:
                    return table
                if assoc.get("Main") and table.get("VpcId") == vpc:
                    main = table
        return main

    def internet_route(
        self, subnets: list[str], public_ipv4: bool | None = None, ipv6: bool = True
    ) -> tuple[bool | None, str]:
        """Whether the workload can reach out, given what it runs on.

        An internet gateway only carries IPv4 traffic from a public address, so a route to one
        isn't enough. `public_ipv4` is None when it's not known whether the workload has one.
        """
        if not subnets:
            return None, ""
        unknown = ""
        for subnet in subnets:
            table = self._route_table(subnet)
            if table is None:
                unknown = unknown or f"Couldn't read the route table for {subnet}"
                continue
            for route in table.get("Routes", []):
                reaches, detail = _default_route(route, subnet, public_ipv4, ipv6)
                if reaches:
                    return True, detail
                if reaches is None:
                    unknown = unknown or detail
        if unknown:
            return None, unknown
        return False, "No usable route to the internet from these subnets"

    def open_groups(self, group_ids: list[str]) -> list[str] | None:
        """Groups open to the internet, or None if they couldn't all be read."""
        missing = [g for g in group_ids if g not in self._groups]
        if missing:
            found = self._read(
                "VPC security groups",
                lambda: self.ec2.describe_security_groups(GroupIds=missing).get(
                    "SecurityGroups", []
                ),
            )
            self._groups.update({g["GroupId"]: g for g in found})
        if any(g not in self._groups for g in group_ids):
            return None
        result = []
        for group_id in group_ids:
            for rule in self._groups[group_id].get("IpPermissions", []):
                ranges = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
                ranges += [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])]
                if "0.0.0.0/0" in ranges or "::/0" in ranges:
                    result.append(group_id)
                    break
        return result

    def endpoints(self, vpc_id: str | None) -> list[str] | None:
        if vpc_id is None:
            return None
        if self._endpoints is None:
            self._endpoints = quiet(
                lambda: self.ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
            )
            if self._endpoints is None:
                return None
        return [e["ServiceName"] for e in self._endpoints if e.get("VpcId") == vpc_id]

    def profile(
        self,
        subnets: list[str],
        groups: list[str],
        public_ipv4: bool | None = None,
        ipv6: bool = True,
    ) -> NetworkProfile:
        egress, detail = self.internet_route(subnets, public_ipv4, ipv6)
        vpc = self.vpc_of(subnets[0]) if subnets else None
        return NetworkProfile(
            inbound=[],
            internet_egress=egress,
            egress_detail=detail,
            vpc_id=vpc,
            in_vpc=True,
            open_security_groups=self.open_groups(groups),
            vpc_endpoints=self.endpoints(vpc),
        )


def _default_route(
    route: dict, subnet: str, public_ipv4: bool | None, ipv6: bool
) -> tuple[bool | None, str]:
    """True if this route gets the workload out, None if it can't be told, False otherwise."""
    is_ipv4 = route.get("DestinationCidrBlock") == "0.0.0.0/0"
    is_ipv6 = route.get("DestinationIpv6CidrBlock") == "::/0"
    if not (is_ipv4 or (is_ipv6 and ipv6)) or route.get("State") == "blackhole":
        return False, ""
    if route.get("NatGatewayId"):
        return True, f"{subnet} routes to a NAT gateway"
    if route.get("EgressOnlyInternetGatewayId"):
        return True, f"{subnet} routes IPv6 to an egress-only internet gateway"
    if route.get("GatewayId", "").startswith("igw-"):
        if is_ipv6:
            return True, f"{subnet} routes IPv6 to an internet gateway"
        if public_ipv4:
            return True, f"{subnet} routes to an internet gateway"
        if public_ipv4 is None:
            return None, f"{subnet} routes to an internet gateway, if the workload has a public IP"
        return False, ""
    return None, f"{subnet} sends traffic through a device this tool can't assess"
