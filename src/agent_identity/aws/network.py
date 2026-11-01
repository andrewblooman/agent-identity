"""Answer two network questions for a VPC workload: is it open inbound, and can it reach out?"""

from __future__ import annotations

from typing import Any

from agent_identity.aws.base import quiet
from agent_identity.aws.session import client
from agent_identity.models import NetworkProfile


class RegionNetwork:
    def __init__(self, session: Any, region: str) -> None:
        self.ec2 = client(session, "ec2", region)
        self._routes: list[dict] | None = None
        self._subnets: dict[str, dict] | None = None
        self._groups: dict[str, dict] = {}
        self._endpoints: list[dict] | None = None

    def _load(self) -> None:
        if self._routes is None:
            self._routes = quiet(
                lambda: self.ec2.describe_route_tables().get("RouteTables", []), []
            )
            subnets = quiet(lambda: self.ec2.describe_subnets().get("Subnets", []), [])
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

    def internet_route(self, subnets: list[str]) -> tuple[bool | None, str]:
        if not subnets:
            return None, ""
        any_read = False
        for subnet in subnets:
            table = self._route_table(subnet)
            if table is None:
                continue
            any_read = True
            for route in table.get("Routes", []):
                if route.get("DestinationCidrBlock") != "0.0.0.0/0":
                    continue
                if route.get("State") == "blackhole":
                    continue
                if route.get("GatewayId", "").startswith("igw-"):
                    return True, f"{subnet} routes to an internet gateway"
                if route.get("NatGatewayId"):
                    return True, f"{subnet} routes to a NAT gateway"
                if route.get("TransitGatewayId") or route.get("NetworkInterfaceId"):
                    return None, f"{subnet} sends traffic through a device this tool can't assess"
        if not any_read:
            return None, ""
        return False, "No route to the internet from these subnets"

    def open_groups(self, group_ids: list[str]) -> list[str]:
        missing = [g for g in group_ids if g not in self._groups]
        if missing:
            found = quiet(
                lambda: self.ec2.describe_security_groups(GroupIds=missing).get(
                    "SecurityGroups", []
                ),
                [],
            )
            self._groups.update({g["GroupId"]: g for g in found})
        result = []
        for group_id in group_ids:
            for rule in self._groups.get(group_id, {}).get("IpPermissions", []):
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

    def profile(self, subnets: list[str], groups: list[str]) -> NetworkProfile:
        egress, detail = self.internet_route(subnets)
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
