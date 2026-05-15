"""
Bot Defense profile discovery and fetching from F5 BIG-IP.

All operations are read-only against the BIG-IP device.
Profiles are fetched via the iControl REST API:
  GET /mgmt/tm/security/bot-defense/profile
  GET /mgmt/tm/security/bot-defense/profile/~{partition}~{name}
"""
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .bigip_client import BigIPClient
from .policy_exporter import _parse_destination, _extract_host_conditions
from .utils import get_logger, ensure_dir

_BD_PROFILE_EP  = "/mgmt/tm/security/bot-defense/profile"
_LTM_VIRTUAL_EP = "/mgmt/tm/ltm/virtual"
_LTM_POLICY_EP  = "/mgmt/tm/ltm/policy"

# Bot Defense profile override/reference collections that should always be
# expanded and captured for audit diffing/reporting.
_BD_OVERRIDE_REF_KEYS = [
    "anomalyCategoryOverridesReference",
    "anomalyOverridesReference",
    "classOverridesReference",
    "externalDomainsReference",
    "microServicesReference",
    "signatureCategoryOverridesReference",
    "signatureOverridesReference",
    "siteDomainsReference",
    "stagedSignaturesReference",
    "whitelistReference",
]


def _extract_bot_defense_action(rule: Dict) -> str:
    """
    Extract the Bot Defense profile path from an LTM policy rule's actions.

    F5 BIG-IP uses action type ``botDefense`` with a ``profile`` field
    pointing to the bot-defense profile full path.

    Returns the full path of the Bot Defense profile, or ``""`` when the
    rule has no bot-defense action.
    """
    for action in rule.get("actionsReference", {}).get("items", []):
        if action.get("type", "").lower() == "botdefense":
            return action.get("profile", "")
    return ""


class BotDefenseAuditor:
    """
    Discovers and fetches Bot Defense profiles from a BIG-IP device.
    """

    def __init__(
        self,
        client: BigIPClient,
        output_dir: str,
        partitions: Optional[List[str]] = None,
    ):
        self.client = client
        self.fetch_dir = ensure_dir(Path(output_dir) / "exports")
        self.filter_partitions = [p.strip() for p in partitions] if partitions else []
        self.log = get_logger("bot_defense_auditor")

    # ── Discovery ──────────────────────────────────────────────────────────────

    def discover_profiles(self, all_partitions: List[str]) -> List[Dict]:
        """
        Return a list of Bot Defense profile metadata dicts, filtered by
        partition if ``--partitions`` was specified.

        Each dict has: name, fullPath, partition, template, enforcementMode.
        """
        self.log.info("Discovering Bot Defense profiles …")
        try:
            data = self.client.get(_BD_PROFILE_EP)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to enumerate Bot Defense profiles: {exc}"
            ) from exc

        profiles: List[Dict] = []
        for item in data.get("items", []):
            full_path = item.get("fullPath", "")
            if not full_path.startswith("/"):
                full_path = f"/Common/{full_path}"

            parts = full_path.strip("/").split("/", 1)
            partition = parts[0] if len(parts) == 2 else "Common"

            if self.filter_partitions and partition not in self.filter_partitions:
                continue
            if all_partitions and partition not in all_partitions:
                continue

            profiles.append({
                "name":            item.get("name", ""),
                "fullPath":        full_path,
                "partition":       partition,
                "template":        item.get("template", ""),
                "enforcementMode": item.get("enforcementMode", "transparent"),
            })

        self.log.info("Discovered %d Bot Defense profile(s).", len(profiles))
        return profiles

    # ── Virtual server enrichment ──────────────────────────────────────────────

    def enrich_with_virtual_servers(self, profiles: List[Dict]) -> None:
        """
        Enrich each profile dict in-place with a ``virtual_servers`` list.

        Identifies Virtual Servers where each Bot Defense profile is applied
        via two mechanisms:

        * **Direct** — the bot-defense profile appears in the VS's profiles
          list (attached via the LTM virtual server configuration directly).
        * **LTM policy** — an LTM policy rule attached to the VS has a
          ``botDefense`` action that references this profile, enabling
          condition-based (e.g. host-header routing) Bot Defense application.

        Each entry in ``virtual_servers`` is a dict with keys:
          name, fullPath, destination, ip, port, association_type, ltm_policies

        ``association_type`` is ``"direct"`` for profiles attached directly to
        the VS and ``"ltm_policy"`` when applied via a Local Traffic Policy
        rule.  If a VS has both a direct attachment and an LTM policy
        reference, it appears once with ``association_type="direct"`` and the
        LTM policy appended to its ``ltm_policies`` list.

        This is a best-effort operation: failures are logged and result in an
        empty list for the affected profile.
        """
        self.log.info(
            "Fetching virtual server bindings for %d Bot Defense profile(s) …",
            len(profiles),
        )

        # Initialise empty lists on all profiles
        for p in profiles:
            p.setdefault("virtual_servers", [])

        # Build lookup: fullPath → profile dict
        profile_map: Dict[str, Dict] = {
            p["fullPath"]: p for p in profiles if p.get("fullPath")
        }
        if not profile_map:
            return

        bot_profile_paths = set(profile_map.keys())

        # Fetch all LTM virtual servers in one bulk request
        all_vs = self._fetch_all_vs()
        if not all_vs:
            self.log.warning(
                "No LTM virtual servers found; virtual server bindings will "
                "be empty for all Bot Defense profiles."
            )
            return

        # Track which VS have already been added per profile to avoid duplicates
        seen: Dict[str, set] = {fp: set() for fp in bot_profile_paths}

        for vs_meta in all_vs:
            vs_path = vs_meta.get("fullPath", "")
            if not vs_path:
                continue
            encoded = vs_path.strip("/").replace("/", "~")
            vs_api_path = f"{_LTM_VIRTUAL_EP}/~{encoded}"

            # ── Check direct profile attachments ────────────────────────────
            direct_profiles = self._fetch_vs_bot_profiles(vs_api_path, bot_profile_paths)
            for bp_path in direct_profiles:
                if vs_path not in seen[bp_path]:
                    seen[bp_path].add(vs_path)
                    vs_entry = dict(vs_meta)
                    vs_entry["association_type"] = "direct"
                    vs_entry["ltm_policies"] = []
                    profile_map[bp_path]["virtual_servers"].append(vs_entry)

            # ── Check LTM policy rules for botDefense actions ───────────────
            ltm_policies = self._get_vs_ltm_policies_for_bot(vs_api_path, bot_profile_paths)
            for ltp in ltm_policies:
                referenced = {
                    rule["bot_profile"]
                    for rule in ltp.get("rules", [])
                    if rule.get("bot_profile") in bot_profile_paths
                }
                for bp_path in referenced:
                    if vs_path not in seen[bp_path]:
                        # VS not yet in the list — add as ltm_policy association
                        seen[bp_path].add(vs_path)
                        vs_entry = dict(vs_meta)
                        vs_entry["association_type"] = "ltm_policy"
                        vs_entry["ltm_policies"] = [ltp]
                        profile_map[bp_path]["virtual_servers"].append(vs_entry)
                    else:
                        # VS already added (direct or earlier LTP) — append this LTP
                        existing = next(
                            (v for v in profile_map[bp_path]["virtual_servers"]
                             if v.get("fullPath") == vs_path),
                            None,
                        )
                        if existing is not None:
                            ltp_path = ltp.get("fullPath", "")
                            if not any(
                                lt.get("fullPath") == ltp_path
                                for lt in existing.get("ltm_policies", [])
                            ):
                                existing.setdefault("ltm_policies", []).append(ltp)

    def _fetch_all_vs(self) -> List[Dict]:
        """
        Fetch all LTM virtual servers and return a list of basic metadata dicts.

        Each dict has: name, fullPath, destination, ip, port.
        On failure logs a warning and returns an empty list.
        """
        try:
            data = self.client.get(
                _LTM_VIRTUAL_EP,
                params={"$select": "name,fullPath,destination,partition"},
            )
        except Exception as exc:
            self.log.warning("Could not fetch LTM virtual servers: %s", exc)
            return []

        result = []
        for item in data.get("items", []):
            fp = item.get("fullPath", "")
            if not fp.startswith("/"):
                fp = f"/Common/{item.get('name', fp)}"
            destination = item.get("destination", "")
            ip, port = _parse_destination(destination)
            result.append({
                "name":        item.get("name", ""),
                "fullPath":    fp,
                "destination": destination,
                "ip":          ip,
                "port":        port,
            })
        return result

    def _fetch_vs_bot_profiles(
        self,
        vs_api_path: str,
        bot_profile_paths: set,
    ) -> List[str]:
        """
        Return the subset of ``bot_profile_paths`` that are directly attached
        to the given virtual server's profiles sub-collection.

        Queries ``{vs_api_path}/profiles``.  On failure returns an empty list.
        """
        try:
            data = self.client.get(f"{vs_api_path}/profiles")
        except Exception as exc:
            self.log.debug(
                "Could not fetch profiles for VS %s: %s", vs_api_path, exc
            )
            return []

        found = []
        for item in data.get("items", []):
            fp = item.get("fullPath", "")
            if not fp:
                partition = item.get("partition", "Common")
                name = item.get("name", "")
                fp = f"/{partition}/{name}" if name else ""
            if fp in bot_profile_paths:
                found.append(fp)
        return found

    def _get_vs_ltm_policies_for_bot(
        self,
        vs_api_path: str,
        bot_profile_paths: set,
    ) -> List[Dict]:
        """
        Return LTM policies attached to a VS that contain ``botDefense``
        actions referencing any profile in ``bot_profile_paths``.

        Each returned dict has: name, fullPath, rules (list of rule dicts
        with keys: name, host_conditions, bot_profile).
        """
        try:
            data = self.client.get(f"{vs_api_path}/policies")
        except Exception as exc:
            self.log.debug(
                "Could not fetch LTM policies for VS %s: %s", vs_api_path, exc
            )
            return []

        results = []
        for item in data.get("items", []):
            name = item.get("name", "")
            partition = item.get("partition", "Common")
            full_path = item.get("fullPath", f"/{partition}/{name}")
            rules = self._get_ltm_policy_bot_rules(full_path, bot_profile_paths)
            if rules:
                results.append({
                    "name":     name,
                    "fullPath": full_path,
                    "rules":    rules,
                })
        return results

    def _get_ltm_policy_bot_rules(
        self,
        policy_full_path: str,
        bot_profile_paths: set,
    ) -> List[Dict]:
        """
        Fetch an LTM policy with its rules expanded and return only the rules
        that have a ``botDefense`` action referencing a profile in
        ``bot_profile_paths``.

        Each returned rule dict has: name, host_conditions, bot_profile.
        """
        encoded  = policy_full_path.strip("/").replace("/", "~")
        api_path = f"{_LTM_POLICY_EP}/~{encoded}"

        try:
            data = self.client.get(api_path, params={"expandSubcollections": "true"})
        except Exception as exc:
            self.log.debug(
                "Could not fetch LTM policy %s: %s", policy_full_path, exc
            )
            return []

        rules = []
        for rule in data.get("rulesReference", {}).get("items", []):
            host_conditions = _extract_host_conditions(rule)
            bot_profile = _extract_bot_defense_action(rule)
            if bot_profile and bot_profile in bot_profile_paths:
                rules.append({
                    "name":            rule.get("name", ""),
                    "host_conditions": host_conditions,
                    "bot_profile":     bot_profile,
                })
        return rules

    # ── Fetching ───────────────────────────────────────────────────────────────

    def fetch_profile(self, profile: Dict) -> Dict:
        """
        Fetch the full Bot Defense profile JSON from BIG-IP.

        The profile is also saved to disk under output_dir/bot-defense/ for
        the audit trail.  Returns the raw JSON dict from the API.
        """
        full_path = profile["fullPath"]
        encoded = full_path.strip("/").replace("/", "~")
        api_path = f"{_BD_PROFILE_EP}/~{encoded}"

        self.log.info("Fetching Bot Defense profile: %s", full_path)
        data = self.client.get(api_path, params={"expandSubcollections": "true"})
        self._expand_override_collections(data)

        # Persist to disk for audit trail
        safe_name = full_path.strip("/").replace("/", "_")
        local_path = self.fetch_dir / f"BOT_{safe_name}.json"
        local_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.log.debug("Saved profile JSON to %s", local_path)

        profile["local_path"] = str(local_path)
        return data

    def _expand_override_collections(self, profile_data: Dict) -> None:
        """
        Ensure override-related Bot Defense sub-collections are populated.

        ``expandSubcollections=true`` may not always return ``items`` for every
        reference collection. For each known override reference, this performs a
        best-effort fetch via its ``link`` and hydrates ``...Reference.items``.
        """
        for ref_key in _BD_OVERRIDE_REF_KEYS:
            ref = profile_data.get(ref_key)
            if not isinstance(ref, dict):
                continue

            # Already expanded with items.
            if isinstance(ref.get("items"), list):
                continue

            link = ref.get("link")
            if not link:
                continue

            parsed = urlparse(link)
            api_path = parsed.path
            if not api_path:
                continue

            params = {"expandSubcollections": "true"}
            if parsed.query:
                for pair in parsed.query.split("&"):
                    if "=" not in pair:
                        continue
                    k, v = pair.split("=", 1)
                    if k and v:
                        params[k] = v

            try:
                sub_data = self.client.get(api_path, params=params)
            except Exception as exc:
                self.log.debug(
                    "Could not expand Bot Defense sub-collection %s (%s): %s",
                    ref_key,
                    api_path,
                    exc,
                )
                continue

            items = sub_data.get("items") if isinstance(sub_data, dict) else None
            if not isinstance(items, list):
                items = []

            ref["items"] = items

    def fetch_all(
        self, profiles: List[Dict]
    ) -> Tuple[List[Tuple[Dict, Dict]], List[Tuple[Dict, str]]]:
        """
        Fetch all profiles sequentially.

        Returns:
            (successes, failures)
            successes: list of (profile_meta_dict, profile_data_dict)
            failures:  list of (profile_meta_dict, error_message)
        """
        successes: List[Tuple[Dict, Dict]] = []
        failures: List[Tuple[Dict, str]] = []

        for profile in profiles:
            try:
                data = self.fetch_profile(profile)
                successes.append((profile, data))
            except Exception as exc:
                msg = str(exc)
                self.log.error(
                    "Failed to fetch Bot Defense profile %s: %s",
                    profile["fullPath"], msg,
                )
                failures.append((profile, msg))

        return successes, failures

    # ── Display ────────────────────────────────────────────────────────────────

    def print_discovery_table(self, profiles: List[Dict]) -> None:
        """Print a summary table of discovered Bot Defense profiles to stdout."""
        if not profiles:
            print("No Bot Defense profiles found.")
            return

        col_widths = {
            "fullPath":        max(len("Profile Full Path"),
                                   max(len(p["fullPath"]) for p in profiles)),
            "partition":       max(len("Partition"),
                                   max(len(p["partition"]) for p in profiles)),
            "enforcementMode": max(len("Enforcement"),
                                   max(len(p["enforcementMode"]) for p in profiles)),
            "template":        max(len("Template"),
                                   max(len(p.get("template", "")) for p in profiles)),
        }
        sep = "-" * (
            col_widths["fullPath"] + col_widths["partition"] +
            col_widths["enforcementMode"] + col_widths["template"] + 24
        )
        fmt = (
            f"{{:<{col_widths['fullPath'] + 2}}}"
            f"{{:<{col_widths['partition'] + 2}}}"
            f"{{:<{col_widths['enforcementMode'] + 2}}}"
            f"{{:<{col_widths['template'] + 2}}}"
        )
        print("\n" + sep)
        print(fmt.format("Profile Full Path", "Partition", "Enforcement", "Template"))
        print(sep)
        for p in profiles:
            print(fmt.format(
                p["fullPath"],
                p["partition"],
                p["enforcementMode"],
                p.get("template", ""),
            ))
        print(sep)
        print(f"Total: {len(profiles)} Bot Defense profile(s)\n")
