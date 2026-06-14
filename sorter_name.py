import re
from sorter_ip import run_cleanup_pipeline, cve_sort_key


def find_exact_key(headers: list, target: str, default: str = "") -> str:
    """Find the exact matching key in the headers list case-insensitively."""
    t_lower = target.lower()
    for h in headers:
        if h.lower() == t_lower:
            return h
    for h in headers:
        if t_lower in h.lower():
            return h
    return default or target


def detect_reference_key(headers: list) -> str:
    """Detect reference key from headers such as See Also or Reference."""
    for h in headers:
        if h.lower() in ("see also", "reference", "references"):
            return h
    return "See Also"


def sort_ips(ip_list: list) -> list:
    """Sort IP addresses numerically."""
    def ip_key(ip):
        try:
            return tuple(int(p) for p in ip.strip().split("."))
        except ValueError:
            return (999, 999, 999, 999)
    return sorted(list(set(ip_list)), key=ip_key)


def run_name_sorting_pipeline(paths: list, api_key: str, use_ai: bool, log) -> tuple:
    """
    Run full cleanup, group by Name, merge Hosts, Ports, and CVEs,
    and return (headers, sorted_rows, total, none_removed, deduped).
    """
    # 1. Run parsing and Case 1, 2, 3 cleanups
    headers, rows, total, none_removed, deduped = run_cleanup_pipeline(paths, api_key, use_ai, log)

    if not rows:
        return headers, [], total, none_removed, deduped

    # 2. Detect exact keys to access case-insensitively
    name_key      = find_exact_key(headers, "Name")
    host_key      = find_exact_key(headers, "Host")
    cve_key       = find_exact_key(headers, "CVE")
    port_key      = find_exact_key(headers, "Port")
    risk_key      = find_exact_key(headers, "Risk")
    desc_key      = find_exact_key(headers, "Description")
    solution_key  = find_exact_key(headers, "Solution")
    see_also_key  = detect_reference_key(headers)
    plugin_id_key = find_exact_key(headers, "Plugin ID")

    # 3. Group rows by vulnerability name
    grouped = {}
    for r in rows:
        name = str(r.get(name_key, "")).strip()
        if name:
            grouped.setdefault(name, []).append(r)

    # 4. Merge information within groups
    merged_rows = []
    for name, group in grouped.items():
        # Merge Host
        ips = []
        for r in group:
            ip_val = str(r.get(host_key, "")).strip()
            if ip_val:
                parts = [p.strip() for p in re.split(r"[,;]", ip_val) if p.strip()]
                ips.extend(parts)
        unique_ips = sort_ips(ips)
        merged_host = ", ".join(unique_ips)
        ip_count = len(unique_ips)

        # Merge CVE
        cves = []
        for r in group:
            cve_val = str(r.get(cve_key, "")).strip()
            if cve_val:
                parts = [c.strip() for c in re.split(r"[,;]", cve_val) if c.strip()]
                cves.extend(parts)
        unique_cves = sorted(list(set(cves)), key=cve_sort_key, reverse=True)
        merged_cve = ", ".join(unique_cves)

        # Merge Port
        ports = []
        for r in group:
            port_val = str(r.get(port_key, "")).strip()
            if port_val:
                parts = [p.strip() for p in re.split(r"[,;]", port_val) if p.strip()]
                ports.extend(parts)
        def port_sort_key(p):
            try:
                return int(p)
            except ValueError:
                return 999999
        unique_ports = sorted(list(set(ports)), key=port_sort_key)
        merged_port = ", ".join(unique_ports)

        # Merge Plugin ID
        plugin_ids = []
        for r in group:
            pid = str(r.get(plugin_id_key, "")).strip()
            if pid:
                parts = [p.strip() for p in re.split(r"[,;]", pid) if p.strip()]
                plugin_ids.extend(parts)
        def pid_sort_key(p):
            try:
                return int(p)
            except ValueError:
                return 999999
        unique_pids = sorted(list(set(plugin_ids)), key=pid_sort_key)
        merged_plugin_id = ", ".join(unique_pids)

        # Risk (take highest rating)
        risk_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        highest_risk = "None"
        highest_pri = -1
        for r in group:
            risk = str(r.get(risk_key, "")).strip()
            pri = risk_priority.get(risk.lower(), -1)
            if pri > highest_pri:
                highest_pri = pri
                highest_risk = risk

        # Description
        desc_val = ""
        for r in group:
            d = str(r.get(desc_key, "")).strip()
            if d:
                desc_val = d
                break

        # Solution
        sol_val = ""
        for r in group:
            s = str(r.get(solution_key, "")).strip()
            if s:
                sol_val = s
                break

        # See Also / References
        urls = []
        for r in group:
            ref_val = str(r.get(see_also_key, "")).strip()
            if ref_val:
                parts = [p.strip() for p in re.split(r"[\n,;]", ref_val) if p.strip()]
                urls.extend(parts)
        unique_urls = list(dict.fromkeys(urls))
        merged_reference = "\n".join(unique_urls)

        # Create consolidated row
        merged_row = {
            name_key: name,
            host_key: merged_host,
            "IP Count": ip_count,
            cve_key: merged_cve,
            port_key: merged_port,
            risk_key: highest_risk,
            desc_key: desc_val,
            solution_key: sol_val,
            see_also_key: merged_reference,
            plugin_id_key: merged_plugin_id
        }
        merged_rows.append(merged_row)

    # 5. Sort final rows by Name (case-insensitive)
    sorted_rows = sorted(merged_rows, key=lambda r: str(r.get(name_key, "")).lower())

    # 6. Define output headers
    output_headers = [
        name_key,
        host_key,
        "IP Count",
        cve_key,
        port_key,
        risk_key,
        desc_key,
        solution_key,
        see_also_key,
        plugin_id_key
    ]

    log(f"Grouped into {len(sorted_rows)} unique vulnerabilities sorted by Name.", "ok")
    return output_headers, sorted_rows, total, none_removed, deduped
