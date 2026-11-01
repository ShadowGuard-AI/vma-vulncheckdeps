import argparse
import logging
import os
import json
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Optional
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "vma-VulnCheckDeps/1.0 (Python)"


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line tool.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Check project dependencies for known vulnerabilities using the NIST NVD."
    )
    parser.add_argument(
        "dependency_file",
        help="Path to the dependency file (e.g., requirements.txt, package.json).  Supported file types are: requirements.txt, package.json, pom.xml"
    )
    parser.add_argument(
        "--api_key",
        help="NIST NVD API Key (optional). The primary route is the NVD_API_KEY environment variable; --api_key overrides it. Get a key here: https://nvd.nist.gov/developers/request-an-api-key",
        required=False
    )
    parser.add_argument(
        "--output",
        help="Path to the output file (optional, defaults to console)",
        required=False
    )
    parser.add_argument(
        "--severity_threshold",
        help="Minimum severity level to report (CRITICAL, HIGH, MEDIUM, LOW).  Defaults to HIGH.",
        default="HIGH",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        required=False
    )

    return parser


def _exact_or_spec_version(req):
    specs = list(req.specifier)
    for s in specs:
        if s.operator in ("==", "==="):
            return s.version.rstrip(".*")
    if specs:
        return str(req.specifier)
    return None


def read_requirements_txt(file_path: str):
    """Returns a list of (name, version_or_specifier) tuples."""
    try:
        from packaging.requirements import Requirement
        dependencies = []
        with open(file_path, "r") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                if " #" in line:
                    line = line.split(" #", 1)[0].strip()
                if not line:
                    continue
                try:
                    req = Requirement(line)
                except Exception as e:
                    logging.warning(f"Skipping unparsable requirement line {line!r}: {e}")
                    continue
                dependencies.append((req.name, _exact_or_spec_version(req)))
        return dependencies
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading requirements.txt file: {e}")
        sys.exit(1)


def read_package_json(file_path: str):
    """Returns a list of (name, version_or_specifier) tuples."""
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
            deps = {}
            deps.update(data.get("dependencies", {}) or {})
            deps.update(data.get("devDependencies", {}) or {})
            out = []
            for name, ver in deps.items():
                v = str(ver).strip().lstrip("^~") if ver is not None else None
                out.append((name, v or None))
            return out
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON in package.json: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading package.json file: {e}")
        sys.exit(1)


def read_pom_xml(file_path: str):
    """Returns a list of (artifactId, version_or_None) tuples."""
    try:
        with open(file_path, "r") as f:
            soup = BeautifulSoup(f, 'xml')
            out = []
            for dep in soup.find_all('dependency'):
                art = dep.find('artifactId')
                if not art:
                    continue
                ver = dep.find('version')
                v = ver.text.strip() if ver and ver.text else None
                if v and v.startswith("${"):
                    v = None
                out.append((art.text.strip(), v))
            return out
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading pom.xml file: {e}")
        sys.exit(1)


def _parse_cpe(criteria):
    parts = (criteria or "").split(":")
    if len(parts) >= 7 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[4].lower(), parts[5]
    if (criteria or "").startswith("cpe:/"):
        pp = criteria[5:].split(":")
        if len(pp) >= 4:
            return pp[2].lower(), pp[3]
    return None, None


def _version_satisfies(dep_version, criteria_version, match):
    """True when the dependency version falls in the CPE match version or range."""
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version, InvalidVersion
    start_inc = match.get("versionStartIncluding"); start_exc = match.get("versionStartExcluding")
    end_inc = match.get("versionEndIncluding"); end_exc = match.get("versionEndExcluding")
    has_range = any([start_inc, start_exc, end_inc, end_exc])
    def _cmp(vstr):
        try:
            return Version(vstr)
        except InvalidVersion:
            return None
    if dep_version is None:
        return True
    dep_version = str(dep_version).strip()
    is_spec = dep_version[0] in "<>=!~" or "," in dep_version
    if is_spec:
        # The dependency is a range: the entry version must fall inside it.
        target = criteria_version
        if has_range or not target or target in ("*", "-"):
            return True
        tv = _cmp(target)
        if tv is None:
            return False
        try:
            return SpecifierSet(dep_version).contains(tv, prereleases=True)
        except Exception:
            return False
    dv = _cmp(dep_version)
    if dv is None:
        return False
    if has_range:
        if start_inc and dv < _cmp(start_inc): return False
        if start_exc and dv <= _cmp(start_exc): return False
        if end_inc and dv > _cmp(end_inc): return False
        if end_exc and dv >= _cmp(end_exc): return False
        return True
    if criteria_version and criteria_version not in ("*", "-"):
        cv = _cmp(criteria_version)
        return cv is not None and dv == cv
    return True


def _entry_matches_dependency(vuln, dependency, dep_version):
    cve = vuln.get("cve") or {}
    configs = cve.get("configurations") or []
    found = False
    def walk(nodes):
        nonlocal found
        for node in nodes or []:
            for m in node.get("cpeMatch", []) or []:
                if m.get("vulnerable") is False:
                    continue
                prod, ver = _parse_cpe(m.get("criteria", ""))
                if prod and prod == str(dependency).lower() and _version_satisfies(dep_version, ver, m):
                    found = True
            walk(node.get("children") or node.get("nodes") or [])
    for cfg in configs:
        walk(cfg.get("nodes") or [])
    return found


def get_vulnerabilities(dependency: str, dep_version=None, api_key: Optional[str] = None):
    """Returns (matched_vulnerabilities, error). error is None on a completed query."""
    if isinstance(dependency, tuple):
        dependency, dep_version = dependency
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    collected = []
    start_index = 0
    total = None
    try:
        while True:
            params = {"keywordSearch": dependency, "resultsPerPage": 200, "startIndex": start_index}
            response = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            page = data.get("vulnerabilities", [])
            collected.extend(page)
            total = data.get("totalResults", len(collected))
            start_index += len(page) if page else 200
            if not page or len(collected) >= total:
                break
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching vulnerabilities for {dependency}: {e}")
        return [], str(e)
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON response for {dependency}")
        return [], "JSON decode error"
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return [], str(e)
    matched = [v for v in collected if _entry_matches_dependency(v, dependency, dep_version)]
    return matched, None


def analyze_vulnerabilities(vulnerabilities: List[Dict], severity_threshold: str) -> List[Dict]:
    """
    Analyzes the vulnerabilities and filters based on the severity threshold.

    Args:
        vulnerabilities (List[Dict]): A list of vulnerability dictionaries.
        severity_threshold (str): The minimum severity level to report.

    Returns:
        List[Dict]: A list of filtered vulnerability dictionaries.
    """

    severity_levels = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    threshold_value = severity_levels.get(severity_threshold, 1)  # Default to HIGH if invalid

    filtered_vulnerabilities = []
    for vulnerability in vulnerabilities:
        cve_item = vulnerability.get("cve")
        if not cve_item:
            continue

        metrics = cve_item.get("metrics", {})
        cvss_metric_v31 = metrics.get("cvssMetricV31", [])
        cvss_metric_v3 = metrics.get("cvssMetricV30", [])
        cvss_metric_v2 = metrics.get("cvssMetricV2", [])

        # Prioritize v3.1, then v3.0, then v2.0
        if cvss_metric_v31:
            # I always take element zero of whichever metric list exists, with no
            # check of whether that entry is the primary assessment or a secondary
            # one from another provider. The v2 branch reads baseSeverity from
            # cvssData, where v2 does not put it, so v2 only records filter out
            # here and print as N/A in the duplicated logic in generate_report.
            base_severity = cvss_metric_v31[0].get("cvssData", {}).get("baseSeverity")
        elif cvss_metric_v3:
            base_severity = cvss_metric_v3[0].get("cvssData", {}).get("baseSeverity")
        elif cvss_metric_v2:
            base_severity = cvss_metric_v2[0].get("cvssData", {}).get("baseSeverity")
        else:
            base_severity = None

        if base_severity:
            severity_value = severity_levels.get(base_severity, 4) # Assign a value greater than LOW if not found.

            if severity_value <= threshold_value:
                filtered_vulnerabilities.append(vulnerability)

    return filtered_vulnerabilities


def generate_report(dependency: str, vulnerabilities: List[Dict]) -> str:
    """
    Generates a report of the vulnerabilities found for a dependency.

    Args:
        dependency (str): The name of the dependency.
        vulnerabilities (List[Dict]): A list of vulnerability dictionaries.

    Returns:
        str: The report string.
    """
    if not vulnerabilities:
        return f"No vulnerabilities found for {dependency}.\n"

    report = f"Vulnerabilities found for {dependency}:\n"
    for vulnerability in vulnerabilities:
        cve_item = vulnerability.get("cve")
        cve_id = cve_item.get("id", "N/A")
        # descriptions[0] is whichever language entry the API lists first.
        # Nothing selects for English, so a report can quote a non English
        # description while every other field is in English.
        description = cve_item.get("descriptions", [{}])[0].get("value", "N/A")
        metrics = cve_item.get("metrics", {})

        cvss_metric_v31 = metrics.get("cvssMetricV31", [])
        cvss_metric_v3 = metrics.get("cvssMetricV30", [])
        cvss_metric_v2 = metrics.get("cvssMetricV2", [])

        # Prioritize v3.1, then v3.0, then v2.0
        if cvss_metric_v31:
            base_severity = cvss_metric_v31[0].get("cvssData", {}).get("baseSeverity", "N/A")
            base_score = cvss_metric_v31[0].get("cvssData", {}).get("baseScore", "N/A")
            vector_string = cvss_metric_v31[0].get("cvssData", {}).get("vectorString", "N/A")
        elif cvss_metric_v3:
            base_severity = cvss_metric_v3[0].get("cvssData", {}).get("baseSeverity", "N/A")
            base_score = cvss_metric_v3[0].get("cvssData", {}).get("baseScore", "N/A")
            vector_string = cvss_metric_v3[0].get("cvssData", {}).get("vectorString", "N/A")
        elif cvss_metric_v2:
            base_severity = cvss_metric_v2[0].get("cvssData", {}).get("baseSeverity", "N/A")
            base_score = cvss_metric_v2[0].get("cvssData", {}).get("baseScore", "N/A")
            vector_string = cvss_metric_v2[0].get("cvssData", {}).get("vectorString", "N/A")
        else:
            base_severity = "N/A"
            base_score = "N/A"
            vector_string = "N/A"

        report += f"  CVE ID: {cve_id}\n"
        report += f"  Description: {description}\n"
        report += f"  Severity: {base_severity}\n"
        report += f"  Score: {base_score}\n"
        report += f"  Vector: {vector_string}\n"
        report += "\n"

    return report


def write_output(report: str, output_file: Optional[str] = None) -> None:
    """
    Writes the report to the console or a file.

    Args:
        report (str): The report string.
        output_file (str, optional): Path to the output file. Defaults to None (console).
    """
    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(report)
            logging.info(f"Report written to {output_file}")
        except Exception as e:
            logging.error(f"Error writing to file: {e}")
    else:
        print(report)


def main() -> None:
    """
    Main function of the tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not os.path.exists(args.dependency_file):
        logging.error(f"Dependency file not found: {args.dependency_file}")
        sys.exit(1)

    if args.output and os.path.realpath(args.output) == os.path.realpath(args.dependency_file):
        logging.error("Refusing to write the output over the dependency file.")
        sys.exit(1)

    api_key = args.api_key or os.environ.get("NVD_API_KEY")

    file_name = os.path.basename(args.dependency_file)
    file_extension = file_name.split('.')[-1].lower()

    if file_extension == "txt":
        dependencies = read_requirements_txt(args.dependency_file)
    elif file_extension == "json":
        dependencies = read_package_json(args.dependency_file)
    elif file_extension == "xml":
        dependencies = read_pom_xml(args.dependency_file)
    else:
        logging.error(f"Unsupported file type: {file_extension}")
        sys.exit(1)

    if not dependencies:
        logging.error("No dependencies were found in the dependency file; nothing was checked.")
        sys.exit(1)

    logging.info(f"Analyzing dependencies from {args.dependency_file}")

    all_reports = ""
    failures = 0
    for dependency in dependencies:
        dep_name, dep_version = dependency if isinstance(dependency, tuple) else (dependency, None)
        logging.info(f"Checking vulnerabilities for {dep_name} {dep_version or ''}")
        vulnerabilities, error = get_vulnerabilities(dep_name, dep_version, api_key)
        if error is not None:
            failures += 1
            all_reports += f"Lookup failed for {dep_name}: {error}\n"
            continue
        filtered_vulnerabilities = analyze_vulnerabilities(vulnerabilities, args.severity_threshold)
        if not vulnerabilities:
            all_reports += f"No vulnerabilities matched {dep_name}.\n"
        elif vulnerabilities and not filtered_vulnerabilities:
            all_reports += f"No vulnerabilities at or above the {args.severity_threshold} threshold matched {dep_name}; {len(vulnerabilities)} matched below it.\n"
        else:
            all_reports += generate_report(dep_name, filtered_vulnerabilities)

    write_output(all_reports, args.output)
    if failures:
        logging.info(f"Vulnerability check complete with {failures} failed lookup(s) out of {len(dependencies)}.")
    else:
        logging.info("Vulnerability check complete.")
    if dependencies and failures == len(dependencies):
        logging.error("Every dependency query failed; no clean verdict is possible.")
        sys.exit(1)


if __name__ == "__main__":
    main()