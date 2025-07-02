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
        help="NIST NVD API Key (optional, but recommended for higher rate limits).  Get it here: https://nvd.nist.gov/developers/request-an-api-key",
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


def read_requirements_txt(file_path: str) -> List[str]:
    """
    Reads a requirements.txt file and returns a list of dependencies.

    Args:
        file_path (str): Path to the requirements.txt file.

    Returns:
        List[str]: A list of dependency names.
    """
    try:
        with open(file_path, "r") as f:
            dependencies = [line.strip().split("==")[0].split(">=")[0].split("<=")[0].split(">")[0].split("<")[0] for line in f if line.strip() and not line.startswith("#")]
        return dependencies
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        sys.exit(1)  # Exit with an error code
    except Exception as e:
        logging.error(f"Error reading requirements.txt file: {e}")
        sys.exit(1)


def read_package_json(file_path: str) -> List[str]:
    """
    Reads a package.json file and returns a list of dependencies.

    Args:
        file_path (str): Path to the package.json file.

    Returns:
        List[str]: A list of dependency names.
    """
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
            dependencies = list(data.get("dependencies", {}).keys()) + list(data.get("devDependencies", {}).keys())
        return dependencies
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON in package.json: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading package.json file: {e}")
        sys.exit(1)


def read_pom_xml(file_path: str) -> List[str]:
    """
    Reads a pom.xml file and extracts the artifactId of dependencies

    Args:
        file_path (str): Path to the pom.xml file.

    Returns:
        List[str]: A list of dependency names (artifactIds).
    """
    try:
        with open(file_path, "r") as f:
            soup = BeautifulSoup(f, 'xml')
            dependencies = [dep.find('artifactId').text for dep in soup.find_all('dependency') if dep.find('artifactId')]  # Find all artifactIds
        return dependencies
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading pom.xml file: {e}")
        sys.exit(1)


def get_vulnerabilities(dependency: str, api_key: Optional[str] = None) -> List[Dict]:
    """
    Fetches vulnerabilities for a given dependency from the NIST NVD.

    Args:
        dependency (str): The name of the dependency.
        api_key (str, optional): The NIST NVD API key. Defaults to None.

    Returns:
        List[Dict]: A list of vulnerability dictionaries.
    """
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keyword": dependency,
        "resultsPerPage": 200  # Adjust as needed
    }

    try:
        response = requests.get(NVD_BASE_URL, headers=headers, params=params)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        return vulnerabilities
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching vulnerabilities for {dependency}: {e}")
        return []
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON response for {dependency}")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return []


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

    # Input validation
    if not os.path.exists(args.dependency_file):
        logging.error(f"Dependency file not found: {args.dependency_file}")
        sys.exit(1)

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

    logging.info(f"Analyzing dependencies from {args.dependency_file}")

    all_reports = ""
    for dependency in dependencies:
        logging.info(f"Checking vulnerabilities for {dependency}")
        vulnerabilities = get_vulnerabilities(dependency, args.api_key)
        filtered_vulnerabilities = analyze_vulnerabilities(vulnerabilities, args.severity_threshold)
        report = generate_report(dependency, filtered_vulnerabilities)
        all_reports += report

    write_output(all_reports, args.output)
    logging.info("Vulnerability check complete.")


if __name__ == "__main__":
    main()