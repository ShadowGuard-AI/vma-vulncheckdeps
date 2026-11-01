# vma-VulnCheckDeps
A command-line tool to check if project dependencies (requirements.txt, package.json, etc.) have known vulnerabilities using a public vulnerability database (e.g., NIST NVD). - Focused on Automates the discovery, prioritization, and tracking of vulnerabilities in web applications based on public feeds and identified application components. Focuses on generating actionable reports and integrating with issue tracking systems.

## Install
`git clone https://github.com/ShadowGuardAI/vma-vulncheckdeps`

## Usage
`./vma-vulncheckdeps [params]`

## Parameters
- `-h`: Show help message and exit
- `--api_key`: Optional NVD API key override. The primary route is the `NVD_API_KEY` environment variable; set that instead of passing the key on the command line where possible. The key is sent in the `apiKey` header.
- `--output`: Path to the output file (optional, defaults to console). It must not be the dependency file itself.
- `--severity_threshold`: Minimum severity level to report (CRITICAL, HIGH, MEDIUM, LOW). Defaults to HIGH.

Dependency versions are read from requirements.txt, package.json, and pom.xml, sent with the NVD API 2.0 `keywordSearch` parameter, and returned entries are filtered by affected CPE product and version range before they are reported. Results are paginated to `totalResults`.

## License
Copyright (c) ShadowGuardAI
