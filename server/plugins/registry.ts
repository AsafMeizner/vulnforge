// Built-in catalog of popular security tools that can be installed as plugins

export interface PluginManifest {
  name: string;
  version: string;
  type: 'scanner' | 'reporter' | 'importer';
  description: string;
  install_command: string;
  run_command: string;
  parse_output: 'json' | 'text' | 'markdown';
  requires: string[];
}

export interface CatalogEntry {
  name: string;
  source_url: string;
  website_url: string;
  type: 'scanner' | 'reporter' | 'importer';
  description: string;
  long_description: string;
  install_command: string;
  run_command: string;
  parse_output: 'json' | 'text' | 'markdown';
  requires: string[];
  version: string;
  category: string;
  stars: string;
}

export const PLUGIN_CATALOG: CatalogEntry[] = [
  {
    name: 'OWASP Nettacker',
    source_url: 'https://github.com/OWASP/Nettacker',
    website_url: 'https://owasp.org/www-project-nettacker/',
    type: 'scanner',
    description: 'Automated penetration testing framework for network/web scanning',
    long_description: 'OWASP Nettacker is an open-source automated penetration testing and information gathering framework. It supports 12+ scan modules including XSS, SQLi, SSL analysis, port scanning, subdomain discovery, brute-force attacks, and more. Designed for both security professionals and bug bounty hunters.',
    install_command: 'git clone https://github.com/OWASP/Nettacker && pip install -e Nettacker',
    run_command: 'python nettacker.py -i {target} -m all -o {output}',
    parse_output: 'json',
    requires: ['python3', 'pip', 'git'],
    version: 'latest',
    category: 'Network & Web',
    stars: '3.5k',
  },
  {
    name: 'Garak',
    source_url: 'https://github.com/leondz/garak',
    website_url: 'https://docs.garak.ai/',
    type: 'scanner',
    description: 'LLM vulnerability scanner - red-teaming for language models',
    long_description: 'Garak is a framework for probing LLMs for vulnerabilities. It checks for prompt injection, data leakage, toxicity generation, hallucination, and other AI-specific risks. Supports 12+ probe categories across OpenAI, HuggingFace, and local models.',
    install_command: 'pip install garak',
    run_command: 'garak --model_type {model} --probes all -o {output}',
    parse_output: 'json',
    requires: ['python3'],
    version: 'latest',
    category: 'AI & LLM Security',
    stars: '2.2k',
  },
  {
    name: 'Nuclei',
    source_url: 'https://github.com/projectdiscovery/nuclei',
    website_url: 'https://nuclei.projectdiscovery.io/',
    type: 'scanner',
    description: 'Fast vulnerability scanner based on YAML templates',
    long_description: 'Nuclei is a fast, customizable vulnerability scanner powered by the global security community. It uses YAML-based templates to send requests across targets and detect vulnerabilities. 8000+ community templates covering CVEs, misconfigurations, exposed panels, default credentials, and more.',
    install_command: 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    run_command: 'nuclei -u {target} -o {output}',
    parse_output: 'text',
    requires: ['go'],
    version: 'latest',
    category: 'Network & Web',
    stars: '21k',
  },
  {
    name: 'Semgrep',
    source_url: 'https://github.com/semgrep/semgrep',
    website_url: 'https://semgrep.dev/',
    type: 'scanner',
    description: 'Lightweight static analysis - find bugs with custom rules',
    long_description: 'Semgrep is a fast, open-source static analysis tool for finding bugs and enforcing code standards. It supports 30+ languages and has 2000+ community rules. Pre-built rule packs for OWASP Top 10, CWE Top 25, secrets detection, and supply chain security.',
    install_command: 'pip install semgrep',
    run_command: 'semgrep --config auto {target} --json -o {output}',
    parse_output: 'json',
    requires: ['python3'],
    version: 'latest',
    category: 'Static Analysis',
    stars: '10k',
  },
  {
    name: 'Trivy',
    source_url: 'https://github.com/aquasecurity/trivy',
    website_url: 'https://trivy.dev/',
    type: 'scanner',
    description: 'Comprehensive vulnerability scanner for containers, repos, and cloud',
    long_description: 'Trivy is the most comprehensive security scanner. It finds vulnerabilities in OS packages, language-specific packages, misconfigurations, secrets, and licenses. Supports container images, filesystem, git repos, Kubernetes clusters, and cloud infrastructure (AWS, GCP, Azure).',
    install_command: 'curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh',
    run_command: 'trivy fs {target} --format json -o {output}',
    parse_output: 'json',
    requires: [],
    version: 'latest',
    category: 'Container & Cloud',
    stars: '24k',
  },
  {
    name: 'CodeQL',
    source_url: 'https://github.com/github/codeql',
    website_url: 'https://codeql.github.com/',
    type: 'scanner',
    description: "GitHub's semantic code analysis engine",
    long_description: "CodeQL is GitHub's code analysis engine. It treats code as data - you can write queries to find vulnerabilities across all variants of a bug pattern. Powers GitHub's code scanning. Supports C/C++, C#, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Swift.",
    install_command: 'gh extension install github/codeql',
    run_command: 'codeql database create {target}-db --language=cpp && codeql database analyze {target}-db --format=sarif -o {output}',
    parse_output: 'json',
    requires: ['gh'],
    version: 'latest',
    category: 'Static Analysis',
    stars: '7.5k',
  },
  {
    name: 'Bandit',
    source_url: 'https://github.com/PyCQA/bandit',
    website_url: 'https://bandit.readthedocs.io/',
    type: 'scanner',
    description: 'Security linter for Python code - finds common security issues',
    long_description: 'Bandit is a tool designed to find common security issues in Python code. It processes each file, builds an AST, and runs appropriate plugins against the AST nodes. Detects hardcoded passwords, SQL injection, shell injection, insecure crypto, and more.',
    install_command: 'pip install bandit',
    run_command: 'bandit -r {target} -f json -o {output}',
    parse_output: 'json',
    requires: ['python3'],
    version: 'latest',
    category: 'Static Analysis',
    stars: '6.5k',
  },
  {
    name: 'Grype',
    source_url: 'https://github.com/anchore/grype',
    website_url: 'https://github.com/anchore/grype',
    type: 'scanner',
    description: 'Vulnerability scanner for container images and filesystems',
    long_description: 'Grype is a vulnerability scanner for container images and filesystems by Anchore. It matches packages against known vulnerability databases (NVD, GitHub Advisories, OS-specific). Supports Docker, OCI, Singularity images, directories, SBOMs, and archives.',
    install_command: 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh',
    run_command: 'grype dir:{target} -o json --file {output}',
    parse_output: 'json',
    requires: [],
    version: 'latest',
    category: 'Container & SCA',
    stars: '8.5k',
  },
  {
    name: 'OSV-Scanner',
    source_url: 'https://github.com/google/osv-scanner',
    website_url: 'https://osv.dev/',
    type: 'scanner',
    description: "Google's open source vulnerability scanner for dependencies",
    long_description: "OSV-Scanner uses Google's OSV.dev database (the largest open-source vulnerability database) to find known vulnerabilities in your project's dependencies. Supports lockfiles from npm, pip, Go, Cargo, Maven, and more. Integrates with CI/CD pipelines.",
    install_command: 'go install github.com/google/osv-scanner/cmd/osv-scanner@latest',
    run_command: 'osv-scanner --format json -r {target} > {output}',
    parse_output: 'json',
    requires: ['go'],
    version: 'latest',
    category: 'SCA & Dependencies',
    stars: '6.5k',
  },
  {
    name: 'Safety',
    source_url: 'https://github.com/pyupio/safety',
    website_url: 'https://safetycli.com/',
    type: 'scanner',
    description: 'Checks Python dependencies for known vulnerabilities',
    long_description: 'Safety checks Python dependencies against a curated vulnerability database. It scans requirements.txt, Pipfile, or the current virtual environment. Simple to use, integrates with CI/CD, and provides actionable remediation advice with upgrade paths.',
    install_command: 'pip install safety',
    run_command: 'safety check --json -o {output}',
    parse_output: 'json',
    requires: ['python3'],
    version: 'latest',
    category: 'SCA & Dependencies',
    stars: '1.7k',
  },
];

/**
 * Look up a catalog entry by name (case-insensitive).
 */
export function getCatalogEntry(name: string): CatalogEntry | null {
  const lower = name.toLowerCase();
  return PLUGIN_CATALOG.find(e => e.name.toLowerCase() === lower) ?? null;
}

/**
 * Look up a catalog entry by source URL.
 */
export function getCatalogEntryByUrl(url: string): CatalogEntry | null {
  return PLUGIN_CATALOG.find(e => e.source_url === url) ?? null;
}
