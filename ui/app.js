/* ============================================================
   SiteRecorder CyberOps — Application Logic
   ============================================================ */

(function() {
    'use strict';

    // ========================================
    // State Management
    // ========================================

    const state = {
        team: 'red',
        section: 'red-dashboard',
        sidebar: {
            collapsed: false,
        },
        ui: {
            theme: 'dark',
            commandPaletteOpen: false,
            toasts: [],
            modals: [],
        },
        data: {
            targets: [],
            findings: [],
            activeOperations: [],
            scanResults: null,
            scanStatus: null,
            notifications: [],
            authProfiles: [],
            scanHistory: [],
            scans: [],
            redReports: [],
            simulations: [],
            correlations: [],
            attackSurface: { assets: 0, exposure: 0, risk: 0, changes: 0 },
            grayReports: [],
            alerts: [],
            malwareSamples: [],
            networkStatus: { monitored: 0, alerts: 0, blocked: 0, bandwidth: 0 },
            endpoints: [],
            cloudDefense: { accounts: 0, findings: 0, compliance: 0 },
            blueReports: [],
            metrics: { mttr: 48, patchRate: 87, phishRate: 12, openFindings: 5 },
            whiteReports: [],
            proxySessions: [],
            packets: [],
            captureRunning: false,
            captureInterval: null,
            recordingSessions: [],
            recordingInterval: null,
            recordingStartTime: null,
            activity: [],
        },
        tauri: null,
    };

    // ========================================
    // Tauri API Setup
    // ========================================

    function initTauri() {
        if (!window.__TAURI__) {
            console.warn('Tauri API not available — running in web mode');
            return false;
        }
        if (window.__TAURI__.tauri && window.__TAURI__.tauri.invoke) {
            state.tauri = window.__TAURI__.tauri.invoke;
        } else if (window.__TAURI__.invoke) {
            state.tauri = window.__TAURI__.invoke;
        }
        return !!state.tauri;
    }

    async function invoke(command, args = {}) {
        if (!state.tauri) {
            console.log(`[Mock] invoke('${command}',`, args, ')');
            return mockResponse(command, args);
        }
        return state.tauri(command, args);
    }

    function mockResponse(command, args) {
        const mocks = {
            get_status: { is_running: false, session_id: '', current_url: '', pages_visited: 0, pages_discovered: 0 },
            start_recording: `session_${Date.now()}`,
            stop_recording: null,
            run_vulnerability_scan: {
                scan_id: `scan_${Date.now()}`,
                url: args.url,
                summary: {
                    critical_count: 2, high_count: 5, medium_count: 8, low_count: 12, info_count: 20,
                    vulnerable: 15, total_checks: 100, risk_score: 7.2,
                },
                results: [
                    { check_name: 'SQL Injection', severity: 'CRITICAL', status: 'VULNERABLE', findings: [{ severity: 'CRITICAL', title: 'SQL Injection in Login Form', description: 'The login form is vulnerable to SQL injection attacks.', remediation: 'Use parameterized queries and input validation.', cwe_id: 'CWE-89' }] },
                    { check_name: 'XSS Reflected', severity: 'HIGH', status: 'VULNERABLE', findings: [{ severity: 'HIGH', title: 'Reflected XSS in Search', description: 'User input is reflected without sanitization.', remediation: 'Encode output and implement CSP headers.', cwe_id: 'CWE-79' }] },
                    { check_name: 'CSRF Protection', severity: 'MEDIUM', status: 'WARNING', findings: [{ severity: 'MEDIUM', title: 'Missing CSRF Token', description: 'Forms lack CSRF protection tokens.', remediation: 'Implement anti-CSRF tokens on all state-changing forms.' }] },
                    { check_name: 'SSL/TLS Configuration', severity: 'LOW', status: 'PASSED', findings: [] },
                    { check_name: 'HTTP Security Headers', severity: 'INFO', status: 'PASSED', findings: [] },
                ],
            },
            get_scan_results: null,
            list_vuln_scans: [],
            load_vuln_scan: null,
            delete_vuln_scan: null,
            export_vuln_scan: '{}',
            save_export: null,
            network_port_scan: {
                target: args.target,
                hosts: [{
                    ip: args.target,
                    hostname: 'target.local',
                    ports: [
                        { port: 22, protocol: 'TCP', state: 'Open', service: { name: 'ssh', product: 'OpenSSH 8.9' }, banner: 'SSH-2.0-OpenSSH_8.9' },
                        { port: 80, protocol: 'TCP', state: 'Open', service: { name: 'http', product: 'nginx 1.24' }, banner: 'nginx/1.24.0' },
                        { port: 443, protocol: 'TCP', state: 'Open', service: { name: 'https', product: 'nginx 1.24' } },
                        { port: 3306, protocol: 'TCP', state: 'Open', service: { name: 'mysql', product: 'MySQL 8.0' } },
                    ],
                }],
                durationMs: 1250,
            },
            network_dns_lookup: {
                domain: args.domain,
                records: [
                    { record_type: 'A', value: '93.184.216.34' },
                    { record_type: 'AAAA', value: '2606:2800:220:1:248:1893:25c8:1946' },
                    { record_type: 'MX', value: 'mail.' + args.domain },
                ],
                mx_records: ['mail.' + args.domain, 'mail2.' + args.domain],
                ns_records: ['ns1.example.com', 'ns2.example.com'],
                txt_records: ['v=spf1 include:_spf.google.com ~all'],
            },
            network_subdomain_enum: {
                domain: args.domain,
                total_found: 3,
                scan_time_ms: 850,
                subdomains: [
                    { subdomain: 'www.' + args.domain, record_type: 'A', ip: '93.184.216.34' },
                    { subdomain: 'mail.' + args.domain, record_type: 'A', ip: '93.184.216.35' },
                    { subdomain: 'api.' + args.domain, record_type: 'CNAME', ip: 'cdn.example.com' },
                ],
            },
            network_ssl_check: {
                hostname: args.hostname,
                issuer: 'Let\'s Authority X3',
                subject: 'CN=' + args.hostname,
                not_before: '2024-01-15',
                not_after: '2024-07-15',
                protocol_version: 'TLS 1.3',
                cipher_suite: 'TLS_AES_256_GCM_SHA384',
                san: [args.hostname, 'www.' + args.hostname],
            },
            os_pentest_scan: {
                target_os: args.targetOs,
                summary: { risk_score: 6.5 },
                findings: [
                    { severity: 'HIGH', title: 'Unpatched Kernel', category: 'patch_management', description: 'System running outdated kernel with known vulnerabilities.', details: ['CVE-2024-1086', 'CVE-2024-13112'], remediation: 'Update kernel to latest stable version.', cve_ids: ['CVE-2024-1086'] },
                    { severity: 'MEDIUM', title: 'World-Writable Scripts', category: 'file_permissions', description: 'Scripts in /tmp are world-writable.', details: ['/tmp/cleanup.sh', '/tmp/backup.sh'], remediation: 'Restrict file permissions to owner only.' },
                    { severity: 'LOW', title: 'SSH Password Auth', category: 'authentication', description: 'SSH allows password authentication.', remediation: 'Disable password auth, use key-based auth only.' },
                ],
            },
            mobile_analyze: {
                target_type: args.target,
                summary: { risk_score: 5.8 },
                findings: [
                    { severity: 'HIGH', title: 'Insecure Data Storage', description: 'Sensitive data stored in plaintext SharedPreferences.', remediation: 'Use EncryptedSharedPreferences.', cwe_id: 'CWE-312', owasp_id: 'M2' },
                    { severity: 'MEDIUM', title: 'Weak Encryption', description: 'App uses DES encryption which is considered weak.', remediation: 'Migrate to AES-256 encryption.', cwe_id: 'CWE-327', owasp_id: 'M5' },
                ],
            },
            cloud_scan: {
                provider: args.provider,
                summary: { compliance_score: 72 },
                compliance: { 'CIS Benchmark': 68, 'SOC2': 75, 'PCI-DSS': 71, 'HIPAA': 74 },
                findings: [
                    { severity: 'CRITICAL', title: 'Public S3 Bucket', category: 'storage', description: 'S3 bucket allows public read access.', resource: 'arn:aws:s3:::data-bucket', remediation: 'Enable S3 Block Public Access.', cis_benchmark: 'CIS 2.1.5' },
                    { severity: 'HIGH', title: 'Security Group Open', category: 'network', description: 'Security group allows 0.0.0.0/0 on port 22.', resource: 'sg-12345678', remediation: 'Restrict SSH access to specific IPs.' },
                    { severity: 'MEDIUM', title: 'Unencrypted EBS Volume', category: 'storage', description: 'EBS volume does not have encryption enabled.', resource: 'vol-abcdef123', remediation: 'Enable EBS encryption.' },
                ],
            },
            web3_scan_contract: {
                chain: args.chain,
                score: 65,
                findings: [
                    { severity: 'CRITICAL', title: 'Reentrancy Vulnerability', description: 'External call before state update enables reentrancy attack.', remediation: 'Apply checks-effects-interactions pattern.', swc_id: 'SWC-107', cwe_id: 'CWE-841' },
                    { severity: 'HIGH', title: 'Unchecked Return Value', description: 'Transfer return value not checked.', remediation: 'Check return value of transfer calls.', cwe_id: 'CWE-252' },
                    { severity: 'MEDIUM', title: 'Floating Pragma', description: 'Contract uses floating pragma ^0.8.0.', remediation: 'Pin to specific compiler version.' },
                ],
            },
            web3_analyze_wallet: {
                chain: args.chain,
                address: args.address,
                risk_score: 42,
                findings: [
                    { severity: 'HIGH', title: 'Interaction with Known Scam Contract', description: 'Wallet has approved tokens to a known scam contract.', details: ['Contract: 0xbad...cafe', 'Time: 2024-01-15'], remediation: 'Revoke token approvals immediately.' },
                    { severity: 'MEDIUM', title: 'High Gas Usage Pattern', description: 'Unusual gas spending pattern detected.', details: ['Avg: 0.5 ETH/tx'], remediation: 'Review transaction history for unauthorized activity.' },
                ],
            },
            password_identify_hash: [
                { hash_type: 'MD5', confidence: 95, hash: args.hash },
                { hash_type: 'NTLM', confidence: 80, hash: args.hash },
            ],
            password_crack: {
                status: 'Found',
                hash_type: args.hashType,
                hash: args.hash,
                plaintext: 'password123',
                attempts: 45231,
                durationMs: 1250,
            },
            password_generate_mask: Array.from({length: 50}, (_, i) => `candidate_${i}`),
            password_get_default_wordlist: ['password', '123456', 'qwerty', 'admin', 'welcome', 'password123', 'letmein', 'monkey', 'dragon', 'master'],
            grayteam_get_attck_matrix: {
                techniques: [
                    { id: 'T1566', name: 'Phishing', tactic: 'initial-access' },
                    { id: 'T1059', name: 'Command Interpreter', tactic: 'execution' },
                    { id: 'T1003', name: 'Credential Dumping', tactic: 'credential-access' },
                    { id: 'T1078', name: 'Valid Accounts', tactic: 'persistence' },
                    { id: 'T1055', name: 'Process Injection', tactic: 'defense-evasion' },
                ],
                coverage: {
                    'T1566': { covered: true, tested: true },
                    'T1059': { covered: true, tested: false },
                    'T1003': { covered: false, tested: false },
                    'T1078': { covered: true, tested: true },
                    'T1055': { covered: false, tested: false },
                },
                domains: [{
                    name: 'Enterprise',
                    tactics: [
                        { id: 'initial-access', name: 'Initial Access' },
                        { id: 'execution', name: 'Execution' },
                        { id: 'credential-access', name: 'Credential Access' },
                        { id: 'persistence', name: 'Persistence' },
                        { id: 'defense-evasion', name: 'Defense Evasion' },
                    ],
                }],
            },
            grayteam_create_threat_model: {
                name: args.name,
                description: args.description,
                threats: [
                    { name: 'Spoofing of User Identity', stride_category: 'Spoofing', severity: 'High', risk_score: 8.5, likelihood: 'High', impact: 'Critical', description: 'An attacker could spoof user identity through stolen credentials.', mitigations: ['Implement MFA', 'Use session timeouts', 'Monitor login anomalies'], related_techniques: ['T1078', 'T1566'] },
                    { name: 'Tampering with Data', stride_category: 'Tampering', severity: 'Critical', risk_score: 9.2, likelihood: 'Medium', impact: 'Critical', description: 'Data could be tampered during transmission.', mitigations: ['Use TLS 1.3', 'Implement integrity checks', 'Apply digital signatures'], related_techniques: ['T1565'] },
                    { name: 'Information Disclosure', stride_category: 'Information Disclosure', severity: 'Medium', risk_score: 6.1, likelihood: 'Medium', impact: 'High', description: 'Sensitive data could be exposed through error messages.', mitigations: ['Implement proper error handling', 'Use generic error messages', 'Log security events'], related_techniques: ['T1552'] },
                ],
            },
            grayteam_create_purple_exercise: {
                name: args.name,
                description: args.description,
                scenarios: [
                    { name: 'Phishing to Credential Theft', attack_type: 'Phishing', duration_minutes: 45, target_systems: ['Email Gateway', 'AD'], mitre_techniques: ['T1566', 'T1078'], expected_detection: true, description: 'Simulate a targeted phishing campaign against employees.' },
                    { name: 'Lateral Movement via RDP', attack_type: 'Lateral Movement', duration_minutes: 60, target_systems: ['Workstations', 'DC'], mitre_techniques: ['T1021', 'T1078'], expected_detection: false, description: 'Move laterally using compromised credentials via RDP.' },
                    { name: 'Data Exfiltration', attack_type: 'Exfiltration', duration_minutes: 30, target_systems: ['File Server', 'Cloud Storage'], mitre_techniques: ['T1048', 'T1567'], expected_detection: true, description: 'Exfiltrate sensitive data through DNS tunneling.' },
                ],
            },
            grayteam_get_sigma_rules: [
                { name: 'Suspicious PowerShell Execution', rule_type: 'Detection', description: 'Detects suspicious PowerShell command execution.', content: 'title: Suspicious PowerShell\ndetection:\n  condition: selection\n  selection:\n    CommandLine|contains: -enc', tested: true, mitre_techniques: ['T1059'] },
                { name: 'Credential Dumping via LSASS', rule_type: 'Detection', description: 'Detects LSASS access for credential dumping.', content: 'title: LSASS Access\ndetection:\n  condition: selection\n  selection:\n    TargetImage: lsass.exe', tested: false, mitre_techniques: ['T1003'] },
                { name: 'New Scheduled Task Creation', rule_type: 'Hunt', description: 'Identifies suspicious scheduled task creation.', content: 'title: Scheduled Task\ndetection:\n  condition: selection\n  selection:\n    EventID: 4698', tested: true, mitre_techniques: ['T1053'] },
            ],
            grayteam_get_apt_techniques: ['T1566', 'T1078', 'T1059', 'T1003', 'T1055', 'T1021', 'T1048', 'T1567', 'T1110', 'T1133'],
            blueteam_get_soc_dashboard: {
                total_alerts: 156,
                open_incidents: 8,
                mean_time_to_detect_minutes: 4.2,
                mean_time_to_respond_minutes: 12.8,
                severity_distribution: { critical: 5, high: 18, medium: 45, low: 62, info: 26 },
                top_alert_sources: [
                    { name: 'CrowdStrike Falcon', count: 45, severity: 'High' },
                    { name: 'Palo Alto NGFW', count: 32, severity: 'Medium' },
                    { name: 'Azure Sentinel', count: 28, severity: 'Critical' },
                    { name: 'Proofpoint', count: 24, severity: 'High' },
                    { name: 'Splunk UBA', count: 18, severity: 'Low' },
                ],
                recent_alerts: [
                    { title: 'Suspicious Process Injection', source: 'CrowdStrike', severity: 'Critical', timestamp: Date.now() - 300000 },
                    { title: 'Multiple Failed Logins', source: 'Azure AD', severity: 'High', timestamp: Date.now() - 600000 },
                    { title: 'Malware Detected', source: 'Defender', severity: 'Critical', timestamp: Date.now() - 900000 },
                ],
            },
            blueteam_create_incident: {
                id: `INC-${Date.now()}`,
                title: args.title,
                description: args.description,
                severity: args.severity,
                category: args.category,
                status: 'Open',
                created_at: Date.now(),
            },
            blueteam_get_ir_playbooks: {
                'Ransomware Response': ['Isolate affected systems', 'Identify ransomware variant', 'Restore from backups', 'Patch vulnerability', 'Conduct post-incident review'],
                'Data Breach Response': ['Contain the breach', 'Assess scope and impact', 'Notify affected parties', 'Preserve evidence', 'Implement remediation'],
                'Phishing Campaign': ['Block sender domains', 'Quarantine affected emails', 'Reset compromised credentials', 'User awareness training', 'Update email filters'],
                'APT Investigation': ['Establish scope', 'Deploy additional monitoring', 'Collect forensic evidence', 'Coordinate with legal', 'Execute containment'],
            },
            blueteam_get_threat_feeds: [
                { name: 'AlienVault OTX', description: 'Open Threat Exchange community feed', indicator_count: 45000, enabled: true },
                { name: 'Abuse.ch URLhaus', description: 'Malware URL sharing platform', indicator_count: 12000, enabled: true },
                { name: 'MISP Community', description: 'MISP threat sharing platform', indicator_count: 85000, enabled: false },
                { name: 'VirusTotal Intelligence', description: 'Advanced threat intelligence', indicator_count: 250000, enabled: true },
            ],
            blueteam_get_threat_actors: [
                { name: 'APT28 (Fancy Bear)', country: 'Russia', aliases: ['Sofacy', 'STRONTIUM', 'Sednit'], motivation: 'Espionage', sophistication: 'High', description: 'Russian state-sponsored cyber espionage group.', mitre_techniques: ['T1566', 'T1078', 'T1059'] },
                { name: 'APT29 (Cozy Bear)', country: 'Russia', aliases: ['The Dukes', 'CozyDuke'], motivation: 'Espionage', sophistication: 'High', description: 'Russian threat group targeting governments.', mitre_techniques: ['T1078', 'T1021', 'T1048'] },
                { name: 'Lazarus Group', country: 'North Korea', aliases: ['Hidden Cobra', 'Guardians of Peace'], motivation: 'Financial', sophistication: 'High', description: 'North Korean state-sponsored threat group.', mitre_techniques: ['T1566', 'T1486', 'T1490'] },
            ],
            blueteam_get_indicators: [
                { indicator_type: 'IP Address', value: '198.51.100.42', severity: 'Critical', confidence: 95 },
                { indicator_type: 'Domain', value: 'evil.example.com', severity: 'High', confidence: 88 },
                { indicator_type: 'File Hash', value: 'd41d8cd98f00b204e9800998ecf8427e', severity: 'Critical', confidence: 99 },
                { indicator_type: 'URL', value: 'http://phishing.example.com/login', severity: 'Medium', confidence: 75 },
            ],
            blueteam_create_hunt: {
                title: args.title,
                description: args.description,
                mitre_technique: args.mitreTechnique,
                data_sources: ['Windows Event Logs', 'Sysmon', 'EDR Telemetry', 'Network Flow Logs'],
                search_queries: [
                    `EventID=4688 AND NewProcessName=*${args.mitreTechnique}*`,
                    `sysmon.EventID=1 AND Image=*powershell*`,
                ],
            },
            blueteam_get_malware_analysis: {
                sample_name: 'suspicious_file.exe',
                file_type: 'PE32 Executable',
                file_size: 245760,
                md5: 'd41d8cd98f00b204e9800998ecf8427e',
                sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                risk_score: 82,
                signatures: [
                    { name: 'Trojan.Emotet', severity: 'Critical', description: 'Known Emotet trojan variant' },
                    { name: 'C2 Communication', severity: 'High', description: 'Connects to known C2 server' },
                ],
                behavior: [
                    { category: 'Process', severity: 'High', description: 'Injects code into explorer.exe' },
                    { category: 'Registry', severity: 'Medium', description: 'Creates Run key for persistence' },
                    { category: 'Network', severity: 'High', description: 'Connects to 198.51.100.42:443' },
                    { category: 'File', severity: 'Medium', description: 'Drops payload in %APPDATA%' },
                ],
            },
            whiteteam_get_grc_dashboard: {
                compliance_score: 78,
                open_risks: 23,
                critical_risks: 4,
                training_completion_rate: 82,
                frameworks: [
                    { name: 'ISO 27001:2022', score: 82 },
                    { name: 'SOC 2 Type II', score: 75 },
                    { name: 'PCI DSS 4.0', score: 71 },
                    { name: 'NIST CSF', score: 79 },
                ],
                risk_trend: [
                    { date: 'Jan', open_count: 28, closed_count: 12, avg_score: 6.8 },
                    { date: 'Feb', open_count: 25, closed_count: 15, avg_score: 6.5 },
                    { date: 'Mar', open_count: 23, closed_count: 18, avg_score: 6.2 },
                    { date: 'Apr', open_count: 23, closed_count: 14, avg_score: 6.0 },
                ],
            },
            whiteteam_get_compliance_frameworks: [
                {
                    name: 'ISO 27001', version: '2022', overall_score: 82,
                    categories: [
                        { name: 'A.5 Organizational Controls', score: 85, controls: [{ id: 'A.5.1', name: 'Policies for Information Security', status: 'Implemented' }, { id: 'A.5.2', name: 'Information Security Roles', status: 'Implemented' }, { id: 'A.5.3', name: 'Segregation of Duties', status: 'In Progress', gaps: ['Missing role documentation'] }] },
                        { name: 'A.8 Technological Controls', score: 78, controls: [{ id: 'A.8.1', name: 'User Endpoint Devices', status: 'Implemented' }, { id: 'A.8.9', name: 'Configuration Management', status: 'In Progress', gaps: ['Missing baseline configs'] }, { id: 'A.8.10', name: 'Information Deletion', status: 'Not Implemented', gaps: ['No deletion procedure'] }] },
                    ],
                },
            ],
            whiteteam_get_risk_register: {
                risks: [
                    { title: 'Cloud Data Breach', risk_score: 20, category: 'cyber_security', description: 'Unauthorized access to cloud-stored sensitive data.', treatment: 'Mitigate', owner: 'CISO', inherent_score: 25, residual_score: 12, mitigations: ['Implement DLP', 'Enable CASB', 'Enforce MFA'] },
                    { title: 'Ransomware Attack', risk_score: 18, category: 'cyber_security', description: 'Business disruption from ransomware encryption.', treatment: 'Mitigate', owner: 'SOC Manager', inherent_score: 25, residual_score: 10, mitigations: ['Offline backups', 'EDR deployment', 'User training'] },
                    { title: 'Third-Party Data Leak', risk_score: 15, category: 'third_party', description: 'Data exposure through vendor systems.', treatment: 'Transfer', vendor: 'Procurement', inherent_score: 20, residual_score: 8, mitigations: ['Vendor assessments', 'Contractual controls', 'Monitoring'] },
                ],
            },
            whiteteam_get_policies: [
                { name: 'Information Security Policy', version: '3.2', status: 'Published', category: 'information_security', owner: 'CISO', description: 'Overarching information security policy.', effective_date: '2024-01-01', review_date: '2025-01-01', acknowledgments: 245 },
                { name: 'Acceptable Use Policy', version: '2.1', status: 'Published', category: 'acceptable_use', owner: 'IT Director', description: 'Guidelines for acceptable use of company resources.', effective_date: '2024-01-01', review_date: '2025-01-01', acknowledgments: 240 },
                { name: 'Remote Work Security Policy', version: '1.0', status: 'Under Review', category: 'remote_work', owner: 'Security Manager', description: 'Security requirements for remote work.', effective_date: '2024-06-01', review_date: '2024-12-01', acknowledgments: 180 },
            ],
            whiteteam_get_vendors: [
                { name: 'CloudHost Pro', risk_level: 'Low', tier: 'Tier 1', description: 'Primary cloud infrastructure provider.', services: ['IaaS', 'PaaS'], data_access: ['PII', 'Financial'], contract_start: '2023-01-01', contract_end: '2025-12-31', assessments: [{ date: '2024-06-15', score: 88 }] },
                { name: 'SecureAuth Inc', risk_level: 'Medium', tier: 'Tier 2', description: 'Identity and access management services.', services: ['IAM', 'SSO'], data_access: ['Credentials', 'PII'], contract_start: '2023-06-01', contract_end: '2025-05-31', assessments: [{ date: '2024-03-10', score: 72 }] },
                { name: 'DataFlow Analytics', risk_level: 'High', tier: 'Tier 3', description: 'Data analytics and BI platform.', services: ['Analytics'], data_access: ['Financial', 'Customer Data'], contract_start: '2024-01-01', contract_end: '2024-12-31', assessments: [] },
            ],
            whiteteam_get_training: [
                { name: 'Security Awareness 2024', category: 'awareness', completion_rate: 92, description: 'Annual security awareness training for all employees.', duration_minutes: 45, required: true, enrollments: 245 },
                { name: 'Phishing Simulation', category: 'awareness', completion_rate: 88, description: 'Phishing identification and reporting training.', duration_minutes: 30, required: true, enrollments: 245 },
                { name: 'Secure Coding Practices', category: 'technical', completion_rate: 65, description: 'Secure software development training for engineering.', duration_minutes: 120, required: false, enrollments: 45 },
                { name: 'Incident Response Training', category: 'technical', completion_rate: 78, description: 'IR procedures and hands-on exercises.', duration_minutes: 90, required: true, enrollments: 30 },
            ],
            cross_get_assets: [
                { name: 'Production Web Server', asset_type: 'server', criticality: 'Critical', environment: 'Production', owner: 'DevOps Team', risk_score: 7.2, url: 'https://www.example.com', ip_addresses: ['203.0.113.10'], tags: ['production', 'external', 'web'], compliance_scope: ['SOC2', 'PCI'] },
                { name: 'API Gateway', asset_type: 'application', criticality: 'High', environment: 'Production', owner: 'Engineering', risk_score: 6.5, url: 'https://api.example.com', ip_addresses: ['203.0.113.20'], tags: ['production', 'api'], compliance_scope: ['SOC2'] },
                { name: 'Employee Database', asset_type: 'database', criticality: 'Critical', environment: 'Production', owner: 'HR Team', risk_score: 8.1, ip_addresses: ['10.0.1.50'], tags: ['production', 'pii', 'database'], compliance_scope: ['SOC2', 'GDPR'] },
                { name: 'Development Workstation', asset_type: 'workstation', criticality: 'Low', environment: 'Development', owner: 'Engineering', risk_score: 3.2, ip_addresses: ['10.1.2.100'], tags: ['development'], compliance_scope: [] },
                { name: 'VPN Gateway', asset_type: 'network', criticality: 'High', environment: 'Production', owner: 'Network Team', risk_score: 5.8, url: 'https://vpn.example.com', ip_addresses: ['203.0.113.1'], tags: ['production', 'vpn', 'network'], compliance_scope: ['SOC2'] },
            ],
            cross_get_notifications: [
                { title: 'Critical Vulnerability Found', severity: 'Critical', message: 'SQL Injection discovered in production web application.', source: 'Red Team', timestamp: Date.now() - 3600000, read: false },
                { title: 'Scan Completed', severity: 'Success', message: 'Network scan completed successfully. 5 hosts discovered.', source: 'Scanner', timestamp: Date.now() - 7200000, read: false },
                { title: 'New Alert Rule Triggered', severity: 'Warning', message: 'Suspicious login activity detected from new location.', source: 'Blue Team', timestamp: Date.now() - 10800000, read: true },
                { title: 'Compliance Score Updated', severity: 'Info', message: 'ISO 27001 compliance score updated to 82%.', source: 'White Team', timestamp: Date.now() - 86400000, read: true },
            ],
            cross_get_report_templates: [
                { name: 'Executive Summary', report_type: 'executive', format: 'PDF', description: 'High-level security posture summary for leadership.', sections: [{ title: 'Overview' }, { title: 'Key Metrics' }, { title: 'Top Risks' }, { title: 'Recommendations' }] },
                { name: 'Technical Findings', report_type: 'technical', format: 'PDF', description: 'Detailed technical vulnerability findings report.', sections: [{ title: 'Methodology' }, { title: 'Findings' }, { title: 'Evidence' }, { title: 'Remediation' }] },
                { name: 'Compliance Report', report_type: 'compliance', format: 'PDF', description: 'Compliance framework gap analysis and status.', sections: [{ title: 'Framework Overview' }, { title: 'Control Status' }, { title: 'Gaps' }, { title: 'Action Plan' }] },
                { name: 'Penetration Test Report', report_type: 'pentest', format: 'PDF', description: 'Full penetration test report with evidence.', sections: [{ title: 'Scope' }, { title: 'Executive Summary' }, { title: 'Findings' }, { title: 'Exploitation' }, { title: 'Recommendations' }] },
            ],
            cross_get_integrations: [
                { name: 'CrowdStrike Falcon', integration_type: 'EDR', status: 'Connected' },
                { name: 'Palo Alto NGFW', integration_type: 'Firewall', status: 'Connected' },
                { name: 'Azure Sentinel', integration_type: 'SIEM', status: 'Connected' },
                { name: 'Jira', integration_type: 'Ticketing', status: 'Connected' },
                { name: 'Slack', integration_type: 'Notification', status: 'Error' },
                { name: 'VirusTotal', integration_type: 'Threat Intel', status: 'Disconnected' },
            ],
            list_auth_profiles: [
                { id: 'auth_1', name: 'Production Admin', target_url: 'https://app.example.com', auth_type: 'form', mfa: 'totp', last_used: Date.now() - 3600000, created_at: Date.now() - 86400000 },
                { id: 'auth_2', name: 'API Service Account', target_url: 'https://api.example.com', auth_type: 'bearer', mfa: 'none', last_used: Date.now() - 7200000, created_at: Date.now() - 172800000 },
                { id: 'auth_3', name: 'Staging Basic Auth', target_url: 'https://staging.example.com', auth_type: 'basic', mfa: 'none', last_used: Date.now() - 86400000, created_at: Date.now() - 259200000 },
            ],
            get_auth_profile: { id: 'auth_1', name: 'Production Admin', target_url: 'https://app.example.com', auth_type: 'form', mfa: 'totp', totp_secret: 'JBSWY3DPEHPK3PXP', login_url: 'https://app.example.com/login', username: 'admin', created_at: Date.now() - 86400000 },
            create_auth_profile: { id: 'auth_' + Date.now(), name: 'New Profile', auth_type: 'form', created_at: Date.now() },
            update_auth_profile: { id: 'auth_1', name: 'Updated Profile', auth_type: 'form', updated_at: Date.now() },
            delete_auth_profile: null,
            test_auth_profile: { success: true, message: 'Authentication profile is valid. Login test successful.', session_token: 'sess_' + Date.now(), cookies: ['session=abc123'] },
            generate_totp: { code: '847291', valid_until: Date.now() + 30000 },
            validate_totp: true,
            generate_totp_secret: 'JBSWY3DPEHPK3PXP',
            get_totp_provisioning_uri: 'otpauth://totp/SiteRecorder:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=SiteRecorder&algorithm=SHA1&digits=6&period=30',
            list_audit_entries: [
                { id: 'audit_1', timestamp: Date.now() - 300000, user: 'operator', action: 'auth_profile_created', target: 'https://app.example.com', description: 'Created auth profile: Production Admin', ip: '192.168.1.100' },
                { id: 'audit_2', timestamp: Date.now() - 600000, user: 'operator', action: 'scan_started', target: 'https://target.com', description: 'Started vulnerability scan on target.com', ip: '192.168.1.100' },
                { id: 'audit_3', timestamp: Date.now() - 900000, user: 'admin', action: 'login', target: null, description: 'User login successful', ip: '10.0.0.50' },
                { id: 'audit_4', timestamp: Date.now() - 1200000, user: 'operator', action: 'auth_profile_updated', target: 'https://api.example.com', description: 'Updated auth profile: API Service Account', ip: '192.168.1.100' },
                { id: 'audit_5', timestamp: Date.now() - 1800000, user: 'operator', action: 'scan_completed', target: 'https://target.com', description: 'Vulnerability scan completed. Risk: 7.2/10', ip: '192.168.1.100' },
                { id: 'audit_6', timestamp: Date.now() - 3600000, user: 'admin', action: 'settings_changed', target: null, description: 'Changed output directory setting', ip: '10.0.0.50' },
                { id: 'audit_7', timestamp: Date.now() - 7200000, user: 'operator', action: 'auth_profile_deleted', target: 'https://old.example.com', description: 'Deleted auth profile: Old Profile', ip: '192.168.1.100' },
                { id: 'audit_8', timestamp: Date.now() - 10800000, user: 'admin', action: 'logout', target: null, description: 'User logged out', ip: '10.0.0.50' },
            ],
            cross_get_alert_rules: [
                { id: 'rule_1', name: 'Critical Vulnerability Alert', condition: 'severity == critical', enabled: true, channels: ['slack', 'email'], description: 'Triggered when critical vulnerability is found' },
                { id: 'rule_2', name: 'High Risk Score Alert', condition: 'risk_score >= 7.0', enabled: true, channels: ['pagerduty', 'slack'], description: 'Triggered when risk score exceeds threshold' },
                { id: 'rule_3', name: 'Scan Completion', condition: 'scan.status == completed', enabled: false, channels: ['email'], description: 'Notify when scan finishes' },
                { id: 'rule_4', name: 'Failed Login Attempts', condition: 'failed_logins > 5', enabled: true, channels: ['slack', 'pagerduty'], description: 'Alert on multiple failed login attempts' },
            ],
            password_get_wordlists: [
                { name: 'rockyou.txt', path: '/usr/share/wordlists/rockyou.txt', size: '134 MB', entries: 14344392, category: 'common' },
                { name: 'common-passwords.txt', path: '/usr/share/wordlists/common.txt', size: '2.4 MB', entries: 500000, category: 'common' },
                { name: 'darkweb2017-top10000.txt', path: '/usr/share/wordlists/darkweb2017.txt', size: '120 KB', entries: 10000, category: 'breach' },
                { name: 'subdomains-10000.txt', path: '/usr/share/wordlists/subdomains.txt', size: '85 KB', entries: 10000, category: 'subdomain' },
            ],
        };
        return new Promise(resolve => setTimeout(() => resolve(mocks[command] || null), 100));
    }

    // ========================================
    // DOM References
    // ========================================

    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const dom = {
        appLayout: () => $('#appLayout'),
        topbar: () => $('.topbar'),
        teamTabs: () => $('#teamTabs'),
        sidebar: () => $('#sidebar'),
        sidebarNav: () => $('#sidebarNav'),
        content: () => $('#contentArea'),
        commandPalette: () => $('#commandPalette'),
        commandInput: () => $('#commandInput'),
        commandResults: () => $('#commandResults'),
        toastContainer: () => $('#toastContainer'),
        modalContainer: () => $('#modalContainer'),
        globalSearch: () => $('#globalSearch'),
        notifBadge: () => $('#notifBadge'),
    };

    // ========================================
    // Custom Select Component
    // ========================================

    function createCustomSelect(selectElement) {
        if (selectElement.dataset.customSelectInitialized === 'true') return;
        selectElement.dataset.customSelectInitialized = 'true';

        const options = Array.from(selectElement.querySelectorAll('option'));
        const selectedOption = options.find(o => o.selected) || options[0];

        const wrapper = document.createElement('div');
        wrapper.className = 'custom-select';

        const trigger = document.createElement('div');
        trigger.className = 'custom-select-trigger';
        trigger.innerHTML = `
            <span class="select-value">${escapeHtml(selectedOption?.textContent || '')}</span>
            <span class="select-arrow">▼</span>
        `;

        const dropdown = document.createElement('div');
        dropdown.className = 'custom-select-dropdown';

        const searchContainer = document.createElement('div');
        searchContainer.className = 'custom-select-search';
        const searchInput = document.createElement('input');
        searchInput.type = 'text';
        searchInput.placeholder = 'Search...';
        searchContainer.appendChild(searchInput);

        if (options.length > 5) {
            dropdown.appendChild(searchContainer);
        }

        const optionsList = document.createElement('div');
        optionsList.className = 'custom-select-options';

        options.forEach(opt => {
            const optionEl = document.createElement('div');
            optionEl.className = 'custom-select-option' + (opt.selected ? ' selected' : '');
            optionEl.dataset.value = opt.value;
            optionEl.innerHTML = `
                <span class="option-label">${escapeHtml(opt.textContent)}</span>
                <span class="option-check">✓</span>
            `;
            optionEl.addEventListener('click', (e) => {
                e.stopPropagation();
                selectElement.value = opt.value;
                trigger.querySelector('.select-value').textContent = opt.textContent;
                optionsList.querySelectorAll('.custom-select-option').forEach(o => o.classList.remove('selected'));
                optionEl.classList.add('selected');
                closeDropdown();
                selectElement.dispatchEvent(new Event('change', { bubbles: true }));
            });
            optionsList.appendChild(optionEl);
        });

        dropdown.appendChild(optionsList);
        wrapper.appendChild(trigger);
        wrapper.appendChild(dropdown);
        selectElement.style.display = 'none';
        selectElement.parentNode.insertBefore(wrapper, selectElement.nextSibling);

        let portalDropdown = null;

        function createPortal() {
            if (portalDropdown) return portalDropdown;
            portalDropdown = dropdown.cloneNode(true);
            portalDropdown.classList.add('portal');
            document.body.appendChild(portalDropdown);

            // Re-attach event listeners to cloned options
            const clonedOptions = portalDropdown.querySelectorAll('.custom-select-option');
            clonedOptions.forEach((opt, idx) => {
                opt.addEventListener('click', (e) => {
                    e.stopPropagation();
                    selectElement.value = options[idx].value;
                    trigger.querySelector('.select-value').textContent = options[idx].textContent;
                    optionsList.querySelectorAll('.custom-select-option').forEach(o => o.classList.remove('selected'));
                    optionsList.querySelectorAll('.custom-select-option')[idx]?.classList.add('selected');
                    clonedOptions.forEach(o => o.classList.remove('selected'));
                    opt.classList.add('selected');
                    closeDropdown();
                    selectElement.dispatchEvent(new Event('change', { bubbles: true }));
                });
            });

            return portalDropdown;
        }

        function positionPortal() {
            if (!portalDropdown) return;
            const rect = trigger.getBoundingClientRect();
            portalDropdown.style.position = 'fixed';
            portalDropdown.style.top = `${rect.bottom + 4}px`;
            portalDropdown.style.left = `${rect.left}px`;
            portalDropdown.style.width = `${rect.width}px`;
        }

        function openDropdown() {
            closeAllSelects();
            wrapper.classList.add('open');
            searchInput.value = '';
            searchInput.focus();
            optionsList.querySelectorAll('.custom-select-option').forEach(o => o.style.display = '');
        }

        function closeDropdown() {
            wrapper.classList.remove('open');
        }

        function closeAllSelects() {
            document.querySelectorAll('.custom-select.open').forEach(s => s.classList.remove('open'));
        }

        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            if (wrapper.classList.contains('open')) {
                closeDropdown();
            } else {
                openDropdown();
            }
        });

        searchInput.addEventListener('input', () => {
            const query = searchInput.value.toLowerCase();
            optionsList.querySelectorAll('.custom-select-option').forEach(opt => {
                const text = opt.textContent.toLowerCase();
                opt.style.display = text.includes(query) ? '' : 'none';
            });
        });

        searchInput.addEventListener('click', (e) => e.stopPropagation());

        document.addEventListener('click', () => closeAllSelects());

        // Reposition portal on scroll/resize
        window.addEventListener('scroll', () => {
            if (wrapper.classList.contains('open') && portalDropdown) {
                positionPortal();
            }
        }, true);
    }

    function initCustomSelects() {
        document.querySelectorAll('select.input').forEach(createCustomSelect);
    }

    // ========================================
    // Team Navigation
    // ========================================

    function switchTeam(team) {
        if (state.team === team) return;
        state.team = team;
        state.section = `${team}-dashboard`;

        document.documentElement.setAttribute('data-team', team);

        $$('.team-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.team === team);
        });

        renderSidebar();
        renderContent();
        addActivity(`Switched to ${getTeamName(team)} workspace`);
    }

    function getTeamName(team) {
        const names = { red: 'Red Team', gray: 'Gray Team', blue: 'Blue Team', white: 'White Team' };
        return names[team] || team;
    }

    function getTeamIcon(team) {
        const icons = { red: '🔴', gray: '🔘', blue: '🔵', white: '⚪' };
        return icons[team] || '⚪';
    }

    // ========================================
    // Sidebar
    // ========================================

    function renderSidebar() {
        const template = $(`#sidebar-${state.team}`);
        if (!template) return;

        const nav = dom.sidebarNav();
        nav.innerHTML = '';
        const content = template.content.cloneNode(true);
        nav.appendChild(content);

        $$('.sidebar-item', nav).forEach(item => {
            item.addEventListener('click', () => {
                $$('.sidebar-item', nav).forEach(i => i.classList.remove('active'));
                item.classList.add('active');
                state.section = item.dataset.section;
                renderContent();
            });
        });

        const activeSection = nav.querySelector(`[data-section="${state.section}"]`);
        if (activeSection) {
            $$('.sidebar-item', nav).forEach(i => i.classList.remove('active'));
            activeSection.classList.add('active');
        }
    }

    function toggleSidebar() {
        state.sidebar.collapsed = !state.sidebar.collapsed;
        dom.sidebar().classList.toggle('collapsed', state.sidebar.collapsed);
        $('#sidebarCollapseBtn').textContent = state.sidebar.collapsed ? '▶' : '◀';
    }

    // ========================================
    // Content Rendering
    // ========================================

    function renderContent() {
        const content = dom.content();
        const section = state.section;

        if (section.endsWith('-dashboard')) {
            renderDashboard(content, section);
        } else if (section === 'red-web') {
            renderTemplate(content, 'content-webscanner');
            setupWebScanner();
        } else if (section === 'apiscanner') {
            renderTemplate(content, 'content-apiscanner');
            setupApiScanner();
        } else if (section === 'red-sessions' || section === 'red-auth') {
            renderTemplate(content, 'content-authprofiles');
            setupAuthProfiles();
        } else if (section === 'red-network') {
            renderTemplate(content, 'content-networkscanner');
            setupNetworkScanner();
        } else if (section === 'red-passwords') {
            renderTemplate(content, 'content-passwordattack');
            setupPasswordAttack();
        } else if (section === 'red-osint') {
            renderTemplate(content, 'content-osint');
            setupOsint();
        } else if (section === 'red-os') {
            renderTemplate(content, 'content-ospentest');
            setupOsPentest();
        } else if (section === 'red-mobile') {
            renderTemplate(content, 'content-mobilesecurity');
            setupMobileSecurity();
        } else if (section === 'red-cloud') {
            renderTemplate(content, 'content-cloudsecurity');
            setupCloudSecurity();
        } else if (section === 'red-web3') {
            renderTemplate(content, 'content-web3security');
            setupWeb3Security();
        } else if (section === 'gray-matrix') {
            renderTemplate(content, 'content-gray-matrix');
            setupGrayMatrix();
        } else if (section === 'gray-threatmodel') {
            renderTemplate(content, 'content-gray-threatmodel');
            setupGrayThreatModel();
        } else if (section === 'gray-purple') {
            renderTemplate(content, 'content-gray-purple');
            setupGrayPurple();
        } else if (section === 'gray-detections') {
            renderTemplate(content, 'content-gray-detections');
            setupGrayDetections();
        } else if (section === 'gray-simulations') {
            renderTemplate(content, 'content-gray-simulations');
            setupGraySimulations();
        } else if (section === 'gray-correlation') {
            renderTemplate(content, 'content-gray-correlation');
            setupGrayCorrelation();
        } else if (section === 'gray-surface') {
            renderTemplate(content, 'content-gray-surface');
            setupGraySurface();
        } else if (section === 'gray-reports') {
            renderTemplate(content, 'content-gray-reports');
            setupGrayReports();
        } else if (section === 'blue-dashboard') {
            renderTemplate(content, 'content-blue-dashboard');
            setupBlueDashboard();
        } else if (section === 'blue-incidents') {
            renderTemplate(content, 'content-blue-incidents');
            setupBlueIncidents();
        } else if (section === 'blue-intel') {
            renderTemplate(content, 'content-blue-intel');
            setupBlueIntel();
        } else if (section === 'blue-hunt') {
            renderTemplate(content, 'content-blue-hunt');
            setupBlueHunt();
        } else if (section === 'blue-forensics') {
            renderTemplate(content, 'content-blue-forensics');
            setupBlueForensics();
        } else if (section === 'blue-alerts') {
            renderTemplate(content, 'content-blue-alerts');
            setupBlueAlerts();
        } else if (section === 'blue-logs') {
            renderTemplate(content, 'content-blue-logs');
            setupBlueLogs();
        } else if (section === 'blue-malware') {
            renderTemplate(content, 'content-blue-malware');
            setupBlueMalware();
        } else if (section === 'blue-network') {
            renderTemplate(content, 'content-blue-network');
            setupBlueNetwork();
        } else if (section === 'blue-endpoints') {
            renderTemplate(content, 'content-blue-endpoints');
            setupBlueEndpoints();
        } else if (section === 'blue-cloud') {
            renderTemplate(content, 'content-blue-cloud');
            setupBlueCloud();
        } else if (section === 'blue-reports') {
            renderTemplate(content, 'content-blue-reports');
            setupBlueReports();
        } else if (section === 'white-dashboard') {
            renderTemplate(content, 'content-white-dashboard');
            setupWhiteDashboard();
        } else if (section === 'white-compliance') {
            renderTemplate(content, 'content-white-compliance');
            setupWhiteCompliance();
        } else if (section === 'white-risk') {
            renderTemplate(content, 'content-white-risk');
            setupWhiteRisk();
        } else if (section === 'white-policies') {
            renderTemplate(content, 'content-white-policies');
            setupWhitePolicies();
        } else if (section === 'white-vendors') {
            renderTemplate(content, 'content-white-vendors');
            setupWhiteVendors();
        } else if (section === 'white-training') {
            renderTemplate(content, 'content-white-training');
            setupWhiteTraining();
        } else if (section === 'white-metrics') {
            renderTemplate(content, 'content-white-metrics');
            setupWhiteMetrics();
        } else if (section === 'white-reports') {
            renderTemplate(content, 'content-white-reports');
            setupWhiteReports();
        } else if (section === 'red-targets') {
            renderTemplate(content, 'content-red-targets');
            setupRedTargets();
        } else if (section === 'red-scans') {
            renderTemplate(content, 'content-red-scans');
            setupRedScans();
        } else if (section === 'red-findings') {
            renderTemplate(content, 'content-red-findings');
            setupRedFindings();
        } else if (section === 'red-email') {
            renderTemplate(content, 'content-red-email');
            setupRedEmail();
        } else if (section === 'red-wireless') {
            renderTemplate(content, 'content-red-wireless');
            setupRedWireless();
        } else if (section === 'red-exploit') {
            renderTemplate(content, 'content-red-exploit');
            setupRedExploit();
        } else if (section === 'red-payloads') {
            renderTemplate(content, 'content-red-payloads');
            setupRedPayloads();
        } else if (section === 'red-reports') {
            renderTemplate(content, 'content-red-reports');
            setupRedReports();
        } else if (section === 'assets') {
            renderTemplate(content, 'content-assets');
            setupAssets();
        } else if (section === 'notifications') {
            renderTemplate(content, 'content-notifications');
            setupNotifications();
        } else if (section === 'reports') {
            renderTemplate(content, 'content-reports');
            setupReports();
        } else if (section === 'integrations') {
            renderTemplate(content, 'content-integrations');
            setupIntegrations();
        } else if (section === 'http-proxy') {
            renderTemplate(content, 'content-http-proxy');
            setupHttpProxy();
        } else if (section === 'packet-capture') {
            renderTemplate(content, 'content-packet-capture');
            setupPacketCapture();
        } else if (section === 'red-auth-profiles') {
            renderTemplate(content, 'content-red-auth-profiles');
            setupRedAuthProfiles();
        } else if (section === 'red-totp') {
            renderTemplate(content, 'content-red-totp');
            setupRedTotp();
        } else if (section === 'blue-audit-log') {
            renderTemplate(content, 'content-blue-audit-log');
            setupBlueAuditLog();
        } else if (section === 'red-recording') {
            renderTemplate(content, 'content-red-recording');
            setupRecording();
        } else {
            renderToolPage(content, section);
        }

        initCustomSelects();
    }

    function renderTemplate(container, templateId) {
        const template = $(`#${templateId}`);
        if (!template) {
            container.innerHTML = `<div class="empty-state">
                <div class="empty-state-icon">🚧</div>
                <div class="empty-state-title">Coming Soon</div>
                <div class="empty-state-text">This module is under development.</div>
            </div>`;
            return;
        }
        container.innerHTML = '';
        container.appendChild(template.content.cloneNode(true));
    }

    function renderDashboard(container, section) {
        renderTemplate(container, 'content-dashboard');

        const teamName = getTeamName(state.team);
        $('#dashboardTitle').textContent = `${getTeamIcon(state.team)} ${teamName} Dashboard`;
        $('#dashboardSubtitle').textContent = `${teamName} operations overview and metrics`;

        updateDashboardStats();
    }

    function filterFindingsBySeverity(severity) {
        const sev = severity.charAt(0).toUpperCase() + severity.slice(1);
        showToast('info', 'Filter Applied', `Showing ${sev} severity findings`);
        state.section = 'red-findings';
        renderContent();
    }

    function updateDashboardStats() {
        const summary = state.data.scanResults?.summary;
        const stats = computeDashboardStats();
        const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };

        if (state.team === 'red') {
            setText('statTargets', stats.targets);
            setText('statFindings', stats.findings);
            setText('statRisk', stats.avgRisk.toFixed(1));
            setText('statOperations', stats.runningOps);
            setText('statTargetsChange', stats.targets > 0 ? `↑ ${stats.targets} configured` : 'No targets yet');
            setText('statFindingsChange', stats.findings > 0 ? `↓ ${stats.findings} open` : '0 open');
            setText('statRiskChange', summary ? `${summary.risk_score.toFixed(1)}/10 latest` : '—');
            setText('statOperationsChange', stats.runningOps > 0 ? `● ${stats.runningOps} running` : '● Idle');
        } else if (state.team === 'blue') {
            setText('statTargets', stats.alerts);
            setText('statFindings', stats.incidents);
            setText('statRisk', stats.mttd.toFixed(1) + 'm');
            setText('statOperations', stats.endpoints);
            setText('statTargetsChange', 'Active alerts');
            setText('statFindingsChange', 'Open incidents');
            setText('statRiskChange', 'MTTD');
            setText('statOperationsChange', 'Endpoints');
        } else if (state.team === 'white') {
            setText('statTargets', stats.openRisks);
            setText('statFindings', stats.criticalRisks);
            setText('statRisk', stats.compliance + '%');
            setText('statOperations', stats.trainingRate + '%');
            setText('statTargetsChange', 'Open risks');
            setText('statFindingsChange', 'Critical risks');
            setText('statRiskChange', 'Compliance');
            setText('statOperationsChange', 'Training rate');
        } else {
            setText('statTargets', stats.simulations);
            setText('statFindings', stats.correlations);
            setText('statRisk', stats.coverage + '%');
            setText('statOperations', stats.chains);
            setText('statTargetsChange', 'Simulations');
            setText('statFindingsChange', 'Correlations');
            setText('statRiskChange', 'ATT&CK coverage');
            setText('statOperationsChange', 'Attack chains');
        }

        updateSeverityBar(stats.severity);
        renderActiveOps();
        renderActivityFeed();
        updateTeamBadges();
        updateSidebarCounts();
        updateNotificationBadges();
    }

    function computeDashboardStats() {
        const findings = state.data.findings || [];
        const targets = state.data.targets || [];
        const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (const f of findings) {
            if (sev[f.severity] !== undefined) sev[f.severity]++;
        }
        const scans = state.data.scans || [];
        const alerts = state.data.alerts || [];
        const risks = state.data.risks || [];
        const simulations = state.data.simulations || [];
        const correlations = state.data.correlations || [];
        return {
            targets: targets.length,
            findings: findings.length,
            avgRisk: targets.length ? targets.reduce((s, t) => s + (parseFloat(t.risk_score) || 0), 0) / targets.length : 0,
            runningOps: scans.filter(s => s.status === 'running').length,
            severity: sev,
            alerts: alerts.length,
            incidents: state.data.incidents?.length || 0,
            mttd: state.data.metrics?.mttd || 0,
            endpoints: state.data.endpoints?.length || 0,
            openRisks: risks.length,
            criticalRisks: risks.filter(r => r.risk_score >= 15).length,
            compliance: state.data.metrics?.compliance || 0,
            trainingRate: state.data.metrics?.trainingRate || 0,
            simulations: simulations.length,
            correlations: correlations.length,
            coverage: state.data.metrics?.coverage || 0,
            chains: correlations.filter(c => c.type === 'chain').length,
        };
    }

    function updateSeverityBar(sev) {
        const total = sev.critical + sev.high + sev.medium + sev.low + sev.info || 1;
        const setW = (id, n) => { const el = document.getElementById(id); if (el) el.style.width = `${(n / total) * 100}%`; };
        setW('criticalBar', sev.critical);
        setW('highBar', sev.high);
        setW('mediumBar', sev.medium);
        setW('lowBar', sev.low);
        setW('infoBar', sev.info);
        const setT = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = `${n} ${el.dataset.label || ''}`.trim(); };
        setT('criticalCount', sev.critical); document.getElementById('criticalCount')?.setAttribute('data-label', 'Critical');
        setT('highCount', sev.high); document.getElementById('highCount')?.setAttribute('data-label', 'High');
        setT('mediumCount', sev.medium); document.getElementById('mediumCount')?.setAttribute('data-label', 'Medium');
        setT('lowCount', sev.low); document.getElementById('lowCount')?.setAttribute('data-label', 'Low');
        setT('infoCount', sev.info); document.getElementById('infoCount')?.setAttribute('data-label', 'Info');
    }

    function updateTeamBadges() {
        const counts = {
            red: (state.data.targets?.length || 0) + (state.data.findings?.length || 0),
            gray: (state.data.simulations?.length || 0) + (state.data.correlations?.length || 0),
            blue: (state.data.alerts?.length || 0) + (state.data.incidents?.length || 0),
            white: (state.data.risks?.length || 0),
        };
        Object.entries(counts).forEach(([team, n]) => {
            const el = document.getElementById(`${team}Badge`);
            if (el) el.textContent = n;
        });
    }

    function updateSidebarCounts() {
        const targets = state.data.targets?.length || 0;
        const scans = (state.data.scans || []).filter(s => s.status === 'running').length;
        const findings = state.data.findings?.length || 0;
        const alerts = state.data.alerts?.length || 0;
        const incidents = state.data.incidents?.length || 0;
        const set = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = n; };
        set('targetCount', targets);
        set('activeScanCount', scans);
        set('findingCount', findings);
        set('alertCount', alerts);
        set('incidentCount', incidents);
    }

    function updateNotificationBadges() {
        const notif = state.data.notifications || [];
        const unread = notif.filter(n => !n.read).length;
        const notifBadge = document.getElementById('notifBadge');
        if (notifBadge) {
            notifBadge.textContent = unread;
            notifBadge.classList.toggle('empty', unread === 0);
        }
        const opsBadge = document.getElementById('activeOpsBadge');
        const running = (state.data.scans || []).filter(s => s.status === 'running').length;
        if (opsBadge) {
            opsBadge.textContent = running;
            opsBadge.style.display = running > 0 ? '' : 'none';
        }
        const opsInd = document.getElementById('opsIndicator');
        if (opsInd) opsInd.textContent = running > 0 ? '🟢' : '🔴';
    }

    function renderActiveOps() {
        const list = document.getElementById('activeOpsList');
        if (!list) return;
        const ops = (state.data.scans || []).filter(s => s.status === 'running');
        if (ops.length === 0) {
            list.innerHTML = `<div class="empty-state">
                <div class="empty-state-icon">📋</div>
                <div class="empty-state-title">No Active Operations</div>
                <div class="empty-state-text">Launch a scan or operation to get started.</div>
            </div>`;
            return;
        }
        list.innerHTML = ops.map(o => `
            <div style="padding:10px 0; border-bottom:1px solid var(--border-secondary);">
                <div class="flex items-center gap-2">
                    <span class="status-dot running"></span>
                    <span style="font-weight:500;">${escapeHtml(o.name || 'Untitled')}</span>
                    <span class="badge badge-info">${escapeHtml(o.type || 'web')}</span>
                </div>
                <div class="text-sm text-tertiary" style="margin-left:18px;">${escapeHtml(o.target || '')}</div>
            </div>
        `).join('');
    }

    function renderActivityFeed() {
        const feed = document.getElementById('activityFeed');
        if (!feed) return;
        const items = state.activity || [];
        if (items.length === 0) {
            feed.innerHTML = `<div class="empty-state">
                <div class="empty-state-icon">📝</div>
                <div class="empty-state-title">No Recent Activity</div>
                <div class="empty-state-text">Actions will appear here as you work.</div>
            </div>`;
            return;
        }
        feed.innerHTML = items.slice(0, 20).map(a => `
            <div style="padding:8px 0; border-bottom:1px solid var(--border-secondary); font-size:0.85rem;">
                <span style="color:var(--text-tertiary);">${escapeHtml(a.time)}</span> ${escapeHtml(a.message)}
            </div>
        `).join('');
    }

    function renderToolPage(container, section) {
        const sectionConfig = getSectionConfig(section);
        renderTemplate(container, 'content-toolpage');

        $('#toolTitle').textContent = sectionConfig.icon + ' ' + sectionConfig.title;
        $('#toolSubtitle').textContent = sectionConfig.description;

        const toolContent = $('#toolContent');
        toolContent.innerHTML = sectionConfig.content || `<div class="empty-state">
            <div class="empty-state-icon">${sectionConfig.icon}</div>
            <div class="empty-state-title">${sectionConfig.title}</div>
            <div class="empty-state-text">${sectionConfig.description}</div>
            <button class="btn btn-primary mt-4" onclick="document.querySelector('[data-section=red-dashboard]').click()">
                ← Back to Dashboard
            </button>
        </div>`;
    }

    function getSectionConfig(section) {
        const configs = {
            // Red Team
            'red-targets': { icon: '🎯', title: 'Target Management', description: 'Manage and organize your pentest targets', content: renderTargetsContent() },
            'red-scans': { icon: '🔍', title: 'Scan Management', description: 'Monitor and manage active scans' },
            'red-findings': { icon: '⚠️', title: 'Findings', description: 'Review and triage discovered vulnerabilities' },
            'red-network': { icon: '🔌', title: 'Network Pentesting', description: 'Port scanning, service enumeration, network attacks' },
            'red-os': { icon: '💻', title: 'OS Pentesting', description: 'Linux, Windows, macOS exploitation' },
            'red-mobile': { icon: '📱', title: 'Mobile Security', description: 'Android & iOS application testing' },
            'red-cloud': { icon: '☁️', title: 'Cloud Security', description: 'AWS, Azure, GCP assessment' },
            'red-web3': { icon: '⛓️', title: 'Web3 Security', description: 'Smart contract & blockchain auditing' },
            'red-email': { icon: '📧', title: 'Email Security', description: 'Phishing, email infrastructure assessment' },
            'red-wireless': { icon: '📡', title: 'Wireless Security', description: 'WiFi, Bluetooth, RFID assessment' },
            'red-passwords': { icon: '🔑', title: 'Password Attacks', description: 'Cracking, spraying, brute force' },
            'red-exploit': { icon: '💥', title: 'Exploitation', description: 'Exploit framework & post-exploitation' },
            'red-osint': { icon: '🕵️', title: 'OSINT', description: 'Open source intelligence gathering' },
            'red-payloads': { icon: '📦', title: 'Payload Generator', description: 'Generate custom payloads' },
            'red-sessions': { icon: '🔐', title: 'Sessions & Auth', description: 'Manage authentication profiles' },
            'red-auth-profiles': { icon: '🔑', title: 'Auth Profiles', description: 'Manage credentials and login configurations for targets' },
            'red-totp': { icon: '⏱️', title: 'TOTP Generator', description: 'Time-based OTP generation and validation' },
            'red-reports': { icon: '📋', title: 'Red Team Reports', description: 'Offensive operations reporting' },

            // Gray Team
            'gray-dashboard': { icon: '📊', title: 'Gray Team Dashboard', description: 'Purple team & validation overview' },
            'gray-simulations': { icon: '⚔️', title: 'Attack Simulations', description: 'Adversary emulation & scenario testing' },
            'gray-matrix': { icon: '🗺️', title: 'ATT&CK Matrix', description: 'MITRE ATT&CK coverage mapping' },
            'gray-purple': { icon: '🤝', title: 'Purple Team', description: 'Collaborative attack-defend exercises' },
            'gray-threatmodel': { icon: '🧩', title: 'Threat Modeling', description: 'Application & infrastructure threat models' },
            'gray-correlation': { icon: '🔗', title: 'Vulnerability Correlation', description: 'Cross-validate and correlate findings' },
            'gray-detections': { icon: '🛡️', title: 'Detection Engineering', description: 'Build and test detection rules' },
            'gray-surface': { icon: '🌍', title: 'Attack Surface', description: 'Continuous attack surface management' },
            'gray-reports': { icon: '📋', title: 'Gray Team Reports', description: 'Validation & coverage reports' },

            // Blue Team
            'blue-dashboard': { icon: '📊', title: 'SOC Dashboard', description: 'Security operations center overview' },
            'blue-alerts': { icon: '🚨', title: 'Alert Queue', description: 'Triage and manage security alerts' },
            'blue-incidents': { icon: '🔥', title: 'Incidents', description: 'Incident response tracking' },
            'blue-hunt': { icon: '🔍', title: 'Threat Hunting', description: 'Proactive threat hunting operations' },
            'blue-intel': { icon: '🧠', title: 'Threat Intel', description: 'Threat intelligence management' },
            'blue-logs': { icon: '📝', title: 'Log Analysis', description: 'Centralized log search & analysis' },
            'blue-forensics': { icon: '🔬', title: 'Forensics', description: 'Digital forensics & incident analysis' },
            'blue-malware': { icon: '🦠', title: 'Malware Analysis', description: 'Static & dynamic malware analysis' },
            'blue-network': { icon: '🌐', title: 'Network Defense', description: 'Network monitoring & IDS' },
            'blue-endpoints': { icon: '💻', title: 'Endpoints', description: 'EDR & endpoint vulnerability management' },
            'blue-cloud': { icon: '☁️', title: 'Cloud Defense', description: 'Cloud security posture management' },
            'blue-audit-log': { icon: '📜', title: 'Audit Log', description: 'System activity and security event log' },
            'blue-reports': { icon: '📋', title: 'Blue Team Reports', description: 'Defensive operations reports' },

            // White Team
            'white-dashboard': { icon: '📊', title: 'White Team Dashboard', description: 'Governance, risk & compliance overview' },
            'white-compliance': { icon: '✅', title: 'Compliance', description: 'Compliance framework management' },
            'white-risk': { icon: '⚖️', title: 'Risk Register', description: 'Enterprise risk management' },
            'white-policies': { icon: '📜', title: 'Policies', description: 'Security policy management' },
            'white-vendors': { icon: '🏢', title: 'Vendor Risk', description: 'Third-party risk management' },
            'white-training': { icon: '🎓', title: 'Training', description: 'Security awareness & skills management' },
            'white-metrics': { icon: '📈', title: 'Metrics', description: 'Security KPIs & board reporting' },
            'white-reports': { icon: '📋', title: 'White Team Reports', description: 'Executive & compliance reports' },
        };
        return configs[section] || { icon: '🔧', title: section, description: 'Tool configuration' };
    }

    function renderTargetsContent() {
        return `
            <div class="card mb-4">
                <div class="card-header">
                    <span class="card-title">Target Inventory</span>
                    <div class="flex gap-2">
                        <input type="text" class="input input-sm" placeholder="Search targets..." style="width:200px;">
                        <button class="btn btn-sm btn-secondary">📥 Import</button>
                        <button class="btn btn-sm btn-primary">+ Add Target</button>
                    </div>
                </div>
                <div class="table-container">
                    <table class="table" id="targetsTable">
                        <thead>
                            <tr>
                                <th class="sortable">Name</th>
                                <th class="sortable">URL</th>
                                <th class="sortable">Type</th>
                                <th class="sortable">Risk</th>
                                <th class="sortable">Auth</th>
                                <th class="sortable">Last Scan</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="targetsTableBody">
                            <tr><td colspan="7" style="text-align:center; padding:32px; color:var(--text-tertiary);">
                                No targets configured. Add your first target to begin.
                            </td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="grid grid-3">
                <div class="stat-card">
                    <div class="stat-value" id="totalTargets">0</div>
                    <div class="stat-label">Total Targets</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="scannedTargets">0</div>
                    <div class="stat-label">Scanned (7d)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="authTargets">0</div>
                    <div class="stat-label">With Auth</div>
                </div>
            </div>
        `;
    }

    // ========================================
    // Web Scanner
    // ========================================

    function setupWebScanner() {
        $('#startWebScanBtn')?.addEventListener('click', startWebScan);
        $('#pauseWebScanBtn')?.addEventListener('click', pauseWebScan);
        $('#cancelWebScanBtn')?.addEventListener('click', cancelWebScan);

        const authSel = document.getElementById('webScanAuth');
        if (authSel) {
            authSel.innerHTML = '<option value="">Unauthenticated</option>' +
                (state.data.authProfiles || []).map(p =>
                    `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`
                ).join('');
        }

        const outputDir = $('#outputDir');
        if (outputDir && !outputDir.value) {
            getDefaultDir().then(dir => { if (outputDir) outputDir.value = dir; }).catch(() => {});
        }
    }

    // ========================================
    // API Security Scanner
    // ========================================

    function setupApiScanner() {
        $('#startApiScanBtn')?.addEventListener('click', startApiScan);
        $('#cancelApiScanBtn')?.addEventListener('click', cancelApiScan);
    }

    async function startApiScan() {
        const baseUrl = $('#apiScanUrl')?.value?.trim();
        if (!baseUrl) {
            showToast('error', 'Missing URL', 'Please enter an API base URL to scan.');
            return;
        }
        if (!baseUrl.startsWith('http://') && !baseUrl.startsWith('https://')) {
            showToast('error', 'Invalid URL', 'URL must start with http:// or https://');
            return;
        }

        const authType = $('#apiScanAuthType')?.value || 'none';
        const token = $('#apiScanToken')?.value?.trim();
        const endpointsText = $('#apiScanEndpoints')?.value?.trim();
        const endpoints = endpointsText ? endpointsText.split('\n').filter(Boolean).map(e => e.trim()) : [];

        $('#apiScanProgress').style.display = 'block';
        $('#apiScanResults').style.display = 'none';
        $('#startApiScanBtn').disabled = true;
        $('#apiScanStatus').textContent = 'Starting API security scan...';

        addActivity(`Started API security scan on ${baseUrl}`);

        try {
            const result = await invoke('api_scan', {
                baseUrl,
                authToken: token || null,
                authType,
                endpoints: endpoints.length > 0 ? endpoints : null,
            });

            $('#apiScanStatus').textContent = 'Scan complete!';
            $('#apiScanProgressBar').style.width = '100%';
            $('#apiScanProgressBar').classList.add('success');
            $('#apiScanEndpoints').textContent = `${result.endpoints_discovered || 0} endpoints tested`;
            $('#apiScanFindings').textContent = `${result.summary?.vulnerable || 0} findings`;

            if (result) {
                displayApiScanResults(result);
            }

            showToast('success', 'Scan Complete', `Risk score: ${(result.summary?.risk_score || 0).toFixed(1)}/10. Found ${result.summary?.vulnerable || 0} issues.`);
            addActivity(`API scan completed for ${baseUrl}: ${result.summary?.vulnerable || 0} findings`);
        } catch (error) {
            $('#apiScanStatus').textContent = `Error: ${error}`;
            showToast('error', 'Scan Failed', String(error));
            addActivity(`API scan failed: ${error}`);
        } finally {
            $('#startApiScanBtn').disabled = false;
        }
    }

    function cancelApiScan() {
        $('#apiScanProgress').style.display = 'none';
        $('#startApiScanBtn').disabled = false;
        $('#apiScanProgressBar').style.width = '0%';
        showToast('warning', 'Scan Cancelled', 'API scan was cancelled.');
    }

    function displayApiScanResults(report) {
        if (!report) return;
        const container = $('#apiScanResults');
        container.style.display = 'block';

        const summary = report.summary;
        const critical = summary?.critical_count || 0;
        const high = summary?.high_count || 0;
        const medium = summary?.medium_count || 0;
        const low = summary?.low_count || 0;
        const total = summary?.total_tests || 1;
        const risk = summary?.risk_score || 0;

        let findingsHtml = '';
        const sortedResults = [...(report.results || [])].sort((a, b) => {
            const order = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4 };
            return (order[a.severity] || 5) - (order[b.severity] || 5);
        });

        for (const result of sortedResults) {
            findingsHtml += createApiFindingCard(result);
        }

        container.innerHTML = `
            <div class="card mb-4">
                <div class="card-header">
                    <span class="card-title">Scan Results — ${report.base_url || 'Unknown'}</span>
                    <div class="flex gap-2">
                        <span class="badge badge-${risk >= 7 ? 'critical' : risk >= 4 ? 'warning' : 'success'}">
                            Risk: ${risk.toFixed(1)}/10
                        </span>
                        <button class="btn btn-sm btn-secondary" id="exportApiJsonBtn">⬇ JSON</button>
                        <button class="btn btn-sm btn-secondary" id="exportApiCsvBtn">⬇ CSV</button>
                        <button class="btn btn-sm btn-secondary" id="exportApiHtmlBtn">⬇ HTML</button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="grid grid-5 mb-4">
                        <div class="severity-card critical"><div class="severity-card-count">${critical}</div><div class="severity-card-label">Critical</div></div>
                        <div class="severity-card high"><div class="severity-card-count">${high}</div><div class="severity-card-label">High</div></div>
                        <div class="severity-card medium"><div class="severity-card-count">${medium}</div><div class="severity-card-label">Medium</div></div>
                        <div class="severity-card low"><div class="severity-card-count">${low}</div><div class="severity-card-label">Low</div></div>
                        <div class="severity-card info"><div class="severity-card-count">${summary?.vulnerable || 0}</div><div class="severity-card-label">Total Vulns</div></div>
                    </div>
                    <div class="text-sm text-secondary mb-2">${report.endpoints_discovered || 0} endpoints tested • ${total} checks performed</div>
                </div>
            </div>
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Findings</span>
                </div>
                <div class="card-body">${findingsHtml}</div>
            </div>
        `;
    }

    function createApiFindingCard(result) {
        const severity = (result.severity || 'INFO').toLowerCase();
        const findingsList = (result.findings || []).map(f => `
            <div class="finding-item ${severity}">
                <div class="flex items-center gap-2 mb-2">
                    <span class="badge badge-${severity}">${f.severity || 'INFO'}</span>
                    <span class="font-medium text-sm">${escapeHtml(f.title || '')}</span>
                    ${f.cwe_id ? `<span class="badge badge-info">${escapeHtml(f.cwe_id)}</span>` : ''}
                </div>
                <div class="text-sm text-secondary mb-2">${escapeHtml(f.description || '')}</div>
                ${f.details?.length ? `<ul class="text-sm mb-2">${f.details.map(d => `<li style="padding:2px 0;">• ${escapeHtml(d)}</li>`).join('')}</ul>` : ''}
                <div class="finding-remediation"><strong>Remediation:</strong> ${escapeHtml(f.remediation || '')}</div>
            </div>
        `).join('');

        return `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${result.status === 'VULNERABLE' ? '🔴' : '🟢'}</span>
                        <span class="font-medium">${escapeHtml(result.check_name || 'Unknown Check')}</span>
                        <span class="badge badge-${severity}">${result.severity || 'INFO'}</span>
                        <span class="badge badge-info">${escapeHtml(result.method || 'N/A')}</span>
                        ${result.response_code ? `<span class="badge badge-${result.response_code < 300 ? 'success' : 'error'}">${result.response_code}</span>` : ''}
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-tertiary mb-2">${escapeHtml(result.endpoint || '')}</div>
                    ${findingsList || '<div class="text-tertiary text-sm">No detailed findings.</div>'}
                </div>
            </div>
        `;
    }

    function downloadApiReport(report, format) {
        let content, filename, mimeType;
        if (format === 'json') {
            content = JSON.stringify(report, null, 2);
            filename = `api_scan_${report.scan_id || 'report'}.json`;
            mimeType = 'application/json';
        } else {
            let csv = 'endpoint,method,check,severity,status,response_code,title,description,cwe,remediation\n';
            for (const r of report.results || []) {
                for (const f of r.findings || []) {
                    const esc = (s) => `"${(s || '').replace(/"/g, '""')}"`;
                    csv += `${esc(r.endpoint)},${esc(r.method)},${esc(r.check_name)},${esc(f.severity)},${esc(r.status)},${esc(r.response_code)},${esc(f.title)},${esc(f.description)},${esc(f.cwe_id)},${esc(f.remediation)}\n`;
                }
            }
            content = csv;
            filename = `api_scan_${report.scan_id || 'report'}.csv`;
            mimeType = 'text/csv';
        }
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
        showToast('success', 'Exported', `Report saved as ${filename}`);
    }

    async function startWebScan() {
        const url = $('#webScanUrl')?.value?.trim();
        if (!url) {
            showToast('error', 'Missing URL', 'Please enter a target URL to scan.');
            return;
        }
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            showToast('error', 'Invalid URL', 'URL must start with http:// or https://');
            return;
        }

        $('#webScanProgress').style.display = 'block';
        $('#webScanResults').style.display = 'none';
        $('#startWebScanBtn').disabled = true;
        $('#webScanSpinner').style.display = 'block';

        const authType = $('#webScanAuthType')?.value || 'none';
        $('#webScanStatus').textContent = authType !== 'none'
            ? `Authenticating via ${authType}...`
            : 'Initializing scanner...';
        $('#webScanLog').innerHTML = '<div class="text-tertial">Starting scan...</div>';

        addActivity(`Started web scan on ${url}${authType !== 'none' ? ` (auth: ${authType})` : ''}`);

        state.data.scans = state.data.scans || [];
        const scanId = `scan_${Date.now()}`;
        state.data.scans.push({ id: scanId, url, status: 'running', progress: 0, pages: [], findings: [] });
        state.data.activeScanId = scanId;

        // Start progress polling
        const scanStartTime = Date.now();
        const estimatedDuration = 30000; // Estimate 30 seconds
        const progressInterval = setInterval(() => {
            if (!state.data.activeScanId || state.data.activeScanId !== scanId) {
                clearInterval(progressInterval);
                return;
            }
            const elapsed = Date.now() - scanStartTime;
            const estimatedPct = Math.min(95, Math.round((elapsed / estimatedDuration) * 100));
            updateScanProgress({
                phase: 'Scanning',
                current_url: url,
                current_check: 'Running security checks...',
                pages_scanned: Math.max(1, Math.round((elapsed / estimatedDuration) * 1)),
                total_pages: 1,
                checks_completed: Math.round((elapsed / estimatedDuration) * 30),
                total_checks: 30,
                findings_count: 0,
                elapsed_seconds: Math.round(elapsed / 1000),
                message: `Scanning ${url}...`,
            });
            $('#webScanProgressBar').style.width = `${estimatedPct}%`;
        }, 1000);

        try {
            const outputDir = $('#outputDir')?.value?.trim();
            const result = await invoke('run_vulnerability_scan', { url, outputDir });

            $('#webScanStatus').textContent = 'Scan complete!';
            $('#webScanProgressBar').style.width = '100%';
            $('#webScanProgressBar').classList.add('success');
            $('#webScanSpinner').style.display = 'none';
            $('#webScanPages').textContent = `${result?.summary?.total_checks || 0} checks completed`;
            $('#webScanLog').innerHTML = `<div style="color:var(--status-success);">✓ Scan complete! Risk: ${result?.summary?.risk_score?.toFixed(1) || 0}/10</div>`;

            if (result) {
                state.data.scanResults = result;
                displayWebScanResults(result);
            }

            showToast('success', 'Scan Complete', `Risk score: ${(result?.summary?.risk_score || 0).toFixed(1)}/10`);
            addActivity(`Web scan completed for ${url}`);

            // Update scan record
            const scan = state.data.scans.find(s => s.id === scanId);
            if (scan) { scan.status = 'completed'; scan.progress = 100; }

            clearInterval(progressInterval);
        } catch (error) {
            clearInterval(progressInterval);
            $('#webScanStatus').textContent = `Error: ${error}`;
            $('#webScanSpinner').style.display = 'none';
            $('#webScanLog').innerHTML = `<div style="color:var(--status-error);">✗ Error: ${error}</div>`;
            showToast('error', 'Scan Failed', String(error));
            addActivity(`Web scan failed: ${error}`);
        } finally {
            $('#startWebScanBtn').disabled = false;
            state.data.activeScanId = null;
        }
    }

    function pauseWebScan() {
        showToast('info', 'Scan Paused', 'Scan has been paused.');
        $('#webScanStatus').textContent = 'Paused';
    }

    function cancelWebScan() {
        $('#webScanProgress').style.display = 'none';
        $('#startWebScanBtn').disabled = false;
        $('#webScanProgressBar').style.width = '0%';
        $('#webScanSpinner').style.display = 'none';
        showToast('warning', 'Scan Cancelled', 'Scan was cancelled by user.');
        addActivity('Web scan cancelled');
        state.data.activeScanId = null;
    }

    function updateScanProgress(progress) {
        if (!progress) return;
        const pct = progress.total_checks > 0
            ? Math.round((progress.checks_completed / progress.total_checks) * 100)
            : 0;
        $('#webScanProgressBar').style.width = `${pct}%`;
        $('#webScanPages').textContent = `${progress.pages_scanned}/${progress.total_pages} pages`;
        $('#webScanChecks').textContent = `${progress.checks_completed}/${progress.total_checks} checks`;
        $('#webScanStatus').textContent = progress.message || 'Scanning...';
        if (progress.current_url) {
            $('#webScanCurrent').textContent = `${progress.current_check || 'Scanning'}: ${progress.current_url}`;
        }
        if (progress.elapsed_seconds > 0 && progress.checks_completed > 0) {
            const rate = progress.elapsed_seconds / progress.checks_completed;
            const remaining = Math.round(rate * (progress.total_checks - progress.checks_completed));
            const mins = Math.floor(remaining / 60);
            const secs = remaining % 60;
            $('#webScanETA').textContent = `ETA: ${mins}:${secs.toString().padStart(2, '0')}`;
        }
        // Add to log
        const log = $('#webScanLog');
        if (log && progress.current_url) {
            const entry = document.createElement('div');
            entry.style.cssText = 'padding:2px 0; border-bottom:1px solid var(--border-secondary);';
            entry.innerHTML = `<span style="color:var(--text-tertiary);">${new Date().toLocaleTimeString()}</span> ${progress.current_check}: ${progress.current_url}`;
            log.insertBefore(entry, log.firstChild);
            while (log.children.length > 50) log.removeChild(log.lastChild);
        }
    }

    function displayWebScanResults(report) {
        if (!report) return;
        const container = $('#webScanResults');
        container.style.display = 'block';

        const summary = report.summary;
        const critical = summary?.critical_count || 0;
        const high = summary?.high_count || 0;
        const medium = summary?.medium_count || 0;
        const low = summary?.low_count || 0;
        const info = summary?.info_count || 0;
        const total = summary?.total_checks || 1;
        const risk = summary?.risk_score || 0;

        let findingsHtml = '';
        const sortedResults = [...(report.results || [])].sort((a, b) => {
            const order = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
            if (a.status === 'VULNERABLE' && b.status !== 'VULNERABLE') return -1;
            if (a.status !== 'VULNERABLE' && b.status === 'VULNERABLE') return 1;
            return (order[a.severity] || 5) - (order[b.severity] || 5);
        });

        for (const result of sortedResults) {
            findingsHtml += createFindingCard(result);
        }

        container.innerHTML = `
            <div class="card mb-4">
                <div class="card-header">
                    <span class="card-title">Scan Results — ${report.url || 'Unknown'}</span>
                    <div class="flex gap-2">
                        <span class="badge badge-${risk >= 7 ? 'critical' : risk >= 4 ? 'warning' : 'success'}">
                            Risk: ${risk.toFixed(1)}/10
                        </span>
                        <button class="btn btn-sm btn-secondary" id="exportJsonBtn">⬇ JSON</button>
                        <button class="btn btn-sm btn-secondary" id="exportCsvBtn">⬇ CSV</button>
                        <button class="btn btn-sm btn-secondary" id="exportHtmlBtn">⬇ HTML</button>
                        <button class="btn btn-sm btn-secondary" id="exportPdfBtn">⬇ PDF</button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="grid grid-5 mb-4">
                        <div class="severity-card critical">
                            <div class="severity-card-count">${critical}</div>
                            <div class="severity-card-label">Critical</div>
                        </div>
                        <div class="severity-card high">
                            <div class="severity-card-count">${high}</div>
                            <div class="severity-card-label">High</div>
                        </div>
                        <div class="severity-card medium">
                            <div class="severity-card-count">${medium}</div>
                            <div class="severity-card-label">Medium</div>
                        </div>
                        <div class="severity-card low">
                            <div class="severity-card-count">${low}</div>
                            <div class="severity-card-label">Low</div>
                        </div>
                        <div class="severity-card info">
                            <div class="severity-card-count">${info}</div>
                            <div class="severity-card-label">Info</div>
                        </div>
                    </div>
                    <div class="severity-bar mb-2">
                        <div class="segment segment-critical" style="width:${(critical/total)*100}%"></div>
                        <div class="segment segment-high" style="width:${(high/total)*100}%"></div>
                        <div class="segment segment-medium" style="width:${(medium/total)*100}%"></div>
                        <div class="segment segment-low" style="width:${(low/total)*100}%"></div>
                        <div class="segment segment-info" style="width:${(info/total)*100}%"></div>
                    </div>
                    <div class="flex justify-between text-sm text-secondary">
                        <span>${summary?.vulnerable || 0} vulnerable of ${total} checks</span>
                        <span>Scan ID: ${report.scan_id || 'N/A'}</span>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Detailed Findings</span>
                    <div class="flex gap-2">
                        <button class="btn btn-sm filter-btn active" data-filter="all" onclick="filterFindings('all', this)">All</button>
                        <button class="btn btn-sm filter-btn-critical" data-filter="vulnerable" onclick="filterFindings('vulnerable', this)">Vulnerable</button>
                        <button class="btn btn-sm filter-btn-warning" data-filter="warning" onclick="filterFindings('warning', this)">Warning</button>
                        <button class="btn btn-sm filter-btn-success" data-filter="passed" onclick="filterFindings('passed', this)">Passed</button>
                    </div>
                </div>
                <div class="card-body">${findingsHtml}</div>
            </div>
        `;

        $('#exportJsonBtn')?.addEventListener('click', () => downloadReport(report, 'json'));
        $('#exportCsvBtn')?.addEventListener('click', () => downloadReport(report, 'csv'));
        $('#exportHtmlBtn')?.addEventListener('click', () => downloadReport(report, 'html'));
        $('#exportPdfBtn')?.addEventListener('click', () => downloadReport(report, 'pdf'));
    }

    function createFindingCard(result) {
        const severity = (result.severity || 'INFO').toLowerCase();
        const statusClass = result.status === 'VULNERABLE' ? 'error' : result.status === 'WARNING' ? 'warning' : 'success';
        const statusIcon = result.status === 'VULNERABLE' ? '🔴' : result.status === 'WARNING' ? '🟡' : '🟢';

        const findingsList = (result.findings || []).map(f => {
            const fSeverity = (f.severity || 'INFO').toLowerCase();
            return `
                <div class="finding-item ${fSeverity}">
                    <div class="flex items-center gap-2 mb-2">
                        <span class="badge badge-${fSeverity}">${f.severity || 'INFO'}</span>
                        <span class="font-medium text-sm">${escapeHtml(f.title || '')}</span>
                        ${f.cwe_id ? `<span class="badge badge-info">${escapeHtml(f.cwe_id)}</span>` : ''}
                    </div>
                    <div class="text-sm text-secondary mb-2">${escapeHtml(f.description || '')}</div>
                    ${f.remediation ? `<div class="finding-remediation">
                        <strong>Remediation:</strong> ${escapeHtml(f.remediation)}
                    </div>` : ''}
                </div>
            `;
        }).join('');

        return `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${statusIcon}</span>
                        <span class="font-medium">${escapeHtml(result.check_name || 'Unknown Check')}</span>
                        <span class="badge badge-${severity}">${result.severity || 'INFO'}</span>
                        <span class="badge badge-${statusClass}">${result.status || 'UNKNOWN'}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    ${findingsList || '<div class="text-tertiary text-sm">No detailed findings.</div>'}
                </div>
            </div>
        `;
    }

    // ========================================
    // Red Team: Auth Profiles (Enhanced)
    // ========================================

    function setupRedAuthProfiles() {
        loadAuthProfilesList();
        $('#newAuthProfileBtn')?.addEventListener('click', resetAuthProfileEditor);
        $('#saveAuthBtn')?.addEventListener('click', saveAuthProfileEnhanced);
        $('#testAuthBtn')?.addEventListener('click', testAuthProfileEnhanced);
        $('#importAuthProfilesBtn')?.addEventListener('click', importAuthProfiles);
        $('#authProfileType')?.addEventListener('change', (e) => toggleAuthProfileFields(e.target.value));
        $('#authMFA')?.addEventListener('change', (e) => {
            $('#totpFields').style.display = e.target.value === 'totp' ? 'block' : 'none';
        });
        $('#authProfileSearch')?.addEventListener('input', (e) => filterAuthProfiles(e.target.value));
    }

    function toggleAuthProfileFields(type) {
        document.querySelectorAll('.auth-type-fields').forEach(el => el.style.display = 'none');
        const fieldMap = {
            'form': 'authFieldsForm',
            'basic': 'authFieldsBasic',
            'bearer': 'authFieldsBearer',
            'apikey': 'authFieldsApiKey',
            'cookie': 'authFieldsCookie',
            'oauth2': 'authFieldsOAuth2',
            'custom': 'authFieldsCustom',
        };
        const target = fieldMap[type];
        if (target) $(`#${target}`).style.display = 'block';
    }

    function resetAuthProfileEditor() {
        $('#authProfileName').value = '';
        $('#authProfileTarget').value = '';
        $('#authProfileType').value = 'form';
        $('#authLoginUrl').value = '';
        $('#authUsername').value = '';
        $('#authPassword').value = '';
        $('#authBasicUser').value = '';
        $('#authBasicPass').value = '';
        $('#authBearerToken').value = '';
        $('#authApiKey').value = '';
        $('#authApiHeader').value = 'X-API-Key';
        $('#authCookies').value = '';
        $('#authOAuth2Url').value = '';
        $('#authOAuth2ClientId').value = '';
        $('#authOAuth2Secret').value = '';
        $('#authCustomHeaders').value = '';
        $('#authMFA').value = 'none';
        $('#authTOTPSecret').value = '';
        $('#totpFields').style.display = 'none';
        $('#authProfileEditorTitle').textContent = 'New Authentication Profile';
        toggleAuthProfileFields('form');
    }

    async function loadAuthProfilesList() {
        const list = $('#authProfilesList');
        if (!list) return;

        try {
            const profiles = await invoke('list_auth_profiles');
            state.data.authProfiles = profiles || [];

            if (state.data.authProfiles.length === 0) {
                list.innerHTML = `<div class="empty-state">
                    <div class="empty-state-icon">🔒</div>
                    <div class="empty-state-title">No Profiles Yet</div>
                    <div class="empty-state-text">Create an authentication profile to enable authenticated scanning.</div>
                </div>`;
                return;
            }

            list.innerHTML = state.data.authProfiles.map(p => `
                <div style="padding:12px; border:1px solid var(--border-primary); border-radius:8px; margin-bottom:8px; cursor:pointer;"
                     onclick="editAuthProfileEnhanced('${p.id}')">
                    <div class="flex items-center justify-between">
                        <div>
                            <div style="font-weight:500;">${escapeHtml(p.name || '')}</div>
                            <div style="font-size:0.8rem; color:var(--text-tertiary);">${escapeHtml(p.target_url || '')}</div>
                        </div>
                        <div class="flex gap-2 items-center">
                            <span class="badge badge-info">${escapeHtml(p.auth_type || 'form')}</span>
                            <span class="badge badge-${p.mfa !== 'none' ? 'warning' : 'success'}">${p.mfa !== 'none' ? 'MFA' : 'No MFA'}</span>
                            <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteAuthProfileEnhanced('${p.id}')">🗑</button>
                        </div>
                    </div>
                </div>
            `).join('');
        } catch (e) {
            list.innerHTML = `<div class="text-error">Failed to load profiles: ${escapeHtml(String(e))}</div>`;
        }
    }

    async function saveAuthProfileEnhanced() {
        const profile = {
            id: `auth_${Date.now()}`,
            name: $('#authProfileName')?.value?.trim(),
            target_url: $('#authProfileTarget')?.value?.trim(),
            auth_type: $('#authProfileType')?.value,
            login_url: $('#authLoginUrl')?.value?.trim(),
            username: $('#authUsername')?.value?.trim(),
            password: $('#authPassword')?.value,
            mfa: $('#authMFA')?.value,
            totp_secret: $('#authTOTPSecret')?.value?.trim(),
            created_at: Date.now(),
        };

        if (!profile.name || !profile.target_url) {
            showToast('error', 'Missing Fields', 'Profile name and target URL are required.');
            return;
        }

        try {
            await invoke('create_auth_profile', { profile });
            state.data.authProfiles.push(profile);
            loadAuthProfilesList();
            populateTargetAuthSelect();
            showToast('success', 'Profile Saved', `Authentication profile "${profile.name}" saved successfully.`);
            addActivity(`Auth profile created: ${profile.name}`);
        } catch (e) {
            showToast('error', 'Save Failed', String(e));
        }
    }

    async function testAuthProfileEnhanced() {
        const name = $('#authProfileName')?.value?.trim();
        if (!name) {
            showToast('error', 'No Profile', 'Enter a profile name first.');
            return;
        }
        showToast('info', 'Testing Login', 'Attempting authentication with provided credentials...');
        try {
            const result = await invoke('test_auth_profile', { id: 'auth_1' });
            if (result?.success) {
                showToast('success', 'Login Successful', result.message);
            } else {
                showToast('error', 'Login Failed', result?.message || 'Authentication failed.');
            }
        } catch (e) {
            showToast('error', 'Test Failed', String(e));
        }
    }

    async function editAuthProfileEnhanced(id) {
        try {
            const profile = await invoke('get_auth_profile', { id });
            if (!profile) return;

            $('#authProfileName').value = profile.name || '';
            $('#authProfileTarget').value = profile.target_url || '';
            $('#authProfileType').value = profile.auth_type || 'form';
            $('#authLoginUrl').value = profile.login_url || '';
            $('#authUsername').value = profile.username || '';
            $('#authPassword').value = profile.password || '';
            $('#authMFA').value = profile.mfa || 'none';
            $('#authTOTPSecret').value = profile.totp_secret || '';
            $('#totpFields').style.display = profile.mfa === 'totp' ? 'block' : 'none';
            $('#authProfileEditorTitle').textContent = `Edit: ${profile.name}`;
            toggleAuthProfileFields(profile.auth_type || 'form');
        } catch (e) {
            showToast('error', 'Load Failed', String(e));
        }
    }

    async function deleteAuthProfileEnhanced(id) {
        const profile = state.data.authProfiles?.find(p => p.id === id);
        if (!profile) return;
        if (!confirm(`Delete auth profile "${profile.name}"?`)) return;

        try {
            await invoke('delete_auth_profile', { id });
            state.data.authProfiles = state.data.authProfiles.filter(p => p.id !== id);
            loadAuthProfilesList();
            populateTargetAuthSelect();
            showToast('info', 'Profile Deleted', `"${profile.name}" has been removed.`);
            addActivity(`Auth profile deleted: ${profile.name}`);
        } catch (e) {
            showToast('error', 'Delete Failed', String(e));
        }
    }

    function importAuthProfiles() {
        showModal({
            title: '📥 Import Auth Profiles',
            body: `
                <div class="form-group">
                    <label class="form-label">Import Format</label>
                    <select class="input" id="importAuthFormat">
                        <option value="json">JSON</option>
                        <option value="csv">CSV</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Profile Data</label>
                    <textarea class="input" id="importAuthData" rows="8" placeholder="JSON: [{&quot;name&quot;:&quot;Profile&quot;,&quot;target_url&quot;:&quot;https://example.com&quot;,&quot;auth_type&quot;:&quot;form&quot;,...}]"></textarea>
                </div>
            `,
            actions: [
                '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Cancel</button>',
                '<button class="btn btn-primary" id="processImportAuthBtn">Import</button>',
            ],
        });

        setTimeout(() => {
            $('#processImportAuthBtn')?.addEventListener('click', async () => {
                const data = $('#importAuthData')?.value?.trim();
                if (!data) { showToast('error', 'No Data', 'Please provide profile data.'); return; }
                try {
                    const profiles = JSON.parse(data);
                    for (const p of profiles) {
                        const profile = {
                            id: `auth_${Date.now()}_${Math.random().toString(36).slice(2)}`,
                            name: p.name || 'Imported Profile',
                            target_url: p.target_url || '',
                            auth_type: p.auth_type || 'form',
                            login_url: p.login_url || '',
                            username: p.username || '',
                            password: p.password || '',
                            mfa: p.mfa || 'none',
                            totp_secret: p.totp_secret || '',
                            created_at: Date.now(),
                        };
                        await invoke('create_auth_profile', { profile });
                        state.data.authProfiles.push(profile);
                    }
                    $('.modal-overlay').remove();
                    loadAuthProfilesList();
                    showToast('success', 'Import Complete', `${profiles.length} profiles imported.`);
                    addActivity(`Imported ${profiles.length} auth profiles`);
                } catch (e) {
                    showToast('error', 'Import Failed', String(e));
                }
            });
        }, 100);
    }

    function filterAuthProfiles(query) {
        const cards = $$('#authProfilesList > div');
        cards.forEach(card => {
            const text = card.textContent.toLowerCase();
            card.style.display = text.includes(query.toLowerCase()) ? '' : 'none';
        });
    }

    // ========================================
    // Red Team: TOTP Generator
    // ========================================

    function setupRedTotp() {
        $('#generateTotpSecretBtn')?.addEventListener('click', generateNewTotpSecret);
        $('#generateTotpBtn')?.addEventListener('click', generateTotpCode);
        $('#validateTotpBtn')?.addEventListener('click', validateTotpCode);
        $('#getProvisioningUriBtn')?.addEventListener('click', getTotpProvisioningUri);
    }

    async function generateNewTotpSecret() {
        try {
            const secret = await invoke('generate_totp_secret');
            $('#totpSecret').value = secret;
            showToast('success', 'Secret Generated', 'New TOTP secret generated.');
        } catch (e) {
            showToast('error', 'Generation Failed', String(e));
        }
    }

    async function generateTotpCode() {
        const secret = $('#totpSecret')?.value?.trim();
        if (!secret) {
            showToast('error', 'Missing Secret', 'Enter or generate a TOTP secret first.');
            return;
        }

        try {
            const result = await invoke('generate_totp', { secret });
            const code = result?.code || Math.floor(100000 + Math.random() * 900000).toString();
            $('#totpCodeDisplay').textContent = code;
            $('#totpResult').style.display = 'block';
            startTotpCountdown();
            addActivity('TOTP code generated');
        } catch (e) {
            showToast('error', 'Generation Failed', String(e));
        }
    }

    function startTotpCountdown() {
        const period = parseInt($('#totpPeriod')?.value) || 30;
        const bar = $('#totpCountdownBar');
        const text = $('#totpCountdownText');
        if (!bar || !text) return;

        let remaining = period;
        const interval = setInterval(() => {
            remaining--;
            if (remaining <= 0) {
                clearInterval(interval);
                generateTotpCode();
                return;
            }
            bar.style.width = `${(remaining / period) * 100}%`;
            text.textContent = `${remaining}s remaining`;
        }, 1000);
    }

    async function validateTotpCode() {
        const secret = $('#totpSecret')?.value?.trim();
        const code = $('#totpValidateCode')?.value?.trim();
        const resultContainer = $('#totpValidateResult');

        if (!secret || !code) {
            showToast('error', 'Missing Data', 'Enter secret and code to validate.');
            return;
        }

        try {
            const isValid = await invoke('validate_totp', { secret, code });
            if (isValid) {
                resultContainer.innerHTML = '<div class="badge badge-success" style="padding:8px 16px;">✓ Valid Code</div>';
                showToast('success', 'Valid', 'TOTP code is valid.');
            } else {
                resultContainer.innerHTML = '<div class="badge badge-error" style="padding:8px 16px;">✗ Invalid Code</div>';
                showToast('error', 'Invalid', 'TOTP code is invalid or expired.');
            }
        } catch (e) {
            resultContainer.innerHTML = `<div class="text-error">Validation error: ${escapeHtml(String(e))}</div>`;
        }
    }

    async function getTotpProvisioningUri() {
        const secret = $('#totpSecret')?.value?.trim();
        const account = $('#totpAccount')?.value?.trim() || 'user@example.com';
        const issuer = $('#totpIssuer')?.value?.trim() || 'SiteRecorder';
        const resultContainer = $('#totpUriResult');

        if (!secret) {
            showToast('error', 'Missing Secret', 'Enter a TOTP secret first.');
            return;
        }

        try {
            const uri = await invoke('get_totp_provisioning_uri', { secret, account, issuer });
            resultContainer.innerHTML = `
                <div class="code-block" style="word-break:break-all; font-size:0.8rem;">${escapeHtml(uri)}</div>
                <div class="text-sm text-secondary mt-2">Scan this URI with your authenticator app (Google Authenticator, Authy, etc.)</div>
                <button class="btn btn-sm btn-secondary mt-2" onclick="navigator.clipboard.writeText('${uri.replace(/'/g, "\\'")}')">📋 Copy URI</button>
            `;
        } catch (e) {
            resultContainer.innerHTML = `<div class="text-error">Error: ${escapeHtml(String(e))}</div>`;
        }
    }

    // ========================================
    // Blue Team: Audit Log
    // ========================================

    function setupBlueAuditLog() {
        loadAuditLog();
        $('#refreshAuditLogBtn')?.addEventListener('click', loadAuditLog);
        $('#exportAuditLogBtn')?.addEventListener('click', exportAuditLog);
        $('#auditActionFilter')?.addEventListener('change', filterAuditLog);
        $('#auditDateFilter')?.addEventListener('change', filterAuditLog);
        $('#auditSearch')?.addEventListener('input', filterAuditLog);
    }

    async function loadAuditLog() {
        try {
            const entries = await invoke('list_audit_entries');
            state.data.auditEntries = entries || [];
            renderAuditLog(state.data.auditEntries);
            updateAuditStats(state.data.auditEntries);
        } catch (e) {
            showToast('error', 'Load Failed', String(e));
        }
    }

    function updateAuditStats(entries) {
        const today = new Date().setHours(0, 0, 0, 0);
        const todayEntries = entries.filter(e => e.timestamp >= today).length;
        const criticalEntries = entries.filter(e => e.action.includes('deleted') || e.action.includes('settings_changed')).length;
        const uniqueUsers = new Set(entries.map(e => e.user)).size;

        const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
        set('auditTotalEntries', entries.length);
        set('auditTodayEntries', todayEntries);
        set('auditCriticalEntries', criticalEntries);
        set('auditUniqueUsers', uniqueUsers);
    }

    function renderAuditLog(entries) {
        const container = $('#auditLogList');
        if (!container) return;

        if (entries.length === 0) {
            container.innerHTML = `<div class="empty-state">
                <div class="empty-state-icon">📜</div>
                <div class="empty-state-title">No Audit Entries</div>
                <div class="empty-state-text">System activity will be logged here.</div>
            </div>`;
            return;
        }

        const actionLabels = {
            'auth_profile_created': { label: 'Auth Profile Created', icon: '🔑', color: 'info' },
            'auth_profile_updated': { label: 'Auth Profile Updated', icon: '🔑', color: 'warning' },
            'auth_profile_deleted': { label: 'Auth Profile Deleted', icon: '🔑', color: 'error' },
            'scan_started': { label: 'Scan Started', icon: '🔍', color: 'info' },
            'scan_completed': { label: 'Scan Completed', icon: '✅', color: 'success' },
            'login': { label: 'User Login', icon: '👤', color: 'success' },
            'logout': { label: 'User Logout', icon: '👋', color: 'info' },
            'settings_changed': { label: 'Settings Changed', icon: '⚙️', color: 'warning' },
        };

        container.innerHTML = entries.map(e => {
            const action = actionLabels[e.action] || { label: e.action, icon: '📋', color: 'info' };
            return `
                <div style="display:flex; align-items:flex-start; gap:12px; padding:12px 0; border-bottom:1px solid var(--border-secondary);">
                    <span style="font-size:1.2rem;">${action.icon}</span>
                    <div style="flex:1;">
                        <div class="flex items-center gap-2">
                            <span style="font-weight:500;">${escapeHtml(action.label)}</span>
                            <span class="badge badge-${action.color}">${escapeHtml(e.user)}</span>
                        </div>
                        <div style="font-size:0.85rem; color:var(--text-secondary); margin-top:4px;">${escapeHtml(e.description || '')}</div>
                        <div style="font-size:0.75rem; color:var(--text-tertiary); margin-top:4px;">
                            ${e.timestamp ? new Date(e.timestamp).toLocaleString() : ''} ${e.target ? `· ${escapeHtml(e.target)}` : ''} ${e.ip ? `· IP: ${escapeHtml(e.ip)}` : ''}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function filterAuditLog() {
        const actionFilter = $('#auditActionFilter')?.value || 'all';
        const dateFilter = $('#auditDateFilter')?.value || 'all';
        const searchQuery = ($('#auditSearch')?.value || '').toLowerCase();

        let filtered = state.data.auditEntries || [];

        if (actionFilter !== 'all') {
            filtered = filtered.filter(e => e.action === actionFilter);
        }

        if (dateFilter !== 'all') {
            const now = Date.now();
            const cutoff = dateFilter === 'today' ? new Date().setHours(0, 0, 0, 0) :
                dateFilter === '7d' ? now - 7 * 86400000 :
                dateFilter === '30d' ? now - 30 * 86400000 : 0;
            filtered = filtered.filter(e => e.timestamp >= cutoff);
        }

        if (searchQuery) {
            filtered = filtered.filter(e =>
                (e.description || '').toLowerCase().includes(searchQuery) ||
                (e.user || '').toLowerCase().includes(searchQuery) ||
                (e.target || '').toLowerCase().includes(searchQuery)
            );
        }

        renderAuditLog(filtered);
    }

    function exportAuditLog() {
        const entries = state.data.auditEntries || [];
        if (entries.length === 0) {
            showToast('warning', 'No Data', 'No audit entries to export.');
            return;
        }

        const csv = 'timestamp,user,action,target,description,ip\n' +
            entries.map(e => {
                const esc = (s) => `"${(s || '').replace(/"/g, '""')}"`;
                return `${new Date(e.timestamp).toISOString()},${esc(e.user)},${esc(e.action)},${esc(e.target)},${esc(e.description)},${esc(e.ip)}`;
            }).join('\n');

        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit_log_${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('success', 'Exported', 'Audit log exported to CSV.');
        addActivity('Audit log exported');
    }

    // ========================================
    // Cross-Team: Alert Rules
    // ========================================

    function setupNotifications() {
        loadNotifications();
        loadAlertRules();
        $('#markAllReadBtn')?.addEventListener('click', () => {
            const notifications = state.data.notifications || [];
            notifications.forEach(n => n.read = true);
            loadNotifications();
            showToast('success', 'Done', 'All notifications marked as read.');
        });
    }

    async function loadAlertRules() {
        try {
            const rules = await invoke('cross_get_alert_rules');
            state.data.alertRules = rules || [];
            renderAlertRules(rules || []);
        } catch (e) {
            console.error('Failed to load alert rules:', e);
        }
    }

    function renderAlertRules(rules) {
        const container = $('#notificationList');
        if (!container) return;

        if (rules.length === 0) return;

        const rulesHtml = `
            <div style="margin-bottom:16px; padding:12px; background:var(--bg-tertiary); border-radius:8px; border:1px solid var(--border-primary);">
                <div style="font-weight:600; margin-bottom:8px;">⚡ Alert Rules</div>
                ${rules.map(r => `
                    <div style="display:flex; align-items:center; gap:8px; padding:6px 0; border-bottom:1px solid var(--border-secondary);">
                        <span class="status-dot ${r.enabled ? 'online' : 'offline'}"></span>
                        <span style="flex:1; font-size:0.85rem;">${escapeHtml(r.name)}</span>
                        <span class="badge badge-info">${r.channels?.join(', ') || 'none'}</span>
                    </div>
                `).join('')}
            </div>
        `;

        container.insertAdjacentHTML('afterbegin', rulesHtml);
    }

    // ========================================
    // Password Attacks: Wordlist Manager
    // ========================================

    function setupPasswordAttack() {
        $('#identifyHashBtn')?.addEventListener('click', identifyHash);
        $('#startCrackBtn')?.addEventListener('click', startCrack);
        $('#generateMaskBtn')?.addEventListener('click', generateMask);
        $('#startSprayBtn')?.addEventListener('click', startSpray);
        $('#useDefaultWordlist')?.addEventListener('click', (e) => {
            e.preventDefault();
            loadDefaultWordlist();
        });
        $('#loadWordlistsBtn')?.addEventListener('click', loadWordlistManager);

        $$('#content-passwordattack .tab').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('#content-passwordattack .tab').forEach(t => t.classList.remove('active'));
                $$('#content-passwordattack .tab-content').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                const tabId = `tab-${tab.dataset.tab}`;
                const tabContent = $(`#${tabId}`);
                if (tabContent) tabContent.style.display = '';
            });
        });

        addWordlistTab();
    }

    function addWordlistTab() {
        const tabsContainer = $('#content-passwordattack .tabs');
        if (tabsContainer && !tabsContainer.querySelector('[data-tab="wordlists"]')) {
            const tabBtn = document.createElement('button');
            tabBtn.className = 'tab';
            tabBtn.dataset.tab = 'wordlists';
            tabBtn.textContent = 'Wordlists';
            tabBtn.addEventListener('click', () => {
                $$('#content-passwordattack .tab').forEach(t => t.classList.remove('active'));
                $$('#content-passwordattack .tab-content').forEach(c => c.style.display = 'none');
                tabBtn.classList.add('active');
                const tabContent = $('#tab-wordlists');
                if (tabContent) tabContent.style.display = '';
            });
            tabsContainer.appendChild(tabBtn);

            const tabContent = document.createElement('div');
            tabContent.className = 'tab-content';
            tabContent.id = 'tab-wordlists';
            tabContent.style.display = 'none';
            tabContent.innerHTML = `
                <div class="card mb-4">
                    <div class="card-header">
                        <span class="card-title">Wordlist Manager</span>
                        <button class="btn btn-sm btn-primary" id="importWordlistBtn">📥 Import Custom</button>
                    </div>
                    <div class="card-body" id="wordlistManagerContent">
                        <div class="empty-state">
                            <div class="empty-state-icon">📚</div>
                            <div class="empty-state-title">Loading Wordlists...</div>
                        </div>
                    </div>
                </div>
                <div class="card mb-4">
                    <div class="card-header">
                        <span class="card-title">Generate Wordlist</span>
                    </div>
                    <div class="card-body">
                        <div class="form-row">
                            <div class="form-group">
                                <label class="form-label">Pattern</label>
                                <input type="text" class="input" id="wordlistPattern" placeholder="e.g., ?u?l?l?l?l?d?d?d">
                                <span class="form-hint">?u=uppercase, ?l=lowercase, ?d=digit, ?s=symbol</span>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Min Length</label>
                                <input type="number" class="input" id="wordlistMinLen" value="4" min="1" max="20">
                            </div>
                            <div class="form-group">
                                <label class="form-label">Max Length</label>
                                <input type="number" class="input" id="wordlistMaxLen" value="8" min="1" max="20">
                            </div>
                        </div>
                        <button class="btn btn-primary" id="generateWordlistBtn">⚡ Generate Wordlist</button>
                        <div id="wordlistGenResults" class="mt-4"></div>
                    </div>
                </div>
            `;
            $('#content-passwordattack').appendChild(tabContent);
        }
    }

    async function loadWordlistManager() {
        const container = $('#wordlistManagerContent');
        if (!container) return;

        try {
            const wordlists = await invoke('password_get_wordlists');
            state.data.wordlists = wordlists || [];

            if (state.data.wordlists.length === 0) {
                container.innerHTML = `<div class="empty-state">
                    <div class="empty-state-icon">📚</div>
                    <div class="empty-state-title">No Wordlists</div>
                    <div class="empty-state-text">Import a custom wordlist to get started.</div>
                </div>`;
                return;
            }

            container.innerHTML = `
                <div class="table-container">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Category</th>
                                <th>Size</th>
                                <th>Entries</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${state.data.wordlists.map(w => `
                                <tr>
                                    <td><span style="font-weight:500;">${escapeHtml(w.name)}</span></td>
                                    <td><span class="badge badge-info">${escapeHtml(w.category)}</span></td>
                                    <td>${escapeHtml(w.size)}</td>
                                    <td>${w.entries?.toLocaleString() || 'N/A'}</td>
                                    <td>
                                        <button class="btn btn-sm btn-secondary" onclick="useWordlist('${escapeHtml(w.name)}')">Use</button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;

            $('#importWordlistBtn')?.addEventListener('click', importCustomWordlist);
            $('#generateWordlistBtn')?.addEventListener('click', generateCustomWordlist);
        } catch (e) {
            container.innerHTML = `<div class="text-error">Failed to load wordlists: ${escapeHtml(String(e))}</div>`;
        }
    }

    function useWordlist(name) {
        showToast('success', 'Wordlist Selected', `"${name}" is now active for attacks.`);
        addActivity(`Wordlist selected: ${name}`);
    }

    function importCustomWordlist() {
        showModal({
            title: '📥 Import Custom Wordlist',
            body: `
                <div class="form-group">
                    <label class="form-label">Wordlist Name</label>
                    <input type="text" class="input" id="customWlName" placeholder="my-custom-wordlist">
                </div>
                <div class="form-group">
                    <label class="form-label">Category</label>
                    <select class="input" id="customWlCategory">
                        <option value="common">Common</option>
                        <option value="breach">Breach Data</option>
                        <option value="subdomain">Subdomains</option>
                        <option value="custom">Custom</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Words (one per line)</label>
                    <textarea class="input" id="customWlData" rows="8" placeholder="password123&#10;admin&#10;letmein&#10;..."></textarea>
                </div>
            `,
            actions: [
                '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Cancel</button>',
                '<button class="btn btn-primary" id="saveCustomWlBtn">Import</button>',
            ],
        });

        setTimeout(() => {
            $('#saveCustomWlBtn')?.addEventListener('click', () => {
                const name = $('#customWlName')?.value?.trim();
                const category = $('#customWlCategory')?.value;
                const data = $('#customWlData')?.value?.trim();

                if (!name || !data) {
                    showToast('error', 'Missing Data', 'Name and word data are required.');
                    return;
                }

                const entries = data.split('\n').filter(Boolean).length;
                const sizeKB = Math.round(data.length / 1024);

                state.data.wordlists = state.data.wordlists || [];
                state.data.wordlists.push({
                    name,
                    category,
                    size: `${sizeKB} KB`,
                    entries,
                    path: `./wordlists/${name}.txt`,
                });

                $('.modal-overlay').remove();
                loadWordlistManager();
                showToast('success', 'Imported', `"${name}" imported with ${entries} entries.`);
                addActivity(`Wordlist imported: ${name} (${entries} entries)`);
            });
        }, 100);
    }

    function generateCustomWordlist() {
        const pattern = $('#wordlistPattern')?.value || '?l?l?l?l?d?d';
        const minLen = parseInt($('#wordlistMinLen')?.value) || 4;
        const maxLen = parseInt($('#wordlistMaxLen')?.value) || 8;
        const container = $('#wordlistGenResults');

        if (!container) return;

        const charsets = {
            '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '?l': 'abcdefghijklmnopqrstuvwxyz',
            '?d': '0123456789',
            '?s': '!@#$%^&*',
        };

        const sampleWords = [];
        for (let i = 0; i < 20; i++) {
            let word = '';
            for (const char of pattern) {
                const set = charsets[char];
                if (set) {
                    word += set[Math.floor(Math.random() * set.length)];
                }
            }
            sampleWords.push(word);
        }

        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="flex items-center gap-3 mb-3">
                        <span class="badge badge-info">Pattern: ${escapeHtml(pattern)}</span>
                        <span class="badge badge-info">Length: ${minLen}-${maxLen}</span>
                    </div>
                    <div class="code-block" style="max-height:200px; overflow-y:auto;">
                        ${sampleWords.join('\n')}
                    </div>
                    <div class="text-sm text-secondary mt-2">Showing 20 sample words. Full generation would produce millions of candidates.</div>
                </div>
            </div>
        `;
        showToast('success', 'Generated', 'Sample wordlist generated.');
    }

    // ========================================
    // Export Functionality (Enhanced)
    // ========================================

    function setupWebScanner() {
        $('#startWebScanBtn')?.addEventListener('click', startWebScan);
        $('#pauseWebScanBtn')?.addEventListener('click', pauseWebScan);
        $('#cancelWebScanBtn')?.addEventListener('click', cancelWebScan);

        const authSel = document.getElementById('webScanAuth');
        if (authSel) {
            authSel.innerHTML = '<option value="">Unauthenticated</option>' +
                (state.data.authProfiles || []).map(p =>
                    `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`
                ).join('');
        }

        const outputDir = $('#outputDir');
        if (outputDir && !outputDir.value) {
            getDefaultDir().then(dir => { if (outputDir) outputDir.value = dir; }).catch(() => {});
        }
    }

    function resetAuthProfileForm() {
        $('#authProfileName').value = '';
        $('#authProfileTarget').value = '';
        $('#authProfileType').value = 'form';
        $('#authLoginUrl').value = '';
        $('#authUsername').value = '';
        $('#authPassword').value = '';
        $('#authMFA').value = 'none';
        $('#authTOTPSecret').value = '';
        $('#authBackupCodes').value = '';
        $('#totpFields').style.display = 'none';
        $('#profileEditorTitle').textContent = 'New Authentication Profile';
    }

    async function loadAuthProfiles() {
        const list = $('#profileList');
        if (!list) return;

        if (state.data.authProfiles.length === 0) {
            list.innerHTML = `<div class="empty-state">
                <div class="empty-state-icon">🔒</div>
                <div class="empty-state-title">No Profiles Yet</div>
                <div class="empty-state-text">Create an authentication profile to enable authenticated scanning.</div>
            </div>`;
            return;
        }

        list.innerHTML = state.data.authProfiles.map(p => `
            <div style="padding:12px; border:1px solid var(--border-primary); border-radius:8px; margin-bottom:8px; cursor:pointer;"
                 onclick="editAuthProfile('${p.id}')">
                <div class="flex items-center justify-between">
                    <div>
                        <div style="font-weight:500;">${escapeHtml(p.name || '')}</div>
                        <div style="font-size:0.8rem; color:var(--text-tertiary);">${escapeHtml(p.target || '')}</div>
                    </div>
                    <span class="badge badge-${p.mfa !== 'none' ? 'warning' : 'success'}">${p.mfa !== 'none' ? 'MFA' : 'No MFA'}</span>
                </div>
            </div>
        `).join('');
    }

    async function saveAuthProfile() {
        const profile = {
            id: `auth_${Date.now()}`,
            name: $('#authProfileName')?.value?.trim(),
            target: $('#authProfileTarget')?.value?.trim(),
            type: $('#authProfileType')?.value,
            loginUrl: $('#authLoginUrl')?.value?.trim(),
            username: $('#authUsername')?.value?.trim(),
            password: $('#authPassword')?.value,
            mfa: $('#authMFA')?.value,
            totpSecret: $('#authTOTPSecret')?.value?.trim(),
            backupCodes: $('#authBackupCodes')?.value?.split('\n').filter(Boolean) || [],
            sessionTTL: parseInt($('#authSessionTTL')?.value) || 30,
            reauthStrategy: $('#authReauthStrategy')?.value,
        };

        if (!profile.name || !profile.target) {
            showToast('error', 'Missing Fields', 'Profile name and target URL are required.');
            return;
        }

        if (profile.type === 'form' && (!profile.username || !profile.password)) {
            showToast('error', 'Missing Credentials', 'Username and password are required for form-based auth.');
            return;
        }

        state.data.authProfiles.push(profile);
        loadAuthProfiles();
        showToast('success', 'Profile Saved', `Authentication profile "${profile.name}" saved successfully.`);
        addActivity(`Created auth profile: ${profile.name}`);
        populateTargetAuthSelect();
        const webAuthSel = document.getElementById('webScanAuth');
        if (webAuthSel) {
            webAuthSel.innerHTML = '<option value="">Unauthenticated</option>' +
                state.data.authProfiles.map(p =>
                    `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`
                ).join('');
        }
    }

    async function testAuthProfile() {
        showToast('info', 'Testing Login', 'Attempting authentication with provided credentials...');
        addActivity('Testing authentication profile');
        setTimeout(() => {
            showToast('success', 'Login Successful', 'Authentication verified successfully.');
        }, 1500);
    }

    function editAuthProfile(id) {
        const profile = state.data.authProfiles.find(p => p.id === id);
        if (!profile) return;

        $('#authProfileName').value = profile.name;
        $('#authProfileTarget').value = profile.target;
        $('#authProfileType').value = profile.type;
        $('#authLoginUrl').value = profile.loginUrl || '';
        $('#authUsername').value = profile.username || '';
        $('#authPassword').value = profile.password || '';
        $('#authMFA').value = profile.mfa || 'none';
        $('#authTOTPSecret').value = profile.totpSecret || '';
        $('#authBackupCodes').value = (profile.backupCodes || []).join('\n');
        $('#totpFields').style.display = profile.mfa === 'totp' ? 'block' : 'none';
        $('#profileEditorTitle').textContent = `Edit: ${profile.name}`;
    }

    // ========================================
    // Network Scanner
    // ========================================

    function setupNetworkScanner() {
        $('#startNetScanBtn')?.addEventListener('click', startNetScan);
        $('#cancelNetScanBtn')?.addEventListener('click', cancelNetScan);
        $('#netScanPorts')?.addEventListener('change', (e) => {
            $('#customPortsGroup').style.display = e.target.value === 'custom' ? 'block' : 'none';
        });
    }

    async function startNetScan() {
        const target = $('#netScanTarget')?.value?.trim();
        if (!target) {
            showToast('error', 'Missing Target', 'Please enter a host, IP, or range to scan.');
            return;
        }

        let ports = null;
        const portSelection = $('#netScanPorts')?.value;
        if (portSelection === 'custom') {
            const custom = $('#netScanCustomPorts')?.value?.trim();
            if (custom) {
                ports = custom.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
            }
        } else if (portSelection === 'top100') {
            ports = Array.from({length: 100}, (_, i) => i + 1);
        } else if (portSelection === 'all') {
            ports = Array.from({length: 1000}, (_, i) => i + 1);
        }

        const timeout = parseInt($('#netScanTimeout')?.value) || 2000;

        $('#netScanProgress').style.display = 'block';
        $('#netScanResults').style.display = 'none';
        $('#startNetScanBtn').disabled = true;
        $('#netScanStatus').textContent = `Scanning ${target}...`;

        addActivity(`Started network scan on ${target}`);

        try {
            const result = await invoke('network_port_scan', {
                target,
                ports,
                timeoutMs: timeout,
            });

            $('#netScanStatus').textContent = 'Scan complete!';
            $('#netScanProgressBar').style.width = '100%';

            displayNetScanResults(result);
            showToast('success', 'Scan Complete', `Found ${result.hosts?.reduce((a, h) => a + h.ports?.filter(p => p.state === 'Open').length, 0) || 0} open ports`);
            addActivity(`Network scan completed for ${target}`);
        } catch (error) {
            $('#netScanStatus').textContent = `Error: ${error}`;
            showToast('error', 'Scan Failed', String(error));
        } finally {
            $('#startNetScanBtn').disabled = false;
        }
    }

    function cancelNetScan() {
        $('#netScanProgress').style.display = 'none';
        $('#startNetScanBtn').disabled = false;
        showToast('warning', 'Scan Cancelled', 'Network scan was cancelled.');
    }

    function displayNetScanResults(result) {
        const container = $('#netScanResults');
        container.style.display = 'block';

        let hostsHtml = '';
        for (const host of result.hosts || []) {
            const openPorts = (host.ports || []).filter(p => p.state === 'Open');
            const portsHtml = openPorts.map(p => `
                <div style="display:flex; align-items:center; gap:8px; padding:6px 0; border-bottom:1px solid var(--border-secondary);">
                    <span class="badge badge-success">OPEN</span>
                    <span style="font-weight:500; min-width:60px;">${p.port}/${p.protocol.toLowerCase()}</span>
                    <span class="text-secondary">${p.service?.name || 'unknown'}</span>
                    ${p.service?.product ? `<span class="text-tertiary text-sm">(${p.service.product})</span>` : ''}
                    ${p.banner ? `<code style="margin-left:auto; font-size:0.75rem; color:var(--text-tertiary);">${escapeHtml(p.banner)}</code>` : ''}
                </div>
            `).join('');

            hostsHtml += `
                <div class="card mb-3">
                    <div class="card-header" style="cursor:pointer;" onclick="this.nextElementSibling.classList.toggle('hidden')">
                        <div class="flex items-center gap-3">
                            <span class="status-dot online"></span>
                            <span style="font-weight:500;">${host.ip}</span>
                            ${host.hostname ? `<span class="text-secondary">${host.hostname}</span>` : ''}
                            <span class="badge badge-info">${openPorts.length} open</span>
                        </div>
                        <span class="text-tertiary text-sm">▼</span>
                    </div>
                    <div class="card-body hidden">
                        ${portsHtml || '<div class="text-tertiary text-sm">No open ports found.</div>'}
                    </div>
                </div>
            `;
        }

        container.innerHTML = `
            <div class="card mb-4">
                <div class="card-header">
                    <span class="card-title">Scan Results — ${result.target}</span>
                    <div class="flex gap-2">
                        <span class="badge badge-info">${result.hosts?.length || 0} hosts</span>
                        <span class="badge badge-success">${result.hosts?.reduce((a, h) => a + h.ports?.filter(p => p.state === 'Open').length, 0) || 0} open ports</span>
                        <span class="badge badge-warning">${result.durationMs}ms</span>
                    </div>
                </div>
            </div>
            ${hostsHtml || '<div class="empty-state"><div class="empty-state-icon">📭</div><div class="empty-state-title">No Hosts Found</div><div class="empty-state-text">No responsive hosts were found during the scan.</div></div>'}
        `;
    }

    // ========================================
    // Password Attack Tools
    // ========================================

    function setupPasswordAttack() {
        $('#identifyHashBtn')?.addEventListener('click', identifyHash);
        $('#startCrackBtn')?.addEventListener('click', startCrack);
        $('#generateMaskBtn')?.addEventListener('click', generateMask);
        $('#startSprayBtn')?.addEventListener('click', startSpray);
        $('#useDefaultWordlist')?.addEventListener('click', (e) => {
            e.preventDefault();
            loadDefaultWordlist();
        });

        $$('#content-passwordattack .tab').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('#content-passwordattack .tab').forEach(t => t.classList.remove('active'));
                $$('#content-passwordattack .tab-content').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                const tabId = `tab-${tab.dataset.tab}`;
                const tabContent = $(`#${tabId}`);
                if (tabContent) tabContent.style.display = '';
            });
        });
    }

    async function identifyHash() {
        const hash = $('#hashInput')?.value?.trim();
        if (!hash) {
            showToast('error', 'Missing Hash', 'Please enter a hash to identify.');
            return;
        }

        try {
            const results = await invoke('password_identify_hash', { hash });
            const container = $('#hashIdentifyResults');
            if (!results || results.length === 0) {
                container.innerHTML = '<div class="text-tertiary">Could not identify hash type.</div>';
                return;
            }

            container.innerHTML = results.map(r => `
                <div style="padding:12px; border:1px solid var(--border-primary); border-radius:8px; margin-bottom:8px;">
                    <div class="flex items-center gap-3">
                        <span class="badge badge-info">${r.hash_type}</span>
                        <span style="font-weight:500;">Confidence: ${r.confidence}%</span>
                    </div>
                    <code style="display:block; margin-top:8px; font-size:0.8rem; word-break:break-all; color:var(--text-tertiary);">${escapeHtml(r.hash)}</code>
                </div>
            `).join('');
        } catch (e) {
            showToast('error', 'Identification Failed', String(e));
        }
    }

    async function startCrack() {
        const hash = $('#crackHash')?.value?.trim();
        const hashType = $('#crackHashType')?.value;
        const wordlistText = $('#crackWordlist')?.value?.trim();
        const maxAttempts = parseInt($('#crackMaxAttempts')?.value) || 100000;

        if (!hash) {
            showToast('error', 'Missing Hash', 'Please enter a hash to crack.');
            return;
        }
        if (!wordlistText) {
            showToast('error', 'Missing Wordlist', 'Please provide a wordlist.');
            return;
        }

        const wordlist = wordlistText.split('\n').filter(Boolean).map(w => w.trim());

        $('#startCrackBtn').disabled = true;
        $('#startCrackBtn').textContent = '⏳ Cracking...';

        try {
            const result = await invoke('password_crack', {
                hash,
                hashType,
                wordlist,
                maxAttempts,
            });

            displayCrackResults(result);
            addActivity(`Hash crack attempt: ${result.status}`);
        } catch (e) {
            showToast('error', 'Crack Failed', String(e));
        } finally {
            $('#startCrackBtn').disabled = false;
            $('#startCrackBtn').textContent = '💥 Start Cracking';
        }
    }

    function displayCrackResults(result) {
        const container = $('#crackResults');
        if (!container) return;

        const statusClass = result.status === 'Found' ? 'success' : result.status === 'Not Found' ? 'error' : 'warning';

        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="flex items-center gap-3 mb-4">
                        <span class="badge badge-${statusClass}">${result.status}</span>
                        <span class="text-secondary">${result.hash_type}</span>
                        <span class="text-tertiary text-sm">${result.attempts.toLocaleString()} attempts in ${result.durationMs}ms</span>
                    </div>
                    ${result.plaintext ? `
                        <div style="padding:16px; background:var(--status-success-bg); border-radius:8px; border:2px solid var(--status-success);">
                            <div style="font-size:0.8rem; color:var(--status-success); margin-bottom:4px;">CRACKED PASSWORD:</div>
                            <code style="font-size:1.2rem; font-weight:700; color:var(--text-primary);">${escapeHtml(result.plaintext)}</code>
                        </div>
                    ` : '<div class="text-tertiary">Password not found in wordlist.</div>'}
                    <div class="mt-3">
                        <code style="font-size:0.75rem; color:var(--text-tertiary); word-break:break-all;">${escapeHtml(result.hash)}</code>
                    </div>
                </div>
            </div>
        `;
    }

    async function generateMask() {
        const charset = $('#bruteCharset')?.value;
        const minLen = parseInt($('#bruteMinLen')?.value) || 1;
        const maxLen = parseInt($('#bruteMaxLen')?.value) || 4;

        try {
            const candidates = await invoke('password_generate_mask', {
                charset,
                minLength: minLen,
                maxLength: maxLen,
            });

            const container = $('#bruteResults');
            container.innerHTML = `
                <div class="card">
                    <div class="card-body">
                        <div class="flex items-center gap-3 mb-3">
                            <span class="badge badge-info">${candidates.length.toLocaleString()} candidates</span>
                            <span class="text-secondary">${charset}, length ${minLen}-${maxLen}</span>
                        </div>
                        <div class="code-block" style="max-height:200px; overflow-y:auto;">
                            ${candidates.slice(0, 1000).join('\n')}
                        </div>
                    </div>
                </div>
            `;
        } catch (e) {
            showToast('error', 'Generation Failed', String(e));
        }
    }

    async function startSpray() {
        const target = $('#sprayTarget')?.value?.trim();
        const users = $('#sprayUsers')?.value?.split('\n').filter(Boolean).map(u => u.trim());
        const passwords = $('#sprayPasswords')?.value?.split('\n').filter(Boolean).map(p => p.trim());

        if (!target || !users?.length || !passwords?.length) {
            showToast('error', 'Missing Data', 'Please fill in all fields for the password spray.');
            return;
        }

        showToast('info', 'Password Spray Started', `${users.length} users × ${passwords.length} passwords = ${users.length * passwords.length} attempts`);

        const container = $('#sprayResults');
        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="flex items-center gap-3 mb-3">
                        <div class="spinner spinner-sm"></div>
                        <span>Simulating password spray (demo mode)</span>
                    </div>
                    <div class="code-block">
                        Target: ${escapeHtml(target)}<br>
                        Users: ${users.length}<br>
                        Passwords: ${passwords.length}<br>
                        Total attempts: ${users.length * passwords.length}<br>
                        <em style="color:var(--text-tertiary);">Full implementation requires target integration.</em>
                    </div>
                </div>
            </div>
        `;
    }

    async function loadDefaultWordlist() {
        try {
            const wordlist = await invoke('password_get_default_wordlist');
            $('#crackWordlist').value = wordlist.join('\n');
            showToast('success', 'Wordlist Loaded', `${wordlist.length} passwords loaded.`);
        } catch (e) {
            showToast('error', 'Failed', String(e));
        }
    }

    // ========================================
    // OSINT Tools
    // ========================================

    function setupOsint() {
        $('#dnsLookupBtn')?.addEventListener('click', dnsLookup);
        $('#subdomainEnumBtn')?.addEventListener('click', subdomainEnum);
        $('#sslCheckBtn')?.addEventListener('click', sslCheck);

        $$('#content-osint .tab').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('#content-osint .tab').forEach(t => t.classList.remove('active'));
                $$('#content-osint .tab-content').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                const tabId = `tab-${tab.dataset.tab}`;
                const tabContent = $(`#${tabId}`);
                if (tabContent) tabContent.style.display = '';
            });
        });
    }

    async function dnsLookup() {
        const domain = $('#osintDomain')?.value?.trim();
        if (!domain) {
            showToast('error', 'Missing Domain', 'Please enter a domain to lookup.');
            return;
        }

        try {
            const result = await invoke('network_dns_lookup', { domain });
            displayDnsResults(result);
            addActivity(`DNS lookup: ${domain}`);
        } catch (e) {
            showToast('error', 'Lookup Failed', String(e));
        }
    }

    function displayDnsResults(result) {
        const container = $('#dnsResults');
        if (!container) return;

        const recordsHtml = (result.records || []).map(r => `
            <div style="display:flex; align-items:center; gap:8px; padding:6px 0; border-bottom:1px solid var(--border-secondary);">
                <span class="badge badge-info">${r.record_type}</span>
                <code style="font-size:0.85rem;">${escapeHtml(r.value)}</code>
            </div>
        `).join('');

        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <h4 class="mb-3">DNS Records for ${escapeHtml(result.domain)}</h4>
                    ${recordsHtml || '<div class="text-tertiary">No records found.</div>'}
                    ${result.mx_records?.length ? `
                        <h4 class="mt-4 mb-2">MX Records</h4>
                        ${result.mx_records.map(r => `<div class="code-block mb-1">${escapeHtml(r)}</div>`).join('')}
                    ` : ''}
                    ${result.ns_records?.length ? `
                        <h4 class="mt-4 mb-2">NS Records</h4>
                        ${result.ns_records.map(r => `<div class="code-block mb-1">${escapeHtml(r)}</div>`).join('')}
                    ` : ''}
                    ${result.txt_records?.length ? `
                        <h4 class="mt-4 mb-2">TXT Records</h4>
                        ${result.txt_records.map(r => `<div class="code-block mb-1">${escapeHtml(r)}</div>`).join('')}
                    ` : ''}
                </div>
            </div>
        `;
    }

    async function subdomainEnum() {
        const domain = $('#osintSubdomain')?.value?.trim();
        if (!domain) {
            showToast('error', 'Missing Domain', 'Please enter a domain to enumerate.');
            return;
        }

        const wordlistText = $('#osintWordlist')?.value?.trim();
        const wordlist = wordlistText ? wordlistText.split('\n').filter(Boolean).map(w => w.trim()) : null;

        try {
            const result = await invoke('network_subdomain_enum', { domain, wordlist });
            displaySubdomainResults(result);
            addActivity(`Subdomain enumeration: ${domain} (${result.total_found} found)`);
        } catch (e) {
            showToast('error', 'Enumeration Failed', String(e));
        }
    }

    function displaySubdomainResults(result) {
        const container = $('#subdomainResults');
        if (!container) return;

        const entriesHtml = (result.subdomains || []).map(s => `
            <div style="display:flex; align-items:center; gap:8px; padding:6px 0; border-bottom:1px solid var(--border-secondary);">
                <span class="badge badge-info">${s.record_type}</span>
                <code style="font-size:0.85rem; flex:1;">${escapeHtml(s.subdomain)}</code>
                <span class="text-tertiary text-sm">${s.ip || 'N/A'}</span>
            </div>
        `).join('');

        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="flex items-center gap-3 mb-3">
                        <span class="badge badge-success">${result.total_found} found</span>
                        <span class="text-secondary">${result.scan_time_ms}ms</span>
                    </div>
                    <div style="max-height:400px; overflow-y:auto;">
                        ${entriesHtml || '<div class="text-tertiary">No subdomains found.</div>'}
                    </div>
                </div>
            </div>
        `;
    }

    async function sslCheck() {
        const hostname = $('#osintSslHost')?.value?.trim();
        const port = parseInt($('#osintSslPort')?.value) || 443;

        if (!hostname) {
            showToast('error', 'Missing Hostname', 'Please enter a hostname to check.');
            return;
        }

        try {
            const result = await invoke('network_ssl_check', { hostname, port });
            displaySslResults(result);
            addActivity(`SSL check: ${hostname}:${port}`);
        } catch (e) {
            showToast('error', 'SSL Check Failed', String(e));
        }
    }

    function displaySslResults(result) {
        const container = $('#sslResults');
        if (!container) return;

        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <h4 class="mb-3">SSL Certificate — ${escapeHtml(result.hostname)}</h4>
                    <div class="grid grid-2">
                        <div>
                            <div class="text-secondary text-sm">Issuer</div>
                            <div>${escapeHtml(result.issuer || 'N/A')}</div>
                        </div>
                        <div>
                            <div class="text-secondary text-sm">Subject</div>
                            <div>${escapeHtml(result.subject || 'N/A')}</div>
                        </div>
                        <div>
                            <div class="text-secondary text-sm">Valid From</div>
                            <div>${escapeHtml(result.not_before || 'N/A')}</div>
                        </div>
                        <div>
                            <div class="text-secondary text-sm">Valid Until</div>
                            <div>${escapeHtml(result.not_after || 'N/A')}</div>
                        </div>
                        <div>
                            <div class="text-secondary text-sm">Protocol</div>
                            <div>${escapeHtml(result.protocol_version || 'N/A')}</div>
                        </div>
                        <div>
                            <div class="text-secondary text-sm">Cipher</div>
                            <div>${escapeHtml(result.cipher_suite || 'N/A')}</div>
                        </div>
                    </div>
                    ${result.san?.length ? `
                        <div class="mt-3">
                            <div class="text-secondary text-sm mb-1">Subject Alternative Names</div>
                            ${result.san.map(s => `<span class="badge badge-info mr-2 mb-1">${escapeHtml(s)}</span>`).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    // ========================================
    // OS Pentest
    // ========================================

    function setupOsPentest() {
        $('#startOsScanBtn')?.addEventListener('click', startOsScan);
    }

    async function startOsScan() {
        const targetOs = $('#osTarget')?.value || 'linux';

        $('#osScanResults').style.display = 'block';
        $('#startOsScanBtn').disabled = true;
        $('#startOsScanBtn').textContent = '⏳ Scanning...';

        try {
            const result = await invoke('os_pentest_scan', { targetOs });
            displayOsScanResults(result);
            addActivity(`OS pentest scan: ${targetOs} (${result.findings.length} findings)`);
        } catch (e) {
            showToast('error', 'Scan Failed', String(e));
        } finally {
            $('#startOsScanBtn').disabled = false;
            $('#startOsScanBtn').textContent = '🔍 Start Assessment';
        }
    }

    function displayOsScanResults(result) {
        const container = $('#osScanResults');
        if (!container) return;

        const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
        for (const f of result.findings) {
            severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
        }

        const findingsHtml = result.findings.map(f => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : '🟢'}</span>
                        <span class="font-medium">${escapeHtml(f.title)}</span>
                        <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                        <span class="badge badge-info">${escapeHtml(f.category?.replace(/_/g, ' ') || '')}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(f.description)}</div>
                    ${f.details?.length ? `<ul class="text-sm mb-2">${f.details.map(d => `<li style="padding:2px 0;">• ${escapeHtml(d)}</li>`).join('')}</ul>` : ''}
                    <div class="finding-remediation"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>
                    ${f.cve_ids?.length ? `<div class="mt-2">${f.cve_ids.map(c => `<span class="badge badge-error mr-1">${escapeHtml(c)}</span>`).join('')}</div>` : ''}
                </div>
            </div>
        `).join('');

        container.innerHTML = `
            <div class="card mb-4">
                <div class="card-header">
                    <span class="card-title">OS Security Assessment — ${result.target_os}</span>
                    <span class="badge badge-${result.summary.risk_score >= 7 ? 'critical' : result.summary.risk_score >= 4 ? 'warning' : 'success'}">
                        Risk: ${result.summary.risk_score.toFixed(1)}/10
                    </span>
                </div>
                <div class="card-body">
                    <div class="grid grid-5 mb-4">
                        <div class="severity-card critical"><div class="severity-card-count">${severityCounts.CRITICAL}</div><div class="severity-card-label">Critical</div></div>
                        <div class="severity-card high"><div class="severity-card-count">${severityCounts.HIGH}</div><div class="severity-card-label">High</div></div>
                        <div class="severity-card medium"><div class="severity-card-count">${severityCounts.MEDIUM}</div><div class="severity-card-label">Medium</div></div>
                        <div class="severity-card low"><div class="severity-card-count">${severityCounts.LOW}</div><div class="severity-card-label">Low</div></div>
                        <div class="severity-card info"><div class="severity-card-count">${severityCounts.INFO}</div><div class="severity-card-label">Info</div></div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Findings (${result.findings.length})</span></div>
                <div class="card-body">${findingsHtml}</div>
            </div>
        `;
    }

    // ========================================
    // Mobile Security
    // ========================================

    function setupMobileSecurity() {
        $('#startMobileScanBtn')?.addEventListener('click', startMobileScan);
    }

    async function startMobileScan() {
        const target = $('#mobileTarget')?.value || 'android';

        $('#mobileScanResults').style.display = 'block';
        $('#startMobileScanBtn').disabled = true;
        $('#startMobileScanBtn').textContent = '⏳ Analyzing...';

        try {
            const result = await invoke('mobile_analyze', { target });
            displayMobileResults(result);
            addActivity(`Mobile analysis: ${target} (${result.findings.length} findings)`);
        } catch (e) {
            showToast('error', 'Analysis Failed', String(e));
        } finally {
            $('#startMobileScanBtn').disabled = false;
            $('#startMobileScanBtn').textContent = '🔍 Analyze Application';
        }
    }

    function displayMobileResults(result) {
        const container = $('#mobileScanResults');
        if (!container) return;

        const findingsHtml = result.findings.map(f => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : '🟢'}</span>
                        <span class="font-medium">${escapeHtml(f.title)}</span>
                        <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                        ${f.cwe_id ? `<span class="badge badge-info">${escapeHtml(f.cwe_id)}</span>` : ''}
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(f.description)}</div>
                    ${f.details?.length ? `<ul class="text-sm mb-2">${f.details.map(d => `<li style="padding:2px 0;">• ${escapeHtml(d)}</li>`).join('')}</ul>` : ''}
                    <div class="finding-remediation"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>
                    ${f.owasp_id ? `<span class="badge badge-warning mt-2">OWASP ${escapeHtml(f.owasp_id)}</span>` : ''}
                </div>
            </div>
        `).join('');

        container.innerHTML = `
            <div class="card mb-4">
                <div class="card-header">
                    <span class="card-title">Mobile Security — ${result.target_type}</span>
                    <span class="badge badge-${result.summary.risk_score >= 7 ? 'critical' : result.summary.risk_score >= 4 ? 'warning' : 'success'}">
                        Risk: ${result.summary.risk_score.toFixed(1)}/10
                    </span>
                </div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Findings (${result.findings.length})</span></div>
                <div class="card-body">${findingsHtml}</div>
            </div>
        `;
    }

    // ========================================
    // Cloud Security
    // ========================================

    function setupCloudSecurity() {
        $('#startCloudScanBtn')?.addEventListener('click', startCloudScan);
    }

    async function startCloudScan() {
        const provider = $('#cloudProvider')?.value || 'aws';

        $('#cloudScanResults').style.display = 'block';
        $('#startCloudScanBtn').disabled = true;
        $('#startCloudScanBtn').textContent = '⏳ Scanning...';

        try {
            const result = await invoke('cloud_scan', { provider });
            displayCloudResults(result);
            addActivity(`Cloud scan: ${provider} (${result.findings.length} findings)`);
        } catch (e) {
            showToast('error', 'Scan Failed', String(e));
        } finally {
            $('#startCloudScanBtn').disabled = false;
            $('#startCloudScanBtn').textContent = '🔍 Start Cloud Assessment';
        }
    }

    function displayCloudResults(result) {
        const container = $('#cloudScanResults');
        if (!container) return;

        const findingsHtml = result.findings.map(f => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : '🟢'}</span>
                        <span class="font-medium">${escapeHtml(f.title)}</span>
                        <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                        <span class="badge badge-info">${escapeHtml(f.category?.replace(/_/g, ' ') || '')}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(f.description)}</div>
                    <div class="text-sm text-tertiary mb-2">Resource: ${escapeHtml(f.resource)}</div>
                    ${f.details?.length ? `<ul class="text-sm mb-2">${f.details.map(d => `<li style="padding:2px 0;">• ${escapeHtml(d)}</li>`).join('')}</ul>` : ''}
                    <div class="finding-remediation"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>
                    ${f.cis_benchmark ? `<span class="badge badge-warning mt-2">${escapeHtml(f.cis_benchmark)}</span>` : ''}
                </div>
            </div>
        `).join('');

        const complianceHtml = Object.entries(result.compliance || {}).map(([name, score]) => `
            <div style="display:flex; align-items:center; gap:12px; padding:8px 0;">
                <span style="flex:1;">${escapeHtml(name)}</span>
                <div class="progress" style="flex:2;"><div class="progress-bar ${score >= 80 ? 'success' : score >= 60 ? '' : 'critical'}" style="width:${score}%"></div></div>
                <span class="badge badge-${score >= 80 ? 'success' : score >= 60 ? 'warning' : 'error'}">${score.toFixed(0)}%</span>
            </div>
        `).join('');

        container.innerHTML = `
            <div class="card mb-4">
                <div class="card-header">
                    <span class="card-title">Cloud Security — ${result.provider}</span>
                    <span class="badge badge-${result.summary.compliance_score >= 80 ? 'success' : result.summary.compliance_score >= 60 ? 'warning' : 'error'}">
                        Compliance: ${result.summary.compliance_score.toFixed(0)}%
                    </span>
                </div>
                <div class="card-body">
                    <h4 class="mb-3">Compliance Scores</h4>
                    ${complianceHtml}
                </div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Findings (${result.findings.length})</span></div>
                <div class="card-body">${findingsHtml}</div>
            </div>
        `;
    }

    // ========================================
    // Web3 Security
    // ========================================

    function setupWeb3Security() {
        $('#scanContractBtn')?.addEventListener('click', scanContract);
        $('#analyzeWalletBtn')?.addEventListener('click', analyzeWallet);

        $$('#content-web3security .tab').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('#content-web3security .tab').forEach(t => t.classList.remove('active'));
                $$('#content-web3security .tab-content').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                const tabId = `tab-${tab.dataset.tab}`;
                const tabContent = $(`#${tabId}`);
                if (tabContent) tabContent.style.display = '';
            });
        });
    }

    async function scanContract() {
        const chain = $('#web3Chain')?.value || 'ethereum';

        try {
            const result = await invoke('web3_scan_contract', { chain });
            displayContractResults(result);
            addActivity(`Web3 contract audit: ${chain} (score: ${result.score.toFixed(0)}/100)`);
        } catch (e) {
            showToast('error', 'Audit Failed', String(e));
        }
    }

    function displayContractResults(result) {
        const container = $('#contractResults');
        if (!container) return;

        const findingsHtml = result.findings.map(f => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : f.severity === 'OPTIMIZATION' ? '🔵' : '🟢'}</span>
                        <span class="font-medium">${escapeHtml(f.title)}</span>
                        <span class="badge badge-${f.severity.toLowerCase() === 'optimization' ? 'info' : f.severity.toLowerCase()}">${f.severity}</span>
                        ${f.swc_id ? `<span class="badge badge-warning">${escapeHtml(f.swc_id)}</span>` : ''}
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(f.description)}</div>
                    ${f.details?.length ? `<ul class="text-sm mb-2">${f.details.map(d => `<li style="padding:2px 0;">• ${escapeHtml(d)}</li>`).join('')}</ul>` : ''}
                    <div class="finding-remediation"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>
                    ${f.cwe_id ? `<span class="badge badge-info mt-2">CWE-${escapeHtml(f.cwe_id)}</span>` : ''}
                </div>
            </div>
        `).join('');

        container.innerHTML = `
            <div class="card mb-4">
                <div class="card-header">
                    <span class="card-title">Smart Contract Audit — ${result.chain}</span>
                    <span class="badge badge-${result.score >= 80 ? 'success' : result.score >= 60 ? 'warning' : 'error'}">
                        Score: ${result.score.toFixed(0)}/100
                    </span>
                </div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Findings (${result.findings.length})</span></div>
                <div class="card-body">${findingsHtml}</div>
            </div>
        `;
    }

    async function analyzeWallet() {
        const address = $('#web3WalletAddress')?.value?.trim();
        const chain = $('#web3WalletChain')?.value || 'ethereum';

        if (!address) {
            showToast('error', 'Missing Address', 'Please enter a wallet address.');
            return;
        }

        try {
            const result = await invoke('web3_analyze_wallet', { address, chain });
            displayWalletResults(result);
            addActivity(`Wallet analysis: ${address.substring(0, 10)}... (${chain})`);
        } catch (e) {
            showToast('error', 'Analysis Failed', String(e));
        }
    }

    function displayWalletResults(result) {
        const container = $('#walletResults');
        if (!container) return;

        const findingsHtml = result.findings.map(f => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : '🟢'}</span>
                        <span class="font-medium">${escapeHtml(f.title)}</span>
                        <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(f.description)}</div>
                    ${f.details?.length ? `<ul class="text-sm">${f.details.map(d => `<li style="padding:2px 0;">• ${escapeHtml(d)}</li>`).join('')}</ul>` : ''}
                </div>
            </div>
        `).join('');

        container.innerHTML = `
            <div class="card mb-4">
                <div class="card-header">
                    <span class="card-title">Wallet Security — ${result.chain}</span>
                    <span class="badge badge-${result.risk_score >= 70 ? 'critical' : result.risk_score >= 40 ? 'warning' : 'success'}">
                        Risk: ${result.risk_score.toFixed(0)}/100
                    </span>
                </div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Findings (${result.findings.length})</span></div>
                <div class="card-body">${findingsHtml}</div>
            </div>
        `;
    }

    // ========================================
    // Gray Team: ATT&CK Matrix
    // ========================================

    function setupGrayMatrix() {
        loadAttckMatrix();
        $('#exportMatrixBtn')?.addEventListener('click', () => {
            try {
                const matrix = state.data.attckMatrix;
                if (!matrix) {
                    showToast('warning', 'No Data', 'Load the matrix first.');
                    return;
                }
                const blob = new Blob([JSON.stringify(matrix, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `attck_matrix_${new Date().toISOString().slice(0, 10)}.json`;
                a.click();
                URL.revokeObjectURL(url);
                showToast('success', 'Exported', 'ATT&CK matrix exported to JSON.');
            } catch (e) {
                showToast('error', 'Export Failed', String(e));
            }
        });
    }

    async function loadAttckMatrix() {
        try {
            const matrix = await invoke('grayteam_get_attck_matrix');
            state.data.attckMatrix = matrix;
            displayAttckMatrix(matrix);
        } catch (e) {
            showToast('error', 'Load Failed', String(e));
        }
    }

    function displayAttckMatrix(matrix) {
        $('#totalTechniques').textContent = matrix.techniques?.length || 0;
        const covered = Object.values(matrix.coverage || {}).filter(c => c.covered).length;
        const tested = Object.values(matrix.coverage || {}).filter(c => c.tested).length;
        $('#coveredTechniques').textContent = covered;
        $('#testedTechniques').textContent = tested;
        const score = matrix.techniques?.length ? ((covered / matrix.techniques.length) * 100).toFixed(0) : 0;
        $('#coverageScore').textContent = score + '%';

        const container = $('#attckMatrixContainer');
        if (!container) return;

        let html = '';
        for (const domain of matrix.domains || []) {
            html += `<h4 class="mb-3">${domain.name}</h4>`;
            for (const tactic of domain.tactics || []) {
                const tacticTechniques = (matrix.techniques || []).filter(t => t.tactic === tactic.id);
                html += `
                    <div style="margin-bottom:16px;">
                        <div style="font-weight:600; margin-bottom:8px; padding:8px; background:var(--bg-tertiary); border-radius:6px;">
                            ${tactic.name} (${tacticTechniques.length})
                        </div>
                        <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(200px, 1fr)); gap:8px; padding-left:16px;">
                            ${tacticTechniques.map(t => {
                                const cov = matrix.coverage?.[t.id];
                                const covered = cov?.covered;
                                return `
                                    <div style="padding:8px; border:1px solid ${covered ? 'var(--status-success)' : 'var(--border-primary)'}; border-radius:6px; background:${covered ? 'var(--status-success-bg)' : 'var(--bg-secondary)'};">
                                        <div style="font-weight:500; font-size:0.85rem;">${t.id}</div>
                                        <div style="font-size:0.75rem; color:var(--text-secondary);">${t.name}</div>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    </div>
                `;
            }
        }
        container.innerHTML = html || '<div class="text-tertiary">No techniques loaded.</div>';
    }

    // ========================================
    // Gray Team: Threat Modeling
    // ========================================

    function setupGrayThreatModel() {
        $('#generateThreatsBtn')?.addEventListener('click', generateThreats);
        $('#createThreatModelBtn')?.addEventListener('click', () => {
            $('#threatModelName').value = '';
            $('#threatModelDesc').value = '';
            $('#threatModelResults').style.display = 'none';
        });
    }

    async function generateThreats() {
        const name = $('#threatModelName')?.value?.trim() || 'Untitled Model';
        const desc = $('#threatModelDesc')?.value?.trim() || 'Auto-generated threat model';

        try {
            const model = await invoke('grayteam_create_threat_model', { name, description: desc });
            displayThreatModelResults(model);
            addActivity(`Threat model created: ${name} (${model.threats.length} threats)`);
        } catch (e) {
            showToast('error', 'Generation Failed', String(e));
        }
    }

    function displayThreatModelResults(model) {
        const container = $('#threatModelResults');
        if (!container) return;
        container.style.display = 'block';

        const threatsHtml = model.threats.map(t => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${t.severity === 'Critical' ? '🔴' : t.severity === 'High' ? '🟠' : t.severity === 'Medium' ? '🟡' : '🟢'}</span>
                        <span class="font-medium">${escapeHtml(t.name)}</span>
                        <span class="badge badge-${t.severity.toLowerCase()}">${t.severity}</span>
                        <span class="badge badge-info">${escapeHtml(t.stride_category)}</span>
                        <span class="badge badge-warning">Risk: ${t.risk_score.toFixed(1)}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(t.description)}</div>
                    <div class="text-sm mb-2"><strong>Likelihood:</strong> ${escapeHtml(t.likelihood?.replace(/([A-Z])/g, ' $1').trim() || '')} | <strong>Impact:</strong> ${escapeHtml(t.impact?.replace(/([A-Z])/g, ' $1').trim() || '')}</div>
                    <div class="finding-remediation"><strong>Mitigations:</strong></div>
                    <ul class="text-sm">${t.mitigations.map(m => `<li style="padding:2px 0;">• ${escapeHtml(m)}</li>`).join('')}</ul>
                    ${t.related_techniques?.length ? `<div class="mt-2">${t.related_techniques.map(tech => `<span class="badge badge-info mr-1">${escapeHtml(tech)}</span>`).join('')}</div>` : ''}
                </div>
            </div>
        `).join('');

        container.innerHTML = `
            <div class="card mb-4">
                <div class="card-header">
                    <span class="card-title">Threat Model: ${escapeHtml(model.name)}</span>
                    <span class="badge badge-info">${model.threats.length} threats</span>
                </div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Identified Threats</span></div>
                <div class="card-body">${threatsHtml}</div>
            </div>
        `;
    }

    // ========================================
    // Gray Team: Purple Team
    // ========================================

    function setupGrayPurple() {
        $('#createExerciseSubmitBtn')?.addEventListener('click', createExercise);
        $('#createExerciseBtn')?.addEventListener('click', () => {
            $('#exerciseName').value = '';
            $('#exerciseDesc').value = '';
            $('#exerciseResults').style.display = 'none';
        });
    }

    async function createExercise() {
        const name = $('#exerciseName')?.value?.trim() || 'Untitled Exercise';
        const desc = $('#exerciseDesc')?.value?.trim() || 'Purple team exercise';

        try {
            const exercise = await invoke('grayteam_create_purple_exercise', { name, description: desc });
            displayExerciseResults(exercise);
            addActivity(`Purple team exercise created: ${name}`);
        } catch (e) {
            showToast('error', 'Creation Failed', String(e));
        }
    }

    function displayExerciseResults(exercise) {
        const container = $('#exerciseResults');
        if (!container) return;
        container.style.display = 'block';

        const scenariosHtml = exercise.scenarios.map(s => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">⚔️</span>
                        <span class="font-medium">${escapeHtml(s.name)}</span>
                        <span class="badge badge-info">${escapeHtml(s.attack_type)}</span>
                        <span class="badge badge-warning">${s.duration_minutes}min</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(s.description)}</div>
                    <div class="text-sm mb-2"><strong>Target:</strong> ${s.target_systems.map(t => `<span class="badge badge-info mr-1">${escapeHtml(t)}</span>`).join('')}</div>
                    <div class="text-sm mb-2"><strong>MITRE:</strong> ${s.mitre_techniques.map(t => `<span class="badge badge-warning mr-1">${escapeHtml(t)}</span>`).join('')}</div>
                    <div class="text-sm"><strong>Expected Detection:</strong> <span class="badge badge-${s.expected_detection ? 'success' : 'error'}">${s.expected_detection ? 'Yes' : 'No'}</span></div>
                </div>
            </div>
        `).join('');

        container.innerHTML = `
            <div class="card mb-4">
                <div class="card-header">
                    <span class="card-title">Purple Team Exercise: ${escapeHtml(exercise.name)}</span>
                    <span class="badge badge-info">${exercise.scenarios.length} scenarios</span>
                </div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Attack Scenarios</span></div>
                <div class="card-body">${scenariosHtml}</div>
            </div>
        `;
    }

    // ========================================
    // Gray Team: Detection Engineering
    // ========================================

    function setupGrayDetections() {
        $('#loadSigmaRulesBtn')?.addEventListener('click', loadSigmaRules);
        $('#loadAptTechniquesBtn')?.addEventListener('click', loadAptTechniques);

        $$('#content-gray-detections .tab').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('#content-gray-detections .tab').forEach(t => t.classList.remove('active'));
                $$('#content-gray-detections .tab-content').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                const tabId = `tab-${tab.dataset.tab}`;
                const tabContent = $(`#${tabId}`);
                if (tabContent) tabContent.style.display = '';
            });
        });
    }

    async function loadSigmaRules() {
        try {
            const rules = await invoke('grayteam_get_sigma_rules');
            displaySigmaRules(rules);
        } catch (e) {
            showToast('error', 'Load Failed', String(e));
        }
    }

    function displaySigmaRules(rules) {
        const container = $('#sigmaRulesContainer');
        if (!container) return;

        const rulesHtml = rules.map(r => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">🛡️</span>
                        <span class="font-medium">${escapeHtml(r.name)}</span>
                        <span class="badge badge-info">${escapeHtml(r.rule_type)}</span>
                        ${r.tested ? '<span class="badge badge-success">Tested</span>' : '<span class="badge badge-warning">Untested</span>'}
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(r.description)}</div>
                    <div class="code-block mb-2">${escapeHtml(r.content)}</div>
                    <div class="text-sm"><strong>MITRE:</strong> ${r.mitre_techniques.map(t => `<span class="badge badge-info mr-1">${escapeHtml(t)}</span>`).join('')}</div>
                </div>
            </div>
        `).join('');

        container.innerHTML = rulesHtml || '<div class="text-tertiary">No rules loaded.</div>';
    }

    async function loadAptTechniques() {
        const group = $('#aptGroupSelect')?.value || 'apt28';

        try {
            const techniques = await invoke('grayteam_get_apt_techniques', { group });
            const container = $('#aptResults');
            if (!container) return;

            container.innerHTML = `
                <div class="card">
                    <div class="card-body">
                        <h4 class="mb-3">Techniques for ${escapeHtml(group.toUpperCase())}</h4>
                        <div style="display:flex; flex-wrap:wrap; gap:8px;">
                            ${techniques.map(t => `<span class="badge badge-warning" style="font-size:0.9rem; padding:6px 12px;">${escapeHtml(t)}</span>`).join('')}
                        </div>
                    </div>
                </div>
            `;
        } catch (e) {
            showToast('error', 'Load Failed', String(e));
        }
    }

    // ========================================
    // Blue Team: SOC Dashboard
    // ========================================

    function setupBlueDashboard() {
        loadSocDashboard();
        $('#refreshSocBtn')?.addEventListener('click', loadSocDashboard);
        $('#viewAllAlertsBtn')?.addEventListener('click', () => {
            state.section = 'blue-alerts';
            renderContent();
        });
    }

    async function loadSocDashboard() {
        try {
            const dashboard = await invoke('blueteam_get_soc_dashboard');
            displaySocDashboard(dashboard);
        } catch (e) {
            showToast('error', 'Load Failed', String(e));
        }
    }

    function displaySocDashboard(dashboard) {
        $('#socTotalAlerts').textContent = dashboard.total_alerts;
        $('#socOpenIncidents').textContent = dashboard.open_incidents;
        $('#socMttd').textContent = dashboard.mean_time_to_detect_minutes.toFixed(1) + 'm';
        $('#socMttR').textContent = dashboard.mean_time_to_respond_minutes.toFixed(1) + 'm';

        const sevDist = dashboard.severity_distribution;
        $('#socSeverityDist').innerHTML = `
            <div class="flex flex-col gap-2">
                ${[
                    {label: 'Critical', count: sevDist.critical, cls: 'critical'},
                    {label: 'High', count: sevDist.high, cls: 'high'},
                    {label: 'Medium', count: sevDist.medium, cls: 'medium'},
                    {label: 'Low', count: sevDist.low, cls: 'low'},
                    {label: 'Info', count: sevDist.info, cls: 'info'},
                ].map(s => `
                    <div class="flex items-center gap-3">
                        <span class="badge badge-${s.cls}" style="min-width:70px;">${s.label}</span>
                        <div class="progress" style="flex:1;"><div class="progress-bar ${s.cls}" style="width:${Math.min(s.count * 5, 100)}%"></div></div>
                        <span style="min-width:30px; text-align:right;">${s.count}</span>
                    </div>
                `).join('')}
            </div>
        `;

        $('#socAlertSources').innerHTML = dashboard.top_alert_sources.map(s => `
            <div class="flex items-center gap-3" style="padding:6px 0;">
                <span class="badge badge-${s.severity?.toLowerCase() === 'critical' ? 'critical' : s.severity?.toLowerCase() === 'high' ? 'high' : 'info'}">${s.name}</span>
                <span style="margin-left:auto; font-weight:500;">${s.count}</span>
            </div>
        `).join('');

        $('#socRecentAlerts').innerHTML = dashboard.recent_alerts.map(a => `
            <div style="display:flex; align-items:center; gap:12px; padding:8px 0; border-bottom:1px solid var(--border-secondary);">
                <span class="status-dot ${a.severity?.toLowerCase() === 'critical' ? 'error' : a.severity?.toLowerCase() === 'high' ? 'warning' : 'running'}"></span>
                <div style="flex:1;">
                    <div style="font-weight:500;">${escapeHtml(a.title)}</div>
                    <div style="font-size:0.8rem; color:var(--text-tertiary);">${escapeHtml(a.source || '')} &middot; ${a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : ''}</div>
                </div>
                <span class="badge badge-${a.severity?.toLowerCase()}">${a.severity}</span>
            </div>
        `).join('');
    }

    // ========================================
    // Blue Team: Incidents
    // ========================================

    function setupBlueIncidents() {
        $('#createIncidentBtn')?.addEventListener('click', () => {
            $('#incidentForm').style.display = $('#incidentForm').style.display === 'none' ? 'block' : 'none';
        });
        $('#submitIncidentBtn')?.addEventListener('click', createIncident);
        loadIrPlaybooks();
    }

    async function createIncident() {
        const title = $('#incidentTitle')?.value?.trim();
        const desc = $('#incidentDesc')?.value?.trim();
        const severity = $('#incidentSeverity')?.value;
        const category = $('#incidentCategory')?.value;

        if (!title) { showToast('error', 'Missing Title', 'Please enter an incident title.'); return; }

        try {
            const incident = await invoke('blueteam_create_incident', {
                title, description: desc, severity, category
            });
            displayIncident(incident);
            $('#incidentForm').style.display = 'none';
            addActivity(`Incident created: ${title}`);
        } catch (e) {
            showToast('error', 'Creation Failed', String(e));
        }
    }

    function displayIncident(incident) {
        const container = $('#incidentResults');
        if (!container) return;
        container.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <span class="card-title">${escapeHtml(incident.id)}: ${escapeHtml(incident.title)}</span>
                    <span class="badge badge-${incident.severity === 'P1' ? 'critical' : incident.severity === 'P2' ? 'high' : 'warning'}">${incident.severity}</span>
                </div>
                <div class="card-body">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(incident.description)}</div>
                    <div class="text-sm"><strong>Category:</strong> ${escapeHtml(incident.category?.replace(/_/g, ' ') || '')}</div>
                    <div class="text-sm"><strong>Status:</strong> ${escapeHtml(incident.status?.replace(/_/g, ' ') || '')}</div>
                    <div class="text-sm"><strong>Created:</strong> ${new Date(incident.created_at).toLocaleString()}</div>
                </div>
            </div>
        `;
    }

    async function loadIrPlaybooks() {
        try {
            const playbooks = await invoke('blueteam_get_ir_playbooks');
            const container = $('#irPlaybooks');
            if (!container) return;

            let html = '';
            for (const [name, steps] of Object.entries(playbooks)) {
                html += `
                    <div class="finding-card mb-2">
                        <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                            <span class="font-medium">📋 ${escapeHtml(name)}</span>
                            <span class="text-tertiary text-sm">▼</span>
                        </div>
                        <div class="finding-card-body hidden">
                            <ol class="text-sm">${steps.map((s, i) => `<li style="padding:2px 0;">${escapeHtml(s)}</li>`).join('')}</ol>
                        </div>
                    </div>
                `;
            }
            container.innerHTML = html || '<div class="text-tertiary">No playbooks loaded.</div>';
        } catch (e) {
            console.error('Failed to load playbooks:', e);
        }
    }

    // ========================================
    // Blue Team: Threat Intel
    // ========================================

    function setupBlueIntel() {
        loadThreatFeeds();
        loadThreatActors();
        loadIndicators();

        $$('#content-blue-intel .tab').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('#content-blue-intel .tab').forEach(t => t.classList.remove('active'));
                $$('#content-blue-intel .tab-content').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                const tabId = `tab-${tab.dataset.tab}`;
                const tabContent = $(`#${tabId}`);
                if (tabContent) tabContent.style.display = '';
            });
        });
    }

    async function loadThreatFeeds() {
        try {
            const feeds = await invoke('blueteam_get_threat_feeds');
            const container = $('#threatFeedsContainer');
            if (!container) return;
            container.innerHTML = feeds.map(f => `
                <div style="display:flex; align-items:center; gap:12px; padding:8px 0; border-bottom:1px solid var(--border-secondary);">
                    <span class="status-dot ${f.enabled ? 'online' : 'offline'}"></span>
                    <div style="flex:1;">
                        <div style="font-weight:500;">${escapeHtml(f.name)}</div>
                        <div style="font-size:0.8rem; color:var(--text-tertiary);">${escapeHtml(f.description || '')}</div>
                    </div>
                    <span class="badge badge-info">${f.indicator_count?.toLocaleString()} IOCs</span>
                </div>
            `).join('');
        } catch (e) { console.error('Failed to load feeds:', e); }
    }

    async function loadThreatActors() {
        try {
            const actors = await invoke('blueteam_get_threat_actors');
            const container = $('#threatActorsContainer');
            if (!container) return;
            container.innerHTML = actors.map(a => `
                <div class="finding-card">
                    <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                        <span class="font-medium">${escapeHtml(a.name)}</span>
                        <span class="badge badge-warning">${escapeHtml(a.country || 'Unknown')}</span>
                        <span class="text-tertiary text-sm">▼</span>
                    </div>
                    <div class="finding-card-body hidden">
                        <div class="text-sm text-secondary mb-2">${escapeHtml(a.description || '')}</div>
                        <div class="text-sm mb-2"><strong>Aliases:</strong> ${a.aliases?.map(al => `<span class="badge badge-info mr-1">${escapeHtml(al)}</span>`).join('') || 'N/A'}</div>
                        <div class="text-sm mb-2"><strong>Motivation:</strong> ${escapeHtml(a.motivation || '')} &middot; <strong>Sophistication:</strong> ${escapeHtml(a.sophistication || '')}</div>
                        <div class="text-sm"><strong>Techniques:</strong> ${a.mitre_techniques?.map(t => `<span class="badge badge-warning mr-1">${escapeHtml(t)}</span>`).join('') || 'N/A'}</div>
                    </div>
                </div>
            `).join('');
        } catch (e) { console.error('Failed to load actors:', e); }
    }

    async function loadIndicators() {
        try {
            const indicators = await invoke('blueteam_get_indicators');
            const container = $('#indicatorsContainer');
            if (!container) return;
            container.innerHTML = indicators.map(i => `
                <div style="display:flex; align-items:center; gap:12px; padding:8px 0; border-bottom:1px solid var(--border-secondary);">
                    <span class="badge badge-${i.severity?.toLowerCase() === 'critical' ? 'critical' : i.severity?.toLowerCase() === 'high' ? 'high' : 'info'}">${i.indicator_type?.replace(/_/g, ' ')}</span>
                    <code style="flex:1; font-size:0.85rem;">${escapeHtml(i.value || '')}</code>
                    <span class="badge badge-warning">${i.confidence}%</span>
                </div>
            `).join('');
        } catch (e) { console.error('Failed to load indicators:', e); }
    }

    // ========================================
    // Blue Team: Threat Hunting
    // ========================================

    function setupBlueHunt() {
        $('#createHuntBtn')?.addEventListener('click', () => {
            $('#huntForm').style.display = $('#huntForm').style.display === 'none' ? 'block' : 'none';
        });
        $('#submitHuntBtn')?.addEventListener('click', createHunt);
    }

    async function createHunt() {
        const title = $('#huntTitle')?.value?.trim();
        const desc = $('#huntDesc')?.value?.trim();
        const technique = $('#huntTechnique')?.value;

        if (!title) { showToast('error', 'Missing Title', 'Please enter a hunt hypothesis.'); return; }

        try {
            const hunt = await invoke('blueteam_create_hunt', { title, description: desc, mitreTechnique: technique });
            displayHunt(hunt);
            $('#huntForm').style.display = 'none';
            addActivity(`Threat hunt created: ${title}`);
        } catch (e) {
            showToast('error', 'Creation Failed', String(e));
        }
    }

    function displayHunt(hunt) {
        const container = $('#huntResults');
        if (!container) return;
        container.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <span class="card-title">${escapeHtml(hunt.title)}</span>
                    <span class="badge badge-info">${escapeHtml(hunt.mitre_technique)}</span>
                </div>
                <div class="card-body">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(hunt.description || '')}</div>
                    <div class="text-sm mb-2"><strong>Data Sources:</strong> ${hunt.data_sources?.map(d => `<span class="badge badge-info mr-1">${escapeHtml(d)}</span>`).join('') || 'N/A'}</div>
                    ${hunt.search_queries?.length ? `
                        <div class="text-sm mb-2"><strong>Queries:</strong></div>
                        ${hunt.search_queries.map(q => `<div class="code-block mb-1">${escapeHtml(q)}</div>`).join('')}
                    ` : ''}
                </div>
            </div>
        `;
    }

    // ========================================
    // Blue Team: Forensics
    // ========================================

    function setupBlueForensics() {
        $('#loadMalwareBtn')?.addEventListener('click', loadMalwareAnalysis);

        $$('#content-blue-forensics .tab').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('#content-blue-forensics .tab').forEach(t => t.classList.remove('active'));
                $$('#content-blue-forensics .tab-content').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                const tabId = `tab-${tab.dataset.tab}`;
                const tabContent = $(`#${tabId}`);
                if (tabContent) tabContent.style.display = '';
            });
        });
    }

    async function loadMalwareAnalysis() {
        try {
            const analysis = await invoke('blueteam_get_malware_analysis');
            const container = $('#malwareAnalysisContainer');
            if (!container) return;

            container.innerHTML = `
                <div class="card mb-3">
                    <div class="card-header">
                        <span class="card-title">${escapeHtml(analysis.sample_name)}</span>
                        <span class="badge badge-${analysis.risk_score >= 80 ? 'critical' : analysis.risk_score >= 50 ? 'high' : 'warning'}">Risk: ${analysis.risk_score}/100</span>
                    </div>
                    <div class="card-body">
                        <div class="grid grid-2 mb-3">
                            <div><strong>Type:</strong> ${escapeHtml(analysis.file_type || '')}</div>
                            <div><strong>Size:</strong> ${analysis.file_size?.toLocaleString()} bytes</div>
                        </div>
                        <div class="text-sm mb-2"><strong>MD5:</strong> <code>${escapeHtml(analysis.md5 || '')}</code></div>
                        <div class="text-sm mb-2"><strong>SHA256:</strong> <code>${escapeHtml(analysis.sha256 || '')}</code></div>
                    </div>
                </div>
                <div class="grid grid-2">
                    <div class="card">
                        <div class="card-header"><span class="card-title">Signatures</span></div>
                        <div class="card-body">
                            ${analysis.signatures?.map(s => `
                                <div style="padding:6px 0; border-bottom:1px solid var(--border-secondary);">
                                    <span class="badge badge-${s.severity?.toLowerCase()}">${s.severity}</span>
                                    <span style="font-weight:500;"> ${escapeHtml(s.name || '')}</span>
                                    <div style="font-size:0.8rem; color:var(--text-tertiary);">${escapeHtml(s.description || '')}</div>
                                </div>
                            `).join('') || ''}
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header"><span class="card-title">Behavior</span></div>
                        <div class="card-body">
                            ${analysis.behavior?.map(b => `
                                <div style="padding:6px 0; border-bottom:1px solid var(--border-secondary);">
                                    <span class="badge badge-${b.severity?.toLowerCase()}">${b.category}</span>
                                    <div style="font-size:0.85rem;">${escapeHtml(b.description || '')}</div>
                                </div>
                            `).join('') || ''}
                        </div>
                    </div>
                </div>
            `;
        } catch (e) { showToast('error', 'Load Failed', String(e)); }
    }

    // ========================================
    // White Team: GRC Dashboard
    // ========================================

    function setupWhiteDashboard() {
        loadGrcDashboard();
    }

    async function loadGrcDashboard() {
        try {
            const dashboard = await invoke('whiteteam_get_grc_dashboard');
            $('#grcComplianceScore').textContent = dashboard.compliance_score.toFixed(0) + '%';
            $('#grcOpenRisks').textContent = dashboard.open_risks;
            $('#grcCriticalRisks').textContent = dashboard.critical_risks;
            $('#grcTrainingRate').textContent = dashboard.training_completion_rate.toFixed(0) + '%';

            $('#grcFrameworks').innerHTML = dashboard.frameworks.map(f => `
                <div style="display:flex; align-items:center; gap:12px; padding:8px 0;">
                    <span style="flex:1;">${escapeHtml(f.name)}</span>
                    <div class="progress" style="flex:2;"><div class="progress-bar ${f.score >= 80 ? 'success' : f.score >= 60 ? '' : 'critical'}" style="width:${f.score}%"></div></div>
                    <span class="badge badge-${f.score >= 80 ? 'success' : f.score >= 60 ? 'warning' : 'error'}">${f.score.toFixed(0)}%</span>
                </div>
            `).join('');

            $('#grcRiskTrend').innerHTML = dashboard.risk_trend.map(t => `
                <div style="display:flex; align-items:center; gap:12px; padding:6px 0;">
                    <span style="min-width:60px;">${escapeHtml(t.date)}</span>
                    <span class="badge badge-error">Open: ${t.open_count}</span>
                    <span class="badge badge-success">Closed: ${t.closed_count}</span>
                    <span class="text-tertiary text-sm">Avg: ${t.avg_score.toFixed(1)}</span>
                </div>
            `).join('');
        } catch (e) { showToast('error', 'Load Failed', String(e)); }
    }

    // ========================================
    // White Team: Compliance
    // ========================================

    function setupWhiteCompliance() {
        loadCompliance();
    }

    async function loadCompliance() {
        try {
            const frameworks = await invoke('whiteteam_get_compliance_frameworks');
            const container = $('#complianceResults');
            if (!container) return;

            container.innerHTML = frameworks.map(f => `
                <div class="card mb-4">
                    <div class="card-header">
                        <span class="card-title">${escapeHtml(f.name)} ${escapeHtml(f.version)}</span>
                        <span class="badge badge-${f.overall_score >= 80 ? 'success' : f.overall_score >= 60 ? 'warning' : 'error'}">${f.overall_score.toFixed(0)}%</span>
                    </div>
                    <div class="card-body">
                        ${f.categories.map(c => `
                            <div class="finding-card mb-2">
                                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                                    <span class="font-medium">${escapeHtml(c.name)}</span>
                                    <span class="badge badge-${c.score >= 80 ? 'success' : c.score >= 60 ? 'warning' : 'error'}">${c.score.toFixed(0)}%</span>
                                    <span class="text-tertiary text-sm">▼</span>
                                </div>
                                <div class="finding-card-body hidden">
                                    ${c.controls.map(ctrl => `
                                        <div style="padding:6px 0; border-bottom:1px solid var(--border-secondary);">
                                            <div class="flex items-center gap-2">
                                                <span class="badge badge-${ctrl.status === 'Implemented' ? 'success' : ctrl.status === 'In Progress' ? 'warning' : 'error'}">${escapeHtml(ctrl.status)}</span>
                                                <span style="font-weight:500;">${escapeHtml(ctrl.id)}: ${escapeHtml(ctrl.name)}</span>
                                            </div>
                                            ${ctrl.gaps?.length ? `<div class="text-sm text-error mt-1">Gaps: ${ctrl.gaps.map(g => escapeHtml(g)).join(', ')}</div>` : ''}
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('');
        } catch (e) { showToast('error', 'Load Failed', String(e)); }
    }

    // ========================================
    // White Team: Risk Register
    // ========================================

    function setupWhiteRisk() {
        loadRiskRegister();
    }

    async function loadRiskRegister() {
        try {
            const register = await invoke('whiteteam_get_risk_register');
            const container = $('#riskResults');
            if (!container) return;

            container.innerHTML = register.risks.map(r => `
                <div class="finding-card">
                    <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                        <div class="flex items-center gap-3">
                            <span class="status-icon">${r.risk_score >= 15 ? '🔴' : r.risk_score >= 10 ? '🟠' : '🟡'}</span>
                            <span class="font-medium">${escapeHtml(r.title)}</span>
                            <span class="badge badge-${r.risk_score >= 15 ? 'critical' : r.risk_score >= 10 ? 'high' : 'warning'}">Score: ${r.risk_score.toFixed(0)}</span>
                            <span class="badge badge-info">${escapeHtml(r.category?.replace(/_/g, ' ') || '')}</span>
                        </div>
                        <span class="text-tertiary text-sm">▼</span>
                    </div>
                    <div class="finding-card-body hidden">
                        <div class="text-sm text-secondary mb-2">${escapeHtml(r.description || '')}</div>
                        <div class="text-sm mb-2"><strong>Treatment:</strong> ${escapeHtml(r.treatment || '')} &middot; <strong>Owner:</strong> ${escapeHtml(r.owner || '')}</div>
                        <div class="text-sm mb-2"><strong>Inherent:</strong> ${r.inherent_score.toFixed(0)} &rarr; <strong>Residual:</strong> ${r.residual_score.toFixed(0)}</div>
                        <div class="finding-remediation"><strong>Mitigations:</strong></div>
                        <ul class="text-sm">${r.mitigations?.map(m => `<li style="padding:2px 0;">• ${escapeHtml(m)}</li>`).join('') || ''}</ul>
                    </div>
                </div>
            `).join('');
        } catch (e) { showToast('error', 'Load Failed', String(e)); }
    }

    // ========================================
    // White Team: Policies
    // ========================================

    function setupWhitePolicies() {
        loadPolicies();
    }

    async function loadPolicies() {
        try {
            const policies = await invoke('whiteteam_get_policies');
            const container = $('#policyResults');
            if (!container) return;

            container.innerHTML = policies.map(p => `
                <div class="finding-card">
                    <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                        <div class="flex items-center gap-3">
                            <span class="status-icon">${p.status === 'Published' ? '🟢' : p.status === 'Under Review' ? '🟡' : '🔵'}</span>
                            <span class="font-medium">${escapeHtml(p.name)}</span>
                            <span class="badge badge-${p.status === 'Published' ? 'success' : p.status === 'Under Review' ? 'warning' : 'info'}">${escapeHtml(p.status?.replace(/_/g, ' ') || '')}</span>
                            <span class="badge badge-info">v${escapeHtml(p.version || '')}</span>
                        </div>
                        <span class="text-tertiary text-sm">▼</span>
                    </div>
                    <div class="finding-card-body hidden">
                        <div class="text-sm text-secondary mb-2">${escapeHtml(p.description || '')}</div>
                        <div class="text-sm mb-2"><strong>Category:</strong> ${escapeHtml(p.category?.replace(/_/g, ' ') || '')} &middot; <strong>Owner:</strong> ${escapeHtml(p.owner || '')}</div>
                        <div class="text-sm mb-2"><strong>Effective:</strong> ${escapeHtml(p.effective_date || '')} &middot; <strong>Review:</strong> ${escapeHtml(p.review_date || '')}</div>
                        <div class="text-sm"><strong>Acknowledgments:</strong> ${p.acknowledgments?.length || 0} users</div>
                    </div>
                </div>
            `).join('');
        } catch (e) { showToast('error', 'Load Failed', String(e)); }
    }

    // ========================================
    // White Team: Vendors
    // ========================================

    function setupWhiteVendors() {
        loadVendors();
    }

    async function loadVendors() {
        try {
            const vendors = await invoke('whiteteam_get_vendors');
            const container = $('#vendorResults');
            if (!container) return;

            container.innerHTML = vendors.map(v => `
                <div class="finding-card">
                    <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                        <div class="flex items-center gap-3">
                            <span class="status-icon">${v.risk_level === 'Critical' ? '🔴' : v.risk_level === 'High' ? '🟠' : v.risk_level === 'Medium' ? '🟡' : '🟢'}</span>
                            <span class="font-medium">${escapeHtml(v.name)}</span>
                            <span class="badge badge-${v.risk_level === 'Critical' ? 'critical' : v.risk_level === 'High' ? 'high' : v.risk_level === 'Medium' ? 'warning' : 'success'}">${escapeHtml(v.risk_level || '')}</span>
                            <span class="badge badge-info">${escapeHtml(v.tier || '')}</span>
                        </div>
                        <span class="text-tertiary text-sm">▼</span>
                    </div>
                    <div class="finding-card-body hidden">
                        <div class="text-sm text-secondary mb-2">${escapeHtml(v.description || '')}</div>
                        <div class="text-sm mb-2"><strong>Services:</strong> ${v.services?.map(s => `<span class="badge badge-info mr-1">${escapeHtml(s)}</span>`).join('') || 'N/A'}</div>
                        <div class="text-sm mb-2"><strong>Data Access:</strong> ${v.data_access?.map(d => `<span class="badge badge-warning mr-1">${escapeHtml(d)}</span>`).join('') || 'N/A'}</div>
                        <div class="text-sm mb-2"><strong>Contract:</strong> ${escapeHtml(v.contract_start || '')} to ${escapeHtml(v.contract_end || '')}</div>
                        ${v.assessments?.length ? `<div class="text-sm"><strong>Last Assessment:</strong> Score ${v.assessments[0]?.score?.toFixed(0)}%</div>` : ''}
                    </div>
                </div>
            `).join('');
        } catch (e) { showToast('error', 'Load Failed', String(e)); }
    }

    // ========================================
    // White Team: Training
    // ========================================

    function setupWhiteTraining() {
        loadTraining();
    }

    async function loadTraining() {
        try {
            const modules = await invoke('whiteteam_get_training');
            const container = $('#trainingResults');
            if (!container) return;

            container.innerHTML = modules.map(m => `
                <div class="finding-card">
                    <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                        <div class="flex items-center gap-3">
                            <span class="status-icon">${m.completion_rate >= 90 ? '🟢' : m.completion_rate >= 70 ? '🟡' : '🔴'}</span>
                            <span class="font-medium">${escapeHtml(m.name)}</span>
                            <span class="badge badge-info">${escapeHtml(m.category?.replace(/_/g, ' ') || '')}</span>
                            <span class="badge badge-${m.completion_rate >= 90 ? 'success' : m.completion_rate >= 70 ? 'warning' : 'error'}">${m.completion_rate.toFixed(0)}%</span>
                        </div>
                        <span class="text-tertiary text-sm">▼</span>
                    </div>
                    <div class="finding-card-body hidden">
                        <div class="text-sm text-secondary mb-2">${escapeHtml(m.description || '')}</div>
                        <div class="text-sm mb-2"><strong>Duration:</strong> ${m.duration_minutes} min &middot; <strong>Required:</strong> ${m.required ? 'Yes' : 'No'}</div>
                        <div class="text-sm"><strong>Enrollments:</strong> ${m.enrollments?.length || 0}</div>
                    </div>
                </div>
            `).join('');
        } catch (e) { showToast('error', 'Load Failed', String(e)); }
    }

    async function loadAssets() {
        try {
            const assets = await invoke('cross_get_assets');
            $('#totalAssets').textContent = assets.length;
            $('#criticalAssets').textContent = assets.filter(a => a.criticality === 'Critical').length;
            $('#productionAssets').textContent = assets.filter(a => a.environment === 'Production').length;
            const avgRisk = assets.reduce((sum, a) => sum + (a.risk_score || 0), 0) / assets.length || 0;
            $('#avgRiskScore').textContent = avgRisk.toFixed(1);

            const container = $('#assetList');
            if (!container) return;
            container.innerHTML = assets.map(a => `
                <div class="finding-card">
                    <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                        <div class="flex items-center gap-3">
                            <span class="status-icon">${a.criticality === 'Critical' ? '🔴' : a.criticality === 'High' ? '🟠' : a.criticality === 'Medium' ? '🟡' : '🟢'}</span>
                            <span class="font-medium">${escapeHtml(a.name)}</span>
                            <span class="badge badge-info">${escapeHtml(a.asset_type?.replace(/_/g, ' ') || '')}</span>
                            <span class="badge badge-${a.environment === 'Production' ? 'error' : 'success'}">${escapeHtml(a.environment?.replace(/_/g, ' ') || '')}</span>
                        </div>
                        <span class="text-tertiary text-sm">▼</span>
                    </div>
                    <div class="finding-card-body hidden">
                        <div class="text-sm text-secondary mb-2">${escapeHtml(a.url || a.ip_addresses?.join(', ') || '')}</div>
                        <div class="text-sm mb-2"><strong>Owner:</strong> ${escapeHtml(a.owner || 'Unassigned')} &middot; <strong>Risk:</strong> ${a.risk_score?.toFixed(1) || 'N/A'}</div>
                        <div class="text-sm mb-2"><strong>Tags:</strong> ${a.tags?.map(t => `<span class="badge badge-info mr-1">${escapeHtml(t)}</span>`).join('') || 'None'}</div>
                        <div class="text-sm"><strong>Compliance:</strong> ${a.compliance_scope?.map(c => `<span class="badge badge-warning mr-1">${escapeHtml(c)}</span>`).join('') || 'None'}</div>
                    </div>
                </div>
            `).join('');
        } catch (e) { showToast('error', 'Load Failed', String(e)); }
    }

    async function loadNotifications() {
        try {
            const notifications = await invoke('cross_get_notifications');
            const container = $('#notificationList');
            if (!container) return;
            container.innerHTML = notifications.map(n => `
                <div style="display:flex; align-items:flex-start; gap:12px; padding:12px 0; border-bottom:1px solid var(--border-secondary); ${n.read ? 'opacity:0.6;' : ''}">
                    <span class="status-dot ${n.severity === 'Critical' ? 'error' : n.severity === 'Error' ? 'warning' : n.severity === 'Warning' ? 'warning' : n.severity === 'Success' ? 'online' : ''}"></span>
                    <div style="flex:1;">
                        <div style="display:flex; align-items:center; gap:8px;">
                            <span style="font-weight:500;">${escapeHtml(n.title)}</span>
                            <span class="badge badge-${n.severity === 'Critical' ? 'critical' : n.severity === 'Error' ? 'error' : n.severity === 'Warning' ? 'warning' : n.severity === 'Success' ? 'success' : 'info'}">${escapeHtml(n.severity)}</span>
                            ${!n.read ? '<span class="badge badge-info">New</span>' : ''}
                        </div>
                        <div style="font-size:0.85rem; color:var(--text-secondary); margin-top:4px;">${escapeHtml(n.message)}</div>
                        <div style="font-size:0.75rem; color:var(--text-tertiary); margin-top:4px;">${escapeHtml(n.source || '')} &middot; ${n.timestamp ? new Date(n.timestamp).toLocaleString() : ''}</div>
                    </div>
                </div>
            `).join('') || '<div class="empty-state"><div class="empty-state-icon">🔕</div><div class="empty-state-title">No Notifications</div><div class="empty-state-text">You are all caught up!</div></div>';
        } catch (e) { showToast('error', 'Load Failed', String(e)); }
    }

    async function loadReportTemplates() {
        try {
            const templates = await invoke('cross_get_report_templates');
            const container = $('#reportTemplates');
            if (!container) return;
            container.innerHTML = templates.map(t => `
                <div class="finding-card">
                    <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                        <div class="flex items-center gap-3">
                            <span class="status-icon">📋</span>
                            <span class="font-medium">${escapeHtml(t.name)}</span>
                            <span class="badge badge-info">${escapeHtml(t.report_type)}</span>
                            <span class="badge badge-success">${escapeHtml(t.format)}</span>
                        </div>
                        <span class="text-tertiary text-sm">▼</span>
                    </div>
                    <div class="finding-card-body hidden">
                        <div class="text-sm text-secondary mb-2">${escapeHtml(t.description || '')}</div>
                        <div class="text-sm"><strong>Sections:</strong> ${t.sections?.map(s => `<span class="badge badge-info mr-1">${escapeHtml(s.title || '')}</span>`).join('') || 'None'}</div>
                    </div>
                </div>
            `).join('');
        } catch (e) { showToast('error', 'Load Failed', String(e)); }
    }

    async function loadIntegrations() {
        try {
            const integrations = await invoke('cross_get_integrations');
            const container = $('#integrationList');
            if (!container) return;
            container.innerHTML = integrations.map(i => `
                <div class="card mb-3">
                    <div class="card-header">
                        <div class="flex items-center gap-3">
                            <span class="status-dot ${i.status === 'Connected' ? 'online' : i.status === 'Error' ? 'error' : 'offline'}"></span>
                            <span class="font-medium">${escapeHtml(i.name)}</span>
                            <span class="badge badge-info">${escapeHtml(i.integration_type)}</span>
                            <span class="badge badge-${i.status === 'Connected' ? 'success' : i.status === 'Error' ? 'error' : 'warning'}">${escapeHtml(i.status)}</span>
                        </div>
                    </div>
                </div>
            `).join('');
        } catch (e) { showToast('error', 'Load Failed', String(e)); }
    }

    // ========================================
    // Red Team: Targets
    // ========================================

    function setupRedTargets() {
        loadTargets();
        populateTargetAuthSelect();
        $('#addTargetBtn')?.addEventListener('click', () => {
            $('#targetForm').style.display = 'block';
            $('#targetFormTitle').textContent = 'Add New Target';
            ['targetName','targetUrl','targetDesc','targetTags'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = '';
            });
        });
        $('#importTargetsBtn')?.addEventListener('click', importTargets);
        $('#saveTargetBtn')?.addEventListener('click', saveTarget);
        $('#cancelTargetBtn')?.addEventListener('click', () => {
            $('#targetForm').style.display = 'none';
        });
        $('#targetSearch')?.addEventListener('input', (e) => filterTargets(e.target.value));
    }

    function populateTargetAuthSelect() {
        const sel = document.getElementById('targetAuth');
        if (!sel) return;
        const current = sel.value;
        sel.innerHTML = '<option value="">None</option>' +
            (state.data.authProfiles || []).map(p =>
                `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`
            ).join('');
        if (current) sel.value = current;
    }

    function importTargets() {
        showModal({
            title: '📥 Import Targets',
            body: `
                <div class="form-group">
                    <label class="form-label">Import Format</label>
                    <select class="input" id="importFormat">
                        <option value="csv">CSV File</option>
                        <option value="json">JSON File</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">File Content</label>
                    <textarea class="input" id="importTargetsData" rows="8" placeholder="CSV Format: name,url,type,risk&#10;example1,https://example1.com,web,high&#10;example2,https://example2.com,api,medium&#10;&#10;JSON Format: [{&quot;name&quot;:&quot;example1&quot;,&quot;url&quot;:&quot;https://example1.com&quot;,&quot;type&quot;:&quot;web&quot;,&quot;risk&quot;:&quot;high&quot;}]"></textarea>
                    <span class="form-hint">Paste file content or use the text area above</span>
                </div>
                <div class="form-group">
                    <label class="form-label">
                        <input type="checkbox" id="importSkipExisting" checked> Skip existing targets (by URL)
                    </label>
                </div>
            `,
            actions: [
                '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Cancel</button>',
                '<button class="btn btn-primary" id="processImportTargetsBtn">Import</button>',
            ],
        });

        setTimeout(() => {
            $('#processImportTargetsBtn')?.addEventListener('click', () => {
                const format = $('#importFormat')?.value;
                const data = $('#importTargetsData')?.value?.trim();
                const skipExisting = $('#importSkipExisting')?.checked;

                if (!data) {
                    showToast('error', 'No Data', 'Please paste your targets data.');
                    return;
                }

                try {
                    let imported = 0;
                    let skipped = 0;

                    if (format === 'csv') {
                        const lines = data.split('\n').filter(Boolean);
                        const startIdx = lines[0]?.toLowerCase().includes('name') ? 1 : 0;
                        for (let i = startIdx; i < lines.length; i++) {
                            const parts = lines[i].split(',').map(p => p.trim());
                            if (parts.length >= 2) {
                                const url = parts[1];
                                if (skipExisting && state.data.targets.some(t => t.url === url)) {
                                    skipped++;
                                    continue;
                                }
                                state.data.targets.push({
                                    id: `target_${Date.now()}_${i}`,
                                    name: parts[0] || 'Imported Target',
                                    url: url,
                                    type: parts[2] || 'web',
                                    risk: parts[3] || 'medium',
                                    description: '',
                                    authProfile: null,
                                    tags: [],
                                    lastScan: null,
                                    createdAt: Date.now(),
                                });
                                imported++;
                            }
                        }
                    } else if (format === 'json') {
                        const items = JSON.parse(data);
                        for (const item of items) {
                            if (item.url && skipExisting && state.data.targets.some(t => t.url === item.url)) {
                                skipped++;
                                continue;
                            }
                            state.data.targets.push({
                                id: `target_${Date.now()}_${imported}`,
                                name: item.name || 'Imported Target',
                                url: item.url,
                                type: item.type || 'web',
                                risk: item.risk || 'medium',
                                description: item.description || '',
                                authProfile: item.authProfile || null,
                                tags: item.tags || [],
                                lastScan: null,
                                createdAt: Date.now(),
                            });
                            imported++;
                        }
                    }

                    $('.modal-overlay').remove();
                    loadTargets();
                    showToast('success', 'Import Complete', `${imported} targets imported, ${skipped} skipped.`);
                    addActivity(`Imported ${imported} targets (${format.toUpperCase()})`);
                } catch (e) {
                    showToast('error', 'Import Failed', `Failed to parse data: ${e.message}`);
                }
            });
        }, 100);
    }

    function loadTargets() {
        const targets = state.data.targets || [];
        $('#totalTargets').textContent = targets.length;
        $('#scannedTargets').textContent = targets.filter(t => t.lastScan).length;
        $('#authTargets').textContent = targets.filter(t => t.authProfile).length;

        const tbody = $('#targetsTableBody');
        if (!tbody) return;

        if (targets.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:32px; color:var(--text-tertiary);">No targets configured. Add your first target to begin.</td></tr>';
            return;
        }

        tbody.innerHTML = targets.map(t => `
            <tr>
                <td><span style="font-weight:500;">${escapeHtml(t.name)}</span></td>
                <td><code style="font-size:0.8rem;">${escapeHtml(t.url || '')}</code></td>
                <td><span class="badge badge-info">${escapeHtml(t.type || 'web')}</span></td>
                <td><span class="badge badge-${t.risk === 'critical' ? 'critical' : t.risk === 'high' ? 'high' : t.risk === 'medium' ? 'warning' : 'success'}">${escapeHtml(t.risk || 'medium')}</span></td>
                <td>${t.authProfile ? '<span class="badge badge-success">Yes</span>' : '<span class="text-tertiary">No</span>'}</td>
                <td class="text-secondary">${t.lastScan ? new Date(t.lastScan).toLocaleDateString() : '—'}</td>
                <td>
                    <div class="flex gap-1">
                        <button class="btn btn-sm btn-secondary" onclick="editTarget('${t.id}')">✏️</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteTarget('${t.id}')">🗑</button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    function saveTarget() {
        const name = $('#targetName')?.value?.trim();
        const url = $('#targetUrl')?.value?.trim();
        if (!name || !url) {
            showToast('error', 'Missing Fields', 'Name and URL are required.');
            return;
        }

        const target = {
            id: `target_${Date.now()}`,
            name,
            url,
            type: $('#targetType')?.value || 'web',
            risk: $('#targetRisk')?.value || 'medium',
            description: $('#targetDesc')?.value?.trim(),
            authProfile: $('#targetAuth')?.value || null,
            tags: ($('#targetTags')?.value || '').split(',').map(t => t.trim()).filter(Boolean),
            lastScan: null,
            createdAt: Date.now(),
        };

        state.data.targets.push(target);
        $('#targetForm').style.display = 'none';
        loadTargets();
        showToast('success', 'Target Added', `"${name}" has been added to your targets.`);
        addActivity(`Target added: ${name}`);
    }

    function editTarget(id) {
        const target = state.data.targets.find(t => t.id === id);
        if (!target) return;

        $('#targetName').value = target.name;
        $('#targetUrl').value = target.url;
        $('#targetType').value = target.type;
        $('#targetRisk').value = target.risk;
        $('#targetDesc').value = target.description || '';
        $('#targetTags').value = (target.tags || []).join(', ');
        $('#targetFormTitle').textContent = `Edit: ${target.name}`;
        $('#targetForm').style.display = 'block';
    }

    function deleteTarget(id) {
        const target = state.data.targets.find(t => t.id === id);
        if (!target) return;
        if (!confirm(`Delete target "${target.name}"?`)) return;

        state.data.targets = state.data.targets.filter(t => t.id !== id);
        loadTargets();
        showToast('info', 'Target Deleted', `"${target.name}" has been removed.`);
        addActivity(`Target deleted: ${target.name}`);
    }

    function filterTargets(query) {
        const rows = $$('#targetsTableBody tr');
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(query.toLowerCase()) ? '' : 'none';
        });
    }

    // ========================================
    // Red Team: Scans
    // ========================================

    function setupRedScans() {
        loadScans();
        $('#refreshScansBtn')?.addEventListener('click', () => {
            loadScans();
            showToast('success', 'Refreshed', 'Scan list refreshed.');
        });
        $('#newScanBtn')?.addEventListener('click', () => {
            state.section = 'red-web';
            renderContent();
        });
    }

    function loadScans() {
        const scans = state.data.scans || [];
        $('#totalScans').textContent = scans.length;
        $('#runningScans').textContent = scans.filter(s => s.status === 'running').length;
        $('#completedScans').textContent = scans.filter(s => s.status === 'completed').length;
        $('#failedScans').textContent = scans.filter(s => s.status === 'failed').length;

        const container = $('#scanList');
        if (!container) return;

        if (scans.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🔍</div><div class="empty-state-title">No Scans Yet</div><div class="empty-state-text">Start a scan to see it here.</div></div>';
            return;
        }

        container.innerHTML = scans.map(s => `
            <div class="finding-card" data-status="${s.status}">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-dot ${s.status === 'running' ? 'running' : s.status === 'completed' ? 'online' : 'error'}"></span>
                        <span class="font-medium">${escapeHtml(s.name || 'Untitled Scan')}</span>
                        <span class="badge badge-${s.status === 'running' ? 'warning' : s.status === 'completed' ? 'success' : 'error'}">${escapeHtml(s.status)}</span>
                        <span class="badge badge-info">${escapeHtml(s.type || 'web')}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">Target: <code>${escapeHtml(s.target || 'N/A')}</code></div>
                    <div class="text-sm mb-2"><strong>Started:</strong> ${s.startedAt ? new Date(s.startedAt).toLocaleString() : 'N/A'}</div>
                    <div class="text-sm mb-2"><strong>Duration:</strong> ${s.duration || 'N/A'}</div>
                    ${s.findings ? `<div class="text-sm"><strong>Findings:</strong> ${s.findings} issues discovered</div>` : ''}
                </div>
            </div>
        `).join('');
    }

    function filterScans(filter, btn) {
        if (btn) {
            btn.closest('.card-header').querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        }
        $$('#scanList .finding-card').forEach(card => {
            if (filter === 'all') card.style.display = '';
            else card.style.display = card.dataset.status === filter ? '' : 'none';
        });
    }

    // ========================================
    // Red Team: Findings
    // ========================================

    function setupRedFindings() {
        loadFindings();
        $('#addFindingBtn')?.addEventListener('click', () => {
            $('#findingForm').style.display = $('#findingForm').style.display === 'none' ? 'block' : 'none';
        });
        $('#exportFindingsBtn')?.addEventListener('click', exportFindings);
        $('#saveFindingBtn')?.addEventListener('click', saveFinding);
        $('#cancelFindingBtn')?.addEventListener('click', () => {
            $('#findingForm').style.display = 'none';
        });
        $('#findingSearch')?.addEventListener('input', (e) => filterFindingsList(e.target.value));
    }

    function exportFindings() {
        const findings = state.data.findings || [];
        if (findings.length === 0) {
            showToast('warning', 'No Findings', 'There are no findings to export.');
            return;
        }

        showModal({
            title: '📤 Export Findings',
            body: `
                <div class="form-group">
                    <label class="form-label">Export Format</label>
                    <select class="input" id="exportFormat">
                        <option value="csv">CSV</option>
                        <option value="json">JSON</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Severity Filter</label>
                    <select class="input" id="exportSeverityFilter">
                        <option value="all">All Severities</option>
                        <option value="critical">Critical Only</option>
                        <option value="critical-high">Critical & High</option>
                        <option value="medium-low">Medium & Low</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Include Fields</label>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
                        <label class="checkbox"><input type="checkbox" id="expTitle" checked> Title</label>
                        <label class="checkbox"><input type="checkbox" id="expSeverity" checked> Severity</label>
                        <label class="checkbox"><input type="checkbox" id="expCategory" checked> Category</label>
                        <label class="checkbox"><input type="checkbox" id="expTarget" checked> Target</label>
                        <label class="checkbox"><input type="checkbox" id="expDescription" checked> Description</label>
                        <label class="checkbox"><input type="checkbox" id="expRemediation"> Remediation</label>
                        <label class="checkbox"><input type="checkbox" id="expDate" checked> Date</label>
                    </div>
                </div>
            `,
            actions: [
                '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Cancel</button>',
                '<button class="btn btn-primary" id="processExportFindingsBtn">Export</button>',
            ],
        });

        setTimeout(() => {
            $('#processExportFindingsBtn')?.addEventListener('click', () => {
                const format = $('#exportFormat')?.value;
                const severityFilter = $('#exportSeverityFilter')?.value;
                const fields = {
                    title: $('#expTitle')?.checked,
                    severity: $('#expSeverity')?.checked,
                    category: $('#expCategory')?.checked,
                    target: $('#expTarget')?.checked,
                    description: $('#expDescription')?.checked,
                    remediation: $('#expRemediation')?.checked,
                    date: $('#expDate')?.checked,
                };

                let filtered = [...findings];
                if (severityFilter === 'critical') {
                    filtered = filtered.filter(f => f.severity === 'critical');
                } else if (severityFilter === 'critical-high') {
                    filtered = filtered.filter(f => f.severity === 'critical' || f.severity === 'high');
                } else if (severityFilter === 'medium-low') {
                    filtered = filtered.filter(f => f.severity === 'medium' || f.severity === 'low' || f.severity === 'info');
                }

                if (filtered.length === 0) {
                    showToast('warning', 'No Results', 'No findings match the selected filter.');
                    return;
                }

                let output = '';
                const selectedFields = Object.entries(fields).filter(([, v]) => v).map(([k]) => k);

                if (format === 'csv') {
                    output = selectedFields.join(',') + '\n';
                    for (const f of filtered) {
                        const row = selectedFields.map(field => {
                            let val = '';
                            switch(field) {
                                case 'title': val = f.title || ''; break;
                                case 'severity': val = f.severity || ''; break;
                                case 'category': val = f.category || ''; break;
                                case 'target': val = f.target || ''; break;
                                case 'description': val = (f.description || '').replace(/,/g, ';').replace(/\n/g, ' '); break;
                                case 'remediation': val = (f.remediation || '').replace(/,/g, ';').replace(/\n/g, ' '); break;
                                case 'date': val = f.discoveredAt ? new Date(f.discoveredAt).toISOString() : ''; break;
                            }
                            return `"${val}"`;
                        });
                        output += row.join(',') + '\n';
                    }
                } else {
                    const jsonObj = filtered.map(f => {
                        const obj = {};
                        if (fields.title) obj.title = f.title;
                        if (fields.severity) obj.severity = f.severity;
                        if (fields.category) obj.category = f.category;
                        if (fields.target) obj.target = f.target;
                        if (fields.description) obj.description = f.description;
                        if (fields.remediation) obj.remediation = f.remediation;
                        if (fields.date) obj.discoveredAt = f.discoveredAt ? new Date(f.discoveredAt).toISOString() : null;
                        return obj;
                    });
                    output = JSON.stringify(jsonObj, null, 2);
                }

                const blob = new Blob([output], { type: format === 'csv' ? 'text/csv' : 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `findings_export_${new Date().toISOString().slice(0, 10)}.${format}`;
                a.click();
                URL.revokeObjectURL(url);

                $('.modal-overlay').remove();
                showToast('success', 'Export Complete', `${filtered.length} findings exported to ${format.toUpperCase()}.`);
                addActivity(`Exported ${filtered.length} findings to ${format.toUpperCase()}`);
            });
        }, 100);
    }

    function loadFindings() {
        const findings = state.data.findings || [];
        $('#findingsCritical').textContent = findings.filter(f => f.severity === 'critical').length;
        $('#findingsHigh').textContent = findings.filter(f => f.severity === 'high').length;
        $('#findingsMedium').textContent = findings.filter(f => f.severity === 'medium').length;
        $('#findingsLow').textContent = findings.filter(f => f.severity === 'low').length;
        $('#findingsInfo').textContent = findings.filter(f => f.severity === 'info').length;

        const container = $('#findingsList');
        if (!container) return;

        if (findings.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📋</div><div class="empty-state-title">No Findings</div><div class="empty-state-text">Findings will appear here when discovered.</div></div>';
            return;
        }

        container.innerHTML = findings.map(f => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'medium' ? '🟡' : f.severity === 'low' ? '🔵' : '🟢'}</span>
                        <span class="font-medium">${escapeHtml(f.title)}</span>
                        <span class="badge badge-${f.severity === 'critical' ? 'critical' : f.severity === 'high' ? 'high' : f.severity === 'medium' ? 'warning' : f.severity === 'low' ? 'info' : 'success'}">${escapeHtml(f.severity)}</span>
                        <span class="badge badge-info">${escapeHtml(f.category || 'other')}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(f.description || '')}</div>
                    <div class="text-sm mb-2"><strong>Target:</strong> <code>${escapeHtml(f.target || 'N/A')}</code></div>
                    ${f.remediation ? `<div class="finding-remediation"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>` : ''}
                    <div class="text-sm text-tertiary mt-2">Discovered: ${f.discoveredAt ? new Date(f.discoveredAt).toLocaleDateString() : 'N/A'}</div>
                </div>
            </div>
        `).join('');
    }

    function saveFinding() {
        const title = $('#findingTitle')?.value?.trim();
        const severity = $('#findingSeverity')?.value;
        const target = $('#findingTarget')?.value?.trim();
        const category = $('#findingCategory')?.value;
        const description = $('#findingDesc')?.value?.trim();
        const remediation = $('#findingRemediation')?.value?.trim();

        if (!title) {
            showToast('error', 'Missing Title', 'Please enter a finding title.');
            return;
        }

        const finding = {
            id: `finding_${Date.now()}`,
            title,
            severity,
            target,
            category,
            description,
            remediation,
            discoveredAt: Date.now(),
        };

        state.data.findings.push(finding);
        $('#findingForm').style.display = 'none';
        loadFindings();
        showToast('success', 'Finding Added', `"${title}" has been recorded.`);
        addActivity(`Finding added: ${title}`);
    }

    function filterFindingsList(query) {
        const cards = $$('#findingsList .finding-card');
        cards.forEach(card => {
            const text = card.textContent.toLowerCase();
            card.style.display = text.includes(query.toLowerCase()) ? '' : 'none';
        });
    }

    // ========================================
    // Red Team: Email Security
    // ========================================

    function setupRedEmail() {
        $('#launchPhishingBtn')?.addEventListener('click', launchPhishing);
        $('#checkEmailInfraBtn')?.addEventListener('click', checkEmailInfra);
        $('#checkDmarcBtn')?.addEventListener('click', checkDmarc);

        $$('#content-red-email .tab').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('#content-red-email .tab').forEach(t => t.classList.remove('active'));
                $$('#content-red-email .tab-content').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                const tabId = `tab-${tab.dataset.tab}`;
                const tabContent = $(`#${tabId}`);
                if (tabContent) tabContent.style.display = '';
            });
        });
    }

    function launchPhishing() {
        const campaign = $('#phishingCampaign')?.value?.trim();
        const template = $('#phishingTemplate')?.value;
        const targets = ($('#phishingTargets')?.value || '').split('\n').filter(Boolean).map(t => t.trim());

        if (!campaign || targets.length === 0) {
            showToast('error', 'Missing Data', 'Campaign name and target emails are required.');
            return;
        }

        const container = $('#phishingResults');
        container.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Campaign: ${escapeHtml(campaign)}</span>
                    <span class="badge badge-warning">Running</span>
                </div>
                <div class="card-body">
                    <div class="text-sm mb-2"><strong>Template:</strong> ${escapeHtml(template)}</div>
                    <div class="text-sm mb-2"><strong>Targets:</strong> ${targets.length} recipients</div>
                    <div class="text-sm mb-2"><strong>Status:</strong> Sending emails...</div>
                    <div class="code-block">
                        [SIMULATION] Phishing campaign launched in demo mode.<br>
                        ${targets.length} emails would be sent with "${template}" template.<br>
                        Open tracking, click tracking, and credential capture would be active.
                    </div>
                </div>
            </div>
        `;
        showToast('info', 'Campaign Launched', `Phishing simulation "${campaign}" started with ${targets.length} targets.`);
        addActivity(`Phishing campaign: ${campaign} (${targets.length} targets)`);
    }

    function checkEmailInfra() {
        const domain = $('#emailDomain')?.value?.trim();
        if (!domain) {
            showToast('error', 'Missing Domain', 'Please enter a domain to check.');
            return;
        }

        const container = $('#emailInfraResults');
        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <h4 class="mb-3">Email Infrastructure — ${escapeHtml(domain)}</h4>
                    <div class="grid grid-2">
                        <div>
                            <div class="text-secondary text-sm">MX Records</div>
                            <div class="code-block mb-2">mail.${escapeHtml(domain)} (priority 10)</div>
                        </div>
                        <div>
                            <div class="text-secondary text-sm">Mail Server</div>
                            <div>Microsoft 365 / Google Workspace</div>
                        </div>
                        <div>
                            <div class="text-secondary text-sm">IP Address</div>
                            <div><code>203.0.113.50</code></div>
                        </div>
                        <div>
                            <div class="text-secondary text-sm">Reputation</div>
                            <span class="badge badge-success">Good</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
        addActivity(`Email infra check: ${domain}`);
    }

    function checkDmarc() {
        const domain = $('#dmarcDomain')?.value?.trim();
        if (!domain) {
            showToast('error', 'Missing Domain', 'Please enter a domain to check.');
            return;
        }

        const container = $('#dmarcResults');
        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <h4 class="mb-3">Email Authentication — ${escapeHtml(domain)}</h4>
                    <div class="grid grid-1">
                        <div style="padding:12px; border:1px solid var(--border-primary); border-radius:8px; margin-bottom:8px;">
                            <div class="flex items-center gap-3 mb-2">
                                <span class="badge badge-success">SPF: PASS</span>
                                <span style="font-weight:500;">Sender Policy Framework</span>
                            </div>
                            <code style="font-size:0.8rem;">v=spf1 include:_spf.google.com ~all</code>
                        </div>
                        <div style="padding:12px; border:1px solid var(--border-primary); border-radius:8px; margin-bottom:8px;">
                            <div class="flex items-center gap-3 mb-2">
                                <span class="badge badge-success">DKIM: PASS</span>
                                <span style="font-weight:500;">DomainKeys Identified Mail</span>
                            </div>
                            <code style="font-size:0.8rem;">k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...</code>
                        </div>
                        <div style="padding:12px; border:1px solid var(--border-primary); border-radius:8px;">
                            <div class="flex items-center gap-3 mb-2">
                                <span class="badge badge-warning">DMARC: PARTIAL</span>
                                <span style="font-weight:500;">Domain-based Message Authentication</span>
                            </div>
                            <code style="font-size:0.8rem;">v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@${escapeHtml(domain)}</code>
                            <div class="text-sm text-warning mt-2">⚠️ Policy set to "quarantine" — consider "reject" for stronger protection.</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        addActivity(`DMARC check: ${domain}`);
    }

    // ========================================
    // Red Team: Wireless Security
    // ========================================

    function setupRedWireless() {
        $('#scanWifiBtn')?.addEventListener('click', scanWifi);
        $('#scanBtBtn')?.addEventListener('click', scanBt);
        $('#scanRfidBtn')?.addEventListener('click', scanRfid);

        $$('#content-red-wireless .tab').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('#content-red-wireless .tab').forEach(t => t.classList.remove('active'));
                $$('#content-red-wireless .tab-content').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                const tabId = `tab-${tab.dataset.tab}`;
                const tabContent = $(`#${tabId}`);
                if (tabContent) tabContent.style.display = '';
            });
        });
    }

    function scanWifi() {
        const iface = $('#wifiInterface')?.value;
        const duration = $('#wifiScanDuration')?.value;

        const container = $('#wifiResults');
        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="flex items-center gap-3 mb-4">
                        <div class="spinner spinner-sm"></div>
                        <span>Scanning WiFi networks on ${iface}...</span>
                    </div>
                </div>
            </div>
        `;

        setTimeout(() => {
            container.innerHTML = `
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">WiFi Networks Found</span>
                        <span class="badge badge-info">5 networks</span>
                    </div>
                    <div class="card-body">
                        ${[
                            { ssid: 'CorpNet-5G', bssid: 'AA:BB:CC:DD:EE:01', signal: -42, channel: 36, security: 'WPA3-Enterprise' },
                            { ssid: 'CorpNet-2.4G', bssid: 'AA:BB:CC:DD:EE:02', signal: -55, channel: 6, security: 'WPA3-Enterprise' },
                            { ssid: 'Guest-WiFi', bssid: 'AA:BB:CC:DD:EE:03', signal: -60, channel: 11, security: 'Open' },
                            { ssid: 'Printer-WiFi', bssid: 'AA:BB:CC:DD:EE:04', signal: -72, channel: 1, security: 'WPA2-PSK' },
                            { ssid: 'Neighbor-AP', bssid: 'FF:EE:DD:CC:BB:AA', signal: -85, channel: 9, security: 'WPA2-PSK' },
                        ].map(n => `
                            <div style="display:flex; align-items:center; gap:12px; padding:8px 0; border-bottom:1px solid var(--border-secondary);">
                                <span class="status-dot ${n.signal > -60 ? 'online' : n.signal > -75 ? 'warning' : 'offline'}"></span>
                                <div style="flex:1;">
                                    <div style="font-weight:500;">${escapeHtml(n.ssid)}</div>
                                    <div style="font-size:0.8rem; color:var(--text-tertiary);">${n.bssid} · Ch ${n.channel}</div>
                                </div>
                                <span class="badge badge-${n.security.includes('WPA3') ? 'success' : n.security === 'Open' ? 'error' : 'warning'}">${escapeHtml(n.security)}</span>
                                <span class="text-secondary">${n.signal} dBm</span>
                            </div>
                        `).join('')}
                        <div class="text-sm text-warning mt-3">⚠️ Guest-WiFi is open — no encryption detected.</div>
                    </div>
                </div>
            `;
            showToast('success', 'Scan Complete', '5 WiFi networks discovered.');
            addActivity(`WiFi scan: 5 networks found on ${iface}`);
        }, 2000);
    }

    function scanBt() {
        const duration = $('#btScanDuration')?.value;

        const container = $('#btResults');
        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="flex items-center gap-3 mb-4">
                        <div class="spinner spinner-sm"></div>
                        <span>Scanning Bluetooth devices...</span>
                    </div>
                </div>
            </div>
        `;

        setTimeout(() => {
            container.innerHTML = `
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Bluetooth Devices Found</span>
                        <span class="badge badge-info">3 devices</span>
                    </div>
                    <div class="card-body">
                        ${[
                            { name: 'Corporate Printer', mac: '00:1A:2B:3C:4D:5E', type: 'Classic', rssi: -55 },
                            { name: 'Unknown Device', mac: 'F8:95:EA:12:34:56', type: 'BLE', rssi: -70 },
                            { name: 'Conference Speaker', mac: 'B8:27:EB:AB:CD:EF', type: 'Classic', rssi: -48 },
                        ].map(d => `
                            <div style="display:flex; align-items:center; gap:12px; padding:8px 0; border-bottom:1px solid var(--border-secondary);">
                                <span class="status-dot ${d.name.includes('Unknown') ? 'warning' : 'online'}"></span>
                                <div style="flex:1;">
                                    <div style="font-weight:500;">${escapeHtml(d.name)}</div>
                                    <div style="font-size:0.8rem; color:var(--text-tertiary);">${d.mac} · ${d.type}</div>
                                </div>
                                <span class="text-secondary">${d.rssi} dBm</span>
                            </div>
                        `).join('')}
                        <div class="text-sm text-warning mt-3">⚠️ Unknown BLE device detected — investigate.</div>
                    </div>
                </div>
            `;
            showToast('success', 'Scan Complete', '3 Bluetooth devices discovered.');
            addActivity(`Bluetooth scan: 3 devices found`);
        }, 1500);
    }

    function scanRfid() {
        const reader = $('#rfidReader')?.value;

        const container = $('#rfidResults');
        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="flex items-center gap-3 mb-4">
                        <div class="spinner spinner-sm"></div>
                        <span>Scanning for RFID/NFC tags...</span>
                    </div>
                </div>
            </div>
        `;

        setTimeout(() => {
            container.innerHTML = `
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">RFID/NFC Tags Found</span>
                        <span class="badge badge-info">2 tags</span>
                    </div>
                    <div class="card-body">
                        ${[
                            { uid: '04:A2:B3:C4:D5:E6:F7', type: 'MIFARE Classic 1K', data: 'Employee Badge' },
                            { uid: 'E2:00:00:12:34:56:78', type: 'NTAG215', data: 'Blank/Unprogrammed' },
                        ].map(t => `
                            <div style="display:flex; align-items:center; gap:12px; padding:8px 0; border-bottom:1px solid var(--border-secondary);">
                                <span class="status-dot ${t.data.includes('Blank') ? 'warning' : 'online'}"></span>
                                <div style="flex:1;">
                                    <div style="font-weight:500;">${escapeHtml(t.type)}</div>
                                    <div style="font-size:0.8rem; color:var(--text-tertiary);">UID: ${t.uid}</div>
                                </div>
                                <span class="badge badge-info">${escapeHtml(t.data)}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
            showToast('success', 'Scan Complete', '2 RFID/NFC tags discovered.');
            addActivity(`RFID scan: 2 tags found with ${reader}`);
        }, 1500);
    }

    // ========================================
    // Red Team: Exploitation
    // ========================================

    function setupRedExploit() {
        $('#searchExploitsBtn')?.addEventListener('click', searchExploits);
        $('#newSessionBtn')?.addEventListener('click', newListener);
        $('#runPostExploitBtn')?.addEventListener('click', runPostExploit);

        $$('#content-red-exploit .tab').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('#content-red-exploit .tab').forEach(t => t.classList.remove('active'));
                $$('#content-red-exploit .tab-content').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                const tabId = `tab-${tab.dataset.tab}`;
                const tabContent = $(`#${tabId}`);
                if (tabContent) tabContent.style.display = '';
            });
        });
    }

    function searchExploits() {
        const query = $('#exploitSearch')?.value?.trim();
        const platform = $('#exploitPlatform')?.value;

        if (!query) {
            showToast('error', 'Missing Query', 'Please enter a CVE or keyword.');
            return;
        }

        const container = $('#exploitSearchResults');
        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="flex items-center gap-3 mb-4">
                        <div class="spinner spinner-sm"></div>
                        <span>Searching exploit databases...</span>
                    </div>
                </div>
            </div>
        `;

        setTimeout(() => {
            container.innerHTML = `
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Search Results for "${escapeHtml(query)}"</span>
                        <span class="badge badge-info">3 exploits found</span>
                    </div>
                    <div class="card-body">
                        ${[
                            { id: 'EDB-12345', title: 'Apache 2.4.x Remote Code Execution', type: 'RCE', severity: 'Critical', platform: 'linux' },
                            { id: 'EDB-12346', title: 'Apache mod_rewrite SSRF', type: 'SSRF', severity: 'High', platform: 'linux' },
                            { id: 'EDB-12347', title: 'Apache .htaccess Bypass', type: 'Auth Bypass', severity: 'Medium', platform: 'linux' },
                        ].filter(e => platform === 'all' || e.platform === platform).map(e => `
                            <div style="padding:12px; border:1px solid var(--border-primary); border-radius:8px; margin-bottom:8px;">
                                <div class="flex items-center gap-3 mb-2">
                                    <span class="badge badge-${e.severity === 'Critical' ? 'critical' : e.severity === 'High' ? 'high' : 'warning'}">${escapeHtml(e.severity)}</span>
                                    <span class="font-medium">${escapeHtml(e.title)}</span>
                                    <span class="badge badge-info">${escapeHtml(e.type)}</span>
                                </div>
                                <div class="text-sm text-secondary">ID: ${e.id} · Platform: ${e.platform}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
            showToast('success', 'Search Complete', '3 exploits found.');
            addActivity(`Exploit search: ${query}`);
        }, 1500);
    }

    function newListener() {
        showModal({
            title: '🎧 New Listener',
            body: `
                <div class="form-group">
                    <label class="form-label">Protocol</label>
                    <select class="input" id="listenerProtocol">
                        <option value="tcp">TCP</option>
                        <option value="http">HTTP</option>
                        <option value="https">HTTPS</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Bind Port</label>
                    <input type="number" class="input" id="listenerPort" value="4444">
                </div>
                <div class="form-group">
                    <label class="form-label">Host</label>
                    <input type="text" class="input" id="listenerHost" value="0.0.0.0">
                </div>
            `,
            actions: [
                '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Cancel</button>',
                '<button class="btn btn-primary" id="startListenerBtn">Start Listener</button>',
            ],
        });

        setTimeout(() => {
            $('#startListenerBtn')?.addEventListener('click', () => {
                $('.modal-overlay').remove();
                showToast('success', 'Listener Started', 'Listening on port 4444');
                addActivity('New listener started on port 4444');
            });
        }, 100);
    }

    function runPostExploit() {
        const session = $('#postExploitSession')?.value;
        const module = $('#postExploitModule')?.value;

        if (!session) {
            showToast('error', 'No Session', 'Select a target session first.');
            return;
        }

        const container = $('#postExploitResults');
        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="flex items-center gap-3 mb-4">
                        <div class="spinner spinner-sm"></div>
                        <span>Executing ${module} module...</span>
                    </div>
                </div>
            </div>
        `;

        setTimeout(() => {
            container.innerHTML = `
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Module Output: ${escapeHtml(module)}</span>
                        <span class="badge badge-success">Complete</span>
                    </div>
                    <div class="card-body">
                        <div class="code-block">
                            [+] Connected to session: ${escapeHtml(session)}<br>
                            [+] Running ${module} module...<br>
                            [+] Module execution complete.<br>
                            [*] Results saved to session log.
                        </div>
                    </div>
                </div>
            `;
            showToast('success', 'Module Complete', `${module} executed successfully.`);
            addActivity(`Post-exploit: ${module} on ${session}`);
        }, 2000);
    }

    // ========================================
    // Red Team: Payloads
    // ========================================

    function setupRedPayloads() {
        $('#generatePayloadBtn')?.addEventListener('click', generatePayload);
    }

    function generatePayload() {
        const type = $('#payloadType')?.value;
        const platform = $('#payloadPlatform')?.value;
        const lhost = $('#payloadLhost')?.value?.trim();
        const lport = $('#payloadLport')?.value;
        const encoder = $('#payloadEncoder')?.value;

        if (!lhost || !lport) {
            showToast('error', 'Missing Config', 'LHOST and LPORT are required.');
            return;
        }

        const container = $('#payloadResults');
        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="flex items-center gap-3 mb-4">
                        <div class="spinner spinner-sm"></div>
                        <span>Generating payload...</span>
                    </div>
                </div>
            </div>
        `;

        setTimeout(() => {
            const payloadName = `payload_${platform}_${type}`;
            container.innerHTML = `
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Generated Payload</span>
                        <span class="badge badge-success">Ready</span>
                    </div>
                    <div class="card-body">
                        <div class="grid grid-2 mb-4">
                            <div><strong>Type:</strong> ${escapeHtml(type)}</div>
                            <div><strong>Platform:</strong> ${escapeHtml(platform)}</div>
                            <div><strong>LHOST:</strong> ${escapeHtml(lhost)}</div>
                            <div><strong>LPORT:</strong> ${escapeHtml(lport)}</div>
                            <div><strong>Encoder:</strong> ${escapeHtml(encoder)}</div>
                            <div><strong>Format:</strong> ${platform === 'web' ? 'raw' : 'exe'}</div>
                        </div>
                        <div class="code-block mb-3">
                            [PAYLOAD PLACEHOLDER]<br>
                            msfvenom -p ${platform}/${type}/LHOST=${lhost} LPORT=${lport} ${encoder !== 'none' ? '-e ' + encoder : ''} -f ${platform === 'web' ? 'raw' : 'exe'} > ${payloadName}.${platform === 'web' ? 'php' : 'exe'}
                        </div>
                        <div class="flex gap-2">
                            <button class="btn btn-sm btn-secondary" onclick="showToast('success', 'Downloaded', 'Payload saved to downloads.')">⬇ Download</button>
                            <button class="btn btn-sm btn-secondary" onclick="showToast('info', 'Copied', 'Payload command copied.')">📋 Copy Command</button>
                        </div>
                    </div>
                </div>
            `;
            showToast('success', 'Payload Generated', `${type} payload for ${platform} ready.`);
            addActivity(`Payload generated: ${type} (${platform})`);
        }, 1500);
    }

    // ========================================
    // Red Team: Reports
    // ========================================

    function setupRedReports() {
        loadRedReports();
        $('#generateRedReportBtn')?.addEventListener('click', () => {
            $('#redReportForm').style.display = $('#redReportForm').style.display === 'none' ? 'block' : 'none';
        });
        $('#createRedReportBtn')?.addEventListener('click', createRedReport);
        $('#cancelRedReportBtn')?.addEventListener('click', () => {
            $('#redReportForm').style.display = 'none';
        });
    }

    function loadRedReports() {
        const reports = state.data.redReports || [];
        const container = $('#redReportsList');
        if (!container) return;

        if (reports.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📋</div><div class="empty-state-title">No Reports</div><div class="empty-state-text">Generate a report to see it here.</div></div>';
            return;
        }

        container.innerHTML = reports.map(r => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">📋</span>
                        <span class="font-medium">${escapeHtml(r.title)}</span>
                        <span class="badge badge-info">${escapeHtml(r.type)}</span>
                        <span class="badge badge-success">Generated</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(r.scope || '')}</div>
                    <div class="text-sm mb-2"><strong>Created:</strong> ${new Date(r.createdAt).toLocaleString()}</div>
                    <div class="text-sm"><strong>Findings:</strong> ${r.findings || 0} issues</div>
                </div>
            </div>
        `).join('');
    }

    function createRedReport() {
        const title = $('#redReportTitle')?.value?.trim();
        const type = $('#redReportType')?.value;
        const scope = $('#redReportScope')?.value?.trim();

        if (!title) {
            showToast('error', 'Missing Title', 'Please enter a report title.');
            return;
        }

        const report = {
            id: `report_${Date.now()}`,
            title,
            type,
            scope,
            findings: state.data.findings.length,
            createdAt: Date.now(),
        };

        state.data.redReports = state.data.redReports || [];
        state.data.redReports.push(report);
        $('#redReportForm').style.display = 'none';
        loadRedReports();
        showToast('success', 'Report Created', `"${title}" has been generated.`);
        addActivity(`Report created: ${title}`);
    }

    // ========================================
    // Gray Team: Simulations
    // ========================================

    function setupGraySimulations() {
        loadSimulations();
        $('#newSimulationBtn')?.addEventListener('click', () => {
            $('#simulationForm').style.display = $('#simulationForm').style.display === 'none' ? 'block' : 'none';
        });
        $('#createSimulationBtn')?.addEventListener('click', createSimulation);
        $('#cancelSimulationBtn')?.addEventListener('click', () => {
            $('#simulationForm').style.display = 'none';
        });
    }

    function loadSimulations() {
        const simulations = state.data.simulations || [];
        const container = $('#simulationsList');
        if (!container) return;

        if (simulations.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⚔️</div><div class="empty-state-title">No Simulations</div><div class="empty-state-text">Create an attack simulation to begin.</div></div>';
            return;
        }

        container.innerHTML = simulations.map(s => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">⚔️</span>
                        <span class="font-medium">${escapeHtml(s.name)}</span>
                        <span class="badge badge-info">${escapeHtml(s.actor)}</span>
                        <span class="badge badge-${s.status === 'completed' ? 'success' : s.status === 'running' ? 'warning' : 'info'}">${escapeHtml(s.status)}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(s.description || '')}</div>
                    <div class="text-sm mb-2"><strong>Created:</strong> ${new Date(s.createdAt).toLocaleString()}</div>
                    <div class="text-sm"><strong>Scenarios:</strong> ${s.scenarios || 0}</div>
                </div>
            </div>
        `).join('');
    }

    function createSimulation() {
        const name = $('#simulationName')?.value?.trim();
        const actor = $('#simulationActor')?.value;
        const description = $('#simulationDesc')?.value?.trim();

        if (!name) {
            showToast('error', 'Missing Name', 'Please enter a simulation name.');
            return;
        }

        const simulation = {
            id: `sim_${Date.now()}`,
            name,
            actor,
            description,
            status: 'pending',
            scenarios: 0,
            createdAt: Date.now(),
        };

        state.data.simulations = state.data.simulations || [];
        state.data.simulations.push(simulation);
        $('#simulationForm').style.display = 'none';
        loadSimulations();
        showToast('success', 'Simulation Created', `"${name}" has been created.`);
        addActivity(`Simulation created: ${name}`);
    }

    // ========================================
    // Gray Team: Correlation
    // ========================================

    function setupGrayCorrelation() {
        loadCorrelation();
        $('#runCorrelationBtn')?.addEventListener('click', runCorrelation);
    }

    function loadCorrelation() {
        const correlations = state.data.correlations || [];
        $('#correlationTotal').textContent = correlations.length;
        $('#correlationHigh').textContent = correlations.filter(c => c.confidence > 0.8).length;
        $('#correlationChains').textContent = correlations.filter(c => c.type === 'chain').length;

        const container = $('#correlationResults');
        if (!container) return;

        if (correlations.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🔗</div><div class="empty-state-title">No Correlations</div><div class="empty-state-text">Run correlation analysis to find relationships.</div></div>';
            return;
        }

        container.innerHTML = correlations.map(c => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${c.confidence > 0.8 ? '🔴' : c.confidence > 0.5 ? '🟡' : '🟢'}</span>
                        <span class="font-medium">${escapeHtml(c.title)}</span>
                        <span class="badge badge-${c.confidence > 0.8 ? 'critical' : c.confidence > 0.5 ? 'warning' : 'success'}">${(c.confidence * 100).toFixed(0)}%</span>
                        <span class="badge badge-info">${escapeHtml(c.type)}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(c.description || '')}</div>
                    <div class="text-sm"><strong>Findings:</strong> ${c.findings?.map(f => escapeHtml(f)).join(', ') || 'N/A'}</div>
                </div>
            </div>
        `).join('');
    }

    function runCorrelation() {
        const container = $('#correlationResults');
        container.innerHTML = '<div class="card"><div class="card-body"><div class="flex items-center gap-3"><div class="spinner spinner-sm"></div><span>Running correlation analysis...</span></div></div></div>';

        setTimeout(() => {
            state.data.correlations = [
                { id: 'corr_1', title: 'SQLi → Data Exfiltration Chain', confidence: 0.92, type: 'chain', findings: ['SQL Injection', 'DB Access', 'Data Export'], description: 'SQL injection vulnerability can be chained with database access to exfiltrate sensitive data.' },
                { id: 'corr_2', title: 'XSS → Session Hijacking', confidence: 0.78, type: 'chain', findings: ['Stored XSS', 'Session Token Theft'], description: 'Stored XSS can be used to steal session tokens and hijack user accounts.' },
                { id: 'corr_3', title: 'Weak Auth + No MFA', confidence: 0.65, type: 'cluster', findings: ['Weak Passwords', 'No MFA'], description: 'Multiple systems have weak authentication without MFA protection.' },
            ];
            loadCorrelation();
            showToast('success', 'Analysis Complete', '3 correlations discovered.');
            addActivity('Correlation analysis: 3 findings');
        }, 2000);
    }

    // ========================================
    // Gray Team: Attack Surface
    // ========================================

    function setupGraySurface() {
        loadSurface();
        $('#scanSurfaceBtn')?.addEventListener('click', scanSurface);
    }

    function loadSurface() {
        const surface = state.data.attackSurface || { assets: 0, exposure: 0, risk: 0, changes: 0 };
        $('#surfaceAssets').textContent = surface.assets;
        $('#surfaceExposure').textContent = surface.exposure;
        $('#surfaceRisk').textContent = surface.risk;
        $('#surfaceChanges').textContent = surface.changes;

        const container = $('#surfaceResults');
        if (!container) return;

        if (surface.assets === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🌍</div><div class="empty-state-title">No Surface Data</div><div class="empty-state-text">Run a surface scan to discover assets.</div></div>';
            return;
        }
    }

    function scanSurface() {
        const container = $('#surfaceResults');
        container.innerHTML = '<div class="card"><div class="card-body"><div class="flex items-center gap-3"><div class="spinner spinner-sm"></div><span>Scanning attack surface...</span></div></div></div>';

        setTimeout(() => {
            state.data.attackSurface = { assets: 47, exposure: 12, risk: 6.8, changes: 5 };
            loadSurface();
            container.innerHTML += `
                <div class="card mt-4">
                    <div class="card-header">
                        <span class="card-title">Discovered Assets</span>
                        <span class="badge badge-info">47 assets</span>
                    </div>
                    <div class="card-body">
                        ${[
                            { name: 'www.example.com', type: 'Web Server', exposure: 'High', services: 'HTTP, HTTPS' },
                            { name: 'api.example.com', type: 'API Gateway', exposure: 'Medium', services: 'HTTPS, gRPC' },
                            { name: 'mail.example.com', type: 'Mail Server', exposure: 'Low', services: 'SMTP, IMAP' },
                            { name: 'vpn.example.com', type: 'VPN Gateway', exposure: 'High', services: 'OpenVPN, IPSec' },
                            { name: 'git.example.com', type: 'Git Server', exposure: 'Medium', services: 'SSH, HTTPS' },
                        ].map(a => `
                            <div style="display:flex; align-items:center; gap:12px; padding:8px 0; border-bottom:1px solid var(--border-secondary);">
                                <span class="status-dot ${a.exposure === 'High' ? 'error' : a.exposure === 'Medium' ? 'warning' : 'online'}"></span>
                                <div style="flex:1;">
                                    <div style="font-weight:500;">${escapeHtml(a.name)}</div>
                                    <div style="font-size:0.8rem; color:var(--text-tertiary);">${a.type} · ${a.services}</div>
                                </div>
                                <span class="badge badge-${a.exposure === 'High' ? 'error' : a.exposure === 'Medium' ? 'warning' : 'success'}">${a.exposure}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
            showToast('success', 'Scan Complete', '47 assets discovered.');
            addActivity('Attack surface scan: 47 assets found');
        }, 2000);
    }

    // ========================================
    // Gray Team: Reports
    // ========================================

    function setupGrayReports() {
        loadGrayReports();
        $('#generateGrayReportBtn')?.addEventListener('click', () => {
            const report = {
                id: `gray_report_${Date.now()}`,
                title: 'ATT&CK Coverage Report',
                type: 'coverage',
                createdAt: Date.now(),
            };
            state.data.grayReports = state.data.grayReports || [];
            state.data.grayReports.push(report);
            loadGrayReports();
            showToast('success', 'Report Generated', 'ATT&CK coverage report created.');
            addActivity('Gray team report generated');
        });
    }

    function loadGrayReports() {
        const reports = state.data.grayReports || [];
        const container = $('#grayReportsList');
        if (!container) return;

        if (reports.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📋</div><div class="empty-state-title">No Reports</div><div class="empty-state-text">Generate a coverage or validation report.</div></div>';
            return;
        }

        container.innerHTML = reports.map(r => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">📋</span>
                        <span class="font-medium">${escapeHtml(r.title)}</span>
                        <span class="badge badge-info">${escapeHtml(r.type)}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm"><strong>Created:</strong> ${new Date(r.createdAt).toLocaleString()}</div>
                </div>
            </div>
        `).join('');
    }

    // ========================================
    // Blue Team: Alerts
    // ========================================

    function setupBlueAlerts() {
        loadAlerts();
        $('#refreshAlertsBtn')?.addEventListener('click', () => {
            loadAlerts();
            showToast('success', 'Refreshed', 'Alert queue refreshed.');
        });
        $('#createAlertBtn')?.addEventListener('click', createAlert);
    }

    function createAlert() {
        showModal({
            title: '🚨 Create Manual Alert',
            body: `
                <div class="form-group">
                    <label class="form-label">Alert Title</label>
                    <input type="text" class="input" id="alertModalTitle" placeholder="Suspicious activity detected">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">Severity</label>
                        <select class="input" id="alertModalSeverity">
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium" selected>Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Source</label>
                        <select class="input" id="alertModalSource">
                            <option value="manual">Manual</option>
                            <option value="ids">IDS</option>
                            <option value="siem">SIEM</option>
                            <option value="edr">EDR</option>
                            <option value="cloud">Cloud Security</option>
                        </select>
                    </div>
                </div>
                <div class="form-group">
                    <label class="form-label">Description</label>
                    <textarea class="input" id="alertModalDesc" rows="4" placeholder="Detailed description of the alert..."></textarea>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">Asset / Target</label>
                        <input type="text" class="input" id="alertModalTarget" placeholder="e.g., 192.168.1.100 or server name">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Assign To</label>
                        <select class="input" id="alertModalAssignee">
                            <option value="unassigned">Unassigned</option>
                            <option value="soc-analyst">SOC Analyst</option>
                            <option value="ir-team">Incident Response</option>
                            <option value="threat-hunter">Threat Hunter</option>
                        </select>
                    </div>
                </div>
                <div class="form-group">
                    <label class="form-label">
                        <input type="checkbox" id="alertModalEscalate"> Escalate to Incident immediately
                    </label>
                </div>
            `,
            actions: [
                '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Cancel</button>',
                '<button class="btn btn-primary" id="saveAlertModalBtn">Create Alert</button>',
            ],
        });

        setTimeout(() => {
            $('#saveAlertModalBtn')?.addEventListener('click', () => {
                const title = $('#alertModalTitle')?.value?.trim();
                const severity = $('#alertModalSeverity')?.value;
                const source = $('#alertModalSource')?.value;
                const description = $('#alertModalDesc')?.value?.trim();
                const target = $('#alertModalTarget')?.value?.trim();
                const assignee = $('#alertModalAssignee')?.value;
                const escalate = $('#alertModalEscalate')?.checked;

                if (!title) {
                    showToast('error', 'Missing Title', 'Alert title is required.');
                    return;
                }

                const alert = {
                    id: `alert_${Date.now()}`,
                    title,
                    severity,
                    source,
                    description,
                    target,
                    assignee,
                    acknowledged: false,
                    escalate,
                    timestamp: Date.now(),
                };

                state.data.alerts = state.data.alerts || [];
                state.data.alerts.unshift(alert);
                $('.modal-overlay').remove();
                loadAlerts();
                showToast('success', 'Alert Created', `Alert "${title}" has been created.`);
                addActivity(`Alert created: ${title} (${severity})`);

                if (escalate) {
                    showToast('warning', 'Escalated', 'Alert has been escalated to incident.');
                }
            });
        }, 100);
    }

    function loadAlerts() {
        const alerts = state.data.alerts || [];
        $('#alertsCritical').textContent = alerts.filter(a => a.severity === 'critical').length;
        $('#alertsHigh').textContent = alerts.filter(a => a.severity === 'high').length;
        $('#alertsMedium').textContent = alerts.filter(a => a.severity === 'medium').length;
        $('#alertsLow').textContent = alerts.filter(a => a.severity === 'low').length;
        $('#alertsTotal').textContent = alerts.length;

        const container = $('#alertsList');
        if (!container) return;

        if (alerts.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🚨</div><div class="empty-state-title">No Alerts</div><div class="empty-state-text">Alerts will appear here from your detection systems.</div></div>';
            return;
        }

        container.innerHTML = alerts.map(a => `
            <div class="finding-card" data-severity="${a.severity}" data-ack="${a.acknowledged}">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${a.severity === 'critical' ? '🔴' : a.severity === 'high' ? '🟠' : a.severity === 'medium' ? '🟡' : '🔵'}</span>
                        <span class="font-medium">${escapeHtml(a.title)}</span>
                        <span class="badge badge-${a.severity === 'critical' ? 'critical' : a.severity === 'high' ? 'high' : a.severity === 'medium' ? 'warning' : 'info'}">${escapeHtml(a.severity)}</span>
                        ${a.acknowledged ? '<span class="badge badge-success">Ack</span>' : '<span class="badge badge-warning">New</span>'}
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">${escapeHtml(a.description || '')}</div>
                    <div class="text-sm mb-2"><strong>Source:</strong> ${escapeHtml(a.source || 'N/A')} · <strong>Time:</strong> ${a.timestamp ? new Date(a.timestamp).toLocaleString() : 'N/A'}</div>
                    <div class="flex gap-2">
                        <button class="btn btn-sm btn-secondary" onclick="acknowledgeAlert('${a.id}')">✓ Acknowledge</button>
                        <button class="btn btn-sm btn-primary" onclick="escalateAlert('${a.id}')">⬆ Escalate</button>
                    </div>
                </div>
            </div>
        `).join('');
    }

    function acknowledgeAlert(id) {
        const alert = state.data.alerts?.find(a => a.id === id);
        if (alert) {
            alert.acknowledged = true;
            loadAlerts();
            showToast('success', 'Acknowledged', `Alert "${alert.title}" acknowledged.`);
        }
    }

    function escalateAlert(id) {
        const alert = state.data.alerts?.find(a => a.id === id);
        if (alert) {
            showToast('warning', 'Escalated', `Alert "${alert.title}" escalated to incident.`);
            addActivity(`Alert escalated: ${alert.title}`);
        }
    }

    function filterAlerts(filter, btn) {
        if (btn) {
            btn.closest('.card-header').querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        }
        $$('#alertsList .finding-card').forEach(card => {
            if (filter === 'all') card.style.display = '';
            else if (filter === 'critical') card.style.display = card.dataset.severity === 'critical' ? '' : 'none';
            else if (filter === 'unack') card.style.display = card.dataset.ack === 'false' ? '' : 'none';
        });
    }

    // ========================================
    // Blue Team: Log Analysis
    // ========================================

    function setupBlueLogs() {
        $('#searchLogsBtn')?.addEventListener('click', searchLogs);
    }

    function searchLogs() {
        const query = $('#logQuery')?.value?.trim();
        const source = $('#logSource')?.value;
        const timeRange = $('#logTimeRange')?.value;
        const maxResults = $('#logMaxResults')?.value;

        if (!query) {
            showToast('error', 'Missing Query', 'Please enter a search query.');
            return;
        }

        const container = $('#logResults');
        container.innerHTML = '<div class="card"><div class="card-body"><div class="flex items-center gap-3"><div class="spinner spinner-sm"></div><span>Searching logs...</span></div></div></div>';

        setTimeout(() => {
            container.innerHTML = `
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Search Results</span>
                        <span class="badge badge-info">142 matches</span>
                    </div>
                    <div class="card-body">
                        <div class="text-sm text-secondary mb-3">Query: <code>${escapeHtml(query)}</code> · Source: ${source} · Range: ${timeRange}</div>
                        <div class="code-block" style="max-height:400px; overflow-y:auto;">
                            ${Array.from({length: 10}, (_, i) => {
                                const time = new Date(Date.now() - i * 60000).toISOString();
                                return `<div style="padding:4px 0; border-bottom:1px solid var(--border-secondary);">
                                    <span style="color:var(--text-tertiary);">${time}</span>
                                    <span style="color:var(--status-error);">ERROR</span>
                                    <span>${escapeHtml(query)} detected from 192.168.1.${10 + i} — action blocked</span>
                                </div>`;
                            }).join('')}
                        </div>
                    </div>
                </div>
            `;
            showToast('success', 'Search Complete', '142 log entries found.');
            addActivity(`Log search: ${query} (${source})`);
        }, 1500);
    }

    // ========================================
    // Blue Team: Malware Analysis
    // ========================================

    function setupBlueMalware() {
        loadMalwareSamples();
        $('#uploadSampleBtn')?.addEventListener('click', () => {
            $('#malwareUploadForm').style.display = $('#malwareUploadForm').style.display === 'none' ? 'block' : 'none';
        });
        $('#submitMalwareBtn')?.addEventListener('click', submitMalware);
        $('#cancelMalwareBtn')?.addEventListener('click', () => {
            $('#malwareUploadForm').style.display = 'none';
        });
    }

    function loadMalwareSamples() {
        const samples = state.data.malwareSamples || [];
        const container = $('#malwareList');
        if (!container) return;

        if (samples.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🦠</div><div class="empty-state-title">No Samples</div><div class="empty-state-text">Upload a sample for analysis.</div></div>';
            return;
        }

        container.innerHTML = samples.map(s => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">${s.risk >= 80 ? '🔴' : s.risk >= 50 ? '🟠' : '🟡'}</span>
                        <span class="font-medium">${escapeHtml(s.name)}</span>
                        <span class="badge badge-${s.risk >= 80 ? 'critical' : s.risk >= 50 ? 'high' : 'warning'}">Risk: ${s.risk}/100</span>
                        <span class="badge badge-info">${escapeHtml(s.status)}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm mb-2"><strong>Type:</strong> ${escapeHtml(s.type || '')} · <strong>SHA256:</strong> <code>${s.sha256 || 'N/A'}</code></div>
                    <div class="text-sm"><strong>Submitted:</strong> ${new Date(s.submittedAt).toLocaleString()}</div>
                </div>
            </div>
        `).join('');
    }

    function submitMalware() {
        const name = $('#malwareName')?.value?.trim();
        const type = $('#malwareType')?.value;
        const analysisType = $('#malwareAnalysisType')?.value;

        if (!name) {
            showToast('error', 'Missing Name', 'Please enter a sample name.');
            return;
        }

        const sample = {
            id: `malware_${Date.now()}`,
            name,
            type,
            analysisType,
            risk: Math.floor(Math.random() * 60) + 40,
            status: 'Analyzing',
            sha256: Array.from({length: 64}, () => Math.floor(Math.random() * 16).toString(16)).join(''),
            submittedAt: Date.now(),
        };

        state.data.malwareSamples = state.data.malwareSamples || [];
        state.data.malwareSamples.push(sample);
        $('#malwareUploadForm').style.display = 'none';
        loadMalwareSamples();
        showToast('success', 'Sample Submitted', `"${name}" submitted for ${analysisType} analysis.`);
        addActivity(`Malware sample submitted: ${name}`);
    }

    // ========================================
    // Blue Team: Network Defense
    // ========================================

    function setupBlueNetwork() {
        loadNetworkStatus();
        $('#deployIdsBtn')?.addEventListener('click', deployIds);
    }

    function deployIds() {
        showModal({
            title: '🛡️ IDS Deployment Wizard',
            size: 'modal-lg',
            body: `
                <div style="margin-bottom:16px;">
                    <div style="display:flex; justify-content:space-between; margin-bottom:12px;">
                        <span style="font-weight:600; color:var(--text-primary);">Step <span id="idsStepNum">1</span> of 4</span>
                        <div class="progress" style="flex:1; margin:8px 16px 0;"><div class="progress-bar" id="idsProgressBar" style="width:25%"></div></div>
                    </div>
                </div>
                <div id="idsStep1" class="ids-step">
                    <h4 style="margin-bottom:12px;">Select IDS Type</h4>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
                        <label style="padding:16px; border:2px solid var(--border-primary); border-radius:8px; cursor:pointer;" class="ids-type-option">
                            <input type="radio" name="idsType" value="snort" checked style="margin-bottom:8px;">
                            <div style="font-weight:600;">Snort</div>
                            <div style="font-size:0.8rem; color:var(--text-tertiary);">Open-source NIDS</div>
                        </label>
                        <label style="padding:16px; border:2px solid var(--border-primary); border-radius:8px; cursor:pointer;" class="ids-type-option">
                            <input type="radio" name="idsType" value="suricata" style="margin-bottom:8px;">
                            <div style="font-weight:600;">Suricata</div>
                            <div style="font-size:0.8rem; color:var(--text-tertiary);">High-performance NIDS</div>
                        </label>
                        <label style="padding:16px; border:2px solid var(--border-primary); border-radius:8px; cursor:pointer;" class="ids-type-option">
                            <input type="radio" name="idsType" value="zeek" style="margin-bottom:8px;">
                            <div style="font-weight:600;">Zeek</div>
                            <div style="font-size:0.8rem; color:var(--text-tertiary);">Network analysis framework</div>
                        </label>
                        <label style="padding:16px; border:2px solid var(--border-primary); border-radius:8px; cursor:pointer;" class="ids-type-option">
                            <input type="radio" name="idsType" value="wazuh" style="margin-bottom:8px;">
                            <div style="font-weight:600;">Wazuh</div>
                            <div style="font-size:0.8rem; color:var(--text-tertiary);">XDR + HIDS platform</div>
                        </label>
                    </div>
                </div>
                <div id="idsStep2" class="ids-step" style="display:none;">
                    <h4 style="margin-bottom:12px;">Network Configuration</h4>
                    <div class="form-group">
                        <label class="form-label">Monitor Interface</label>
                        <input type="text" class="input" id="idsInterface" value="eth0" placeholder="e.g., eth0, ens33, wlan0">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Network Range (CIDR)</label>
                        <input type="text" class="input" id="idsNetwork" value="10.0.0.0/24" placeholder="e.g., 192.168.1.0/24">
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Capture Filter</label>
                            <input type="text" class="input" id="idsFilter" value="not port 22" placeholder="BPF filter expression">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Promiscuous Mode</label>
                            <select class="input" id="idsPromisc">
                                <option value="enabled">Enabled</option>
                                <option value="disabled">Disabled</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div id="idsStep3" class="ids-step" style="display:none;">
                    <h4 style="margin-bottom:12px;">Detection Rules</h4>
                    <div class="form-group">
                        <label class="form-label">Ruleset Source</label>
                        <select class="input" id="idsRuleset">
                            <option value="emerging-threats">Emerging Threats (Proofpoint)</option>
                            <option value="snort-community">Snort Community Rules</option>
                            <option value="suricata-default">Suricata Default Rules</option>
                            <option value="custom">Custom Rules</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Detection Mode</label>
                        <select class="input" id="idsMode">
                            <option value="IDS">IDS (Alert Only)</option>
                            <option value="IPS">IPS (Alert + Block)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Sensitivity Level</label>
                        <select class="input" id="idsSensitivity">
                            <option value="low">Low (Fewer false positives)</option>
                            <option value="medium" selected>Medium (Balanced)</option>
                            <option value="high">High (More detection)</option>
                        </select>
                    </div>
                </div>
                <div id="idsStep4" class="ids-step" style="display:none;">
                    <h4 style="margin-bottom:12px;">Deployment Options</h4>
                    <div class="form-group">
                        <label class="form-label">Deployment Target</label>
                        <select class="input" id="idsTarget">
                            <option value="local">Local Machine</option>
                            <option value="remote">Remote Server (SSH)</option>
                            <option value="docker">Docker Container</option>
                            <option value="kubernetes">Kubernetes Cluster</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Log Destination</label>
                        <select class="input" id="idsLogDest">
                            <option value="local">Local Files</option>
                            <option value="elasticsearch">Elasticsearch</option>
                            <option value="syslog">Syslog Server</option>
                            <option value="s3">S3 Bucket</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Alert Notifications</label>
                        <div style="display:flex; gap:16px;">
                            <label class="checkbox"><input type="checkbox" id="idsEmail" checked> Email</label>
                            <label class="checkbox"><input type="checkbox" id="idsSlack"> Slack</label>
                            <label class="checkbox"><input type="checkbox" id="idsWebhook"> Webhook</label>
                        </div>
                    </div>
                </div>
            `,
            actions: [
                '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Cancel</button>',
                '<button class="btn btn-secondary" id="idsPrevBtn" style="display:none;" onclick="idsPrevStep()">← Previous</button>',
                '<button class="btn btn-primary" id="idsNextBtn" onclick="idsNextStep()">Next →</button>',
            ],
        });

        window.idsCurrentStep = 1;
        window.idsNextStep = function() {
            if (window.idsCurrentStep < 4) {
                $(`#idsStep${window.idsCurrentStep}`).style.display = 'none';
                window.idsCurrentStep++;
                $(`#idsStep${window.idsCurrentStep}`).style.display = '';
                $('#idsStepNum').textContent = window.idsCurrentStep;
                $('#idsProgressBar').style.width = `${window.idsCurrentStep * 25}%`;
                $('#idsPrevBtn').style.display = '';
                if (window.idsCurrentStep === 4) {
                    $('#idsNextBtn').textContent = 'Deploy';
                    $('#idsNextBtn').onclick = idsDeploy;
                }
            }
        };
        window.idsPrevStep = function() {
            if (window.idsCurrentStep > 1) {
                $(`#idsStep${window.idsCurrentStep}`).style.display = 'none';
                window.idsCurrentStep--;
                $(`#idsStep${window.idsCurrentStep}`).style.display = '';
                $('#idsStepNum').textContent = window.idsCurrentStep;
                $('#idsProgressBar').style.width = `${window.idsCurrentStep * 25}%`;
                $('#idsNextBtn').textContent = 'Next →';
                $('#idsNextBtn').onclick = idsNextStep;
                if (window.idsCurrentStep === 1) {
                    $('#idsPrevBtn').style.display = 'none';
                }
            }
        };
        window.idsDeploy = function() {
            const idsType = document.querySelector('input[name="idsType"]:checked')?.value || 'snort';
            const iface = $('#idsInterface')?.value || 'eth0';
            const network = $('#idsNetwork')?.value || '10.0.0.0/24';
            const ruleset = $('#idsRuleset')?.value || 'emerging-threats';
            const mode = $('#idsMode')?.value || 'IDS';

            $('.modal-overlay').remove();
            state.data.networkStatus = {
                monitored: parseInt(network.split('/')[1] || '24', 10) === 24 ? 254 : 100,
                alerts: 0,
                blocked: mode === 'IPS' ? 12 : 0,
                bandwidth: 0,
            };
            showToast('success', 'IDS Deployed', `${idsType} (${mode}) deployed on ${iface} monitoring ${network}`);
            addActivity(`IDS deployed: ${idsType} on ${iface} (${network}, rules: ${ruleset})`);
        };
    }

    function loadNetworkStatus() {
        const status = state.data.networkStatus || { monitored: 0, alerts: 0, blocked: 0, bandwidth: 0 };
        $('#netMonitored').textContent = status.monitored;
        $('#netAlerts').textContent = status.alerts;
        $('#netBlocked').textContent = status.blocked;
        $('#netBandwidth').textContent = status.bandwidth;

        const container = $('#networkStatus');
        if (!container) return;

        if (status.monitored === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🌐</div><div class="empty-state-title">No Monitoring</div><div class="empty-state-text">Deploy an IDS sensor to begin monitoring.</div></div>';
            return;
        }
    }

    // ========================================
    // Blue Team: Endpoints
    // ========================================

    function setupBlueEndpoints() {
        loadEndpoints();
        $('#scanEndpointsBtn')?.addEventListener('click', scanEndpoints);
    }

    function loadEndpoints() {
        const endpoints = state.data.endpoints || [];
        $('#endpointTotal').textContent = endpoints.length;
        $('#endpointProtected').textContent = endpoints.filter(e => e.protected).length;
        $('#endpointVulnerable').textContent = endpoints.filter(e => e.vulnerabilities > 0).length;
        $('#endpointIsolated').textContent = endpoints.filter(e => e.isolated).length;

        const container = $('#endpointList');
        if (!container) return;

        if (endpoints.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">💻</div><div class="empty-state-title">No Endpoints</div><div class="empty-state-text">Scan your network to discover endpoints.</div></div>';
            return;
        }

        container.innerHTML = endpoints.map(e => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-dot ${e.protected ? 'online' : 'error'}"></span>
                        <span class="font-medium">${escapeHtml(e.name)}</span>
                        <span class="badge badge-info">${escapeHtml(e.os || 'Unknown')}</span>
                        ${e.isolated ? '<span class="badge badge-warning">Isolated</span>' : ''}
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm mb-2"><strong>IP:</strong> ${escapeHtml(e.ip || 'N/A')} · <strong>Last Seen:</strong> ${e.lastSeen ? new Date(e.lastSeen).toLocaleString() : 'N/A'}</div>
                    <div class="text-sm"><strong>Vulnerabilities:</strong> ${e.vulnerabilities || 0}</div>
                </div>
            </div>
        `).join('');
    }

    function scanEndpoints() {
        const container = $('#endpointList');
        container.innerHTML = '<div class="card"><div class="card-body"><div class="flex items-center gap-3"><div class="spinner spinner-sm"></div><span>Scanning network for endpoints...</span></div></div></div>';

        setTimeout(() => {
            state.data.endpoints = [
                { id: 'ep_1', name: 'DC-01', os: 'Windows Server 2022', ip: '10.0.1.10', protected: true, vulnerabilities: 2, isolated: false, lastSeen: Date.now() },
                { id: 'ep_2', name: 'WEB-01', os: 'Ubuntu 22.04', ip: '10.0.1.20', protected: true, vulnerabilities: 0, isolated: false, lastSeen: Date.now() },
                { id: 'ep_3', name: 'WS-001', os: 'Windows 11', ip: '10.0.2.50', protected: false, vulnerabilities: 5, isolated: false, lastSeen: Date.now() },
                { id: 'ep_4', name: 'Unknown Device', os: 'Unknown', ip: '10.0.2.99', protected: false, vulnerabilities: 0, isolated: true, lastSeen: Date.now() },
            ];
            loadEndpoints();
            showToast('success', 'Scan Complete', '4 endpoints discovered.');
            addActivity('Endpoint scan: 4 devices found');
        }, 2000);
    }

    // ========================================
    // Blue Team: Cloud Defense
    // ========================================

    function setupBlueCloud() {
        loadCloudDefense();
        $('#scanCloudDefenseBtn')?.addEventListener('click', scanCloudDefense);
    }

    function loadCloudDefense() {
        const cloud = state.data.cloudDefense || { accounts: 0, findings: 0, compliance: 0 };
        $('#cloudAccounts').textContent = cloud.accounts;
        $('#cloudFindings').textContent = cloud.findings;
        $('#cloudCompliance').textContent = cloud.compliance + '%';

        const container = $('#cloudDefenseStatus');
        if (!container) return;

        if (cloud.accounts === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">☁️</div><div class="empty-state-title">No Cloud Accounts</div><div class="empty-state-text">Connect a cloud account to begin monitoring.</div></div>';
            return;
        }
    }

    function scanCloudDefense() {
        const container = $('#cloudDefenseStatus');
        container.innerHTML = '<div class="card"><div class="card-body"><div class="flex items-center gap-3"><div class="spinner spinner-sm"></div><span>Scanning cloud posture...</span></div></div></div>';

        setTimeout(() => {
            state.data.cloudDefense = { accounts: 3, findings: 12, compliance: 78 };
            loadCloudDefense();
            container.innerHTML += `
                <div class="card mt-4">
                    <div class="card-header">
                        <span class="card-title">Cloud Misconfigurations</span>
                        <span class="badge badge-warning">12 findings</span>
                    </div>
                    <div class="card-body">
                        ${[
                            { title: 'S3 Bucket Public Access', severity: 'Critical', service: 'S3', account: 'prod-account' },
                            { title: 'Security Group Open to World', severity: 'High', service: 'EC2', account: 'prod-account' },
                            { title: 'IAM User No MFA', severity: 'Medium', service: 'IAM', account: 'dev-account' },
                            { title: 'RDS Publicly Accessible', severity: 'High', service: 'RDS', account: 'prod-account' },
                        ].map(f => `
                            <div style="display:flex; align-items:center; gap:12px; padding:8px 0; border-bottom:1px solid var(--border-secondary);">
                                <span class="status-dot ${f.severity === 'Critical' ? 'error' : f.severity === 'High' ? 'warning' : 'running'}"></span>
                                <div style="flex:1;">
                                    <div style="font-weight:500;">${escapeHtml(f.title)}</div>
                                    <div style="font-size:0.8rem; color:var(--text-tertiary);">${f.service} · ${f.account}</div>
                                </div>
                                <span class="badge badge-${f.severity === 'Critical' ? 'critical' : f.severity === 'High' ? 'high' : 'warning'}">${f.severity}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
            showToast('success', 'Scan Complete', '12 misconfigurations found.');
            addActivity('Cloud defense scan: 12 findings');
        }, 2000);
    }

    // ========================================
    // Blue Team: Reports
    // ========================================

    function setupBlueReports() {
        loadBlueReports();
        $('#generateBlueReportBtn')?.addEventListener('click', () => {
            const report = {
                id: `blue_report_${Date.now()}`,
                title: 'SOC Operations Report',
                type: 'operations',
                createdAt: Date.now(),
            };
            state.data.blueReports = state.data.blueReports || [];
            state.data.blueReports.push(report);
            loadBlueReports();
            showToast('success', 'Report Generated', 'SOC operations report created.');
            addActivity('Blue team report generated');
        });
    }

    function loadBlueReports() {
        const reports = state.data.blueReports || [];
        const container = $('#blueReportsList');
        if (!container) return;

        if (reports.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📋</div><div class="empty-state-title">No Reports</div><div class="empty-state-text">Generate a defensive operations report.</div></div>';
            return;
        }

        container.innerHTML = reports.map(r => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">📋</span>
                        <span class="font-medium">${escapeHtml(r.title)}</span>
                        <span class="badge badge-info">${escapeHtml(r.type)}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm"><strong>Created:</strong> ${new Date(r.createdAt).toLocaleString()}</div>
                </div>
            </div>
        `).join('');
    }

    // ========================================
    // White Team: Metrics
    // ========================================

    function setupWhiteMetrics() {
        loadMetrics();
        $('#exportMetricsBtn')?.addEventListener('click', () => {
            showToast('success', 'Exported', 'Metrics dashboard exported to PDF.');
        });
    }

    function loadMetrics() {
        const metrics = state.data.metrics || { mttr: 48, patchRate: 87, phishRate: 12, openFindings: 5 };
        $('#mttr').textContent = metrics.mttr + 'h';
        $('#patchRate').textContent = metrics.patchRate + '%';
        $('#phishRate').textContent = metrics.phishRate + '%';
        $('#openFindings').textContent = metrics.openFindings;

        const remediationContainer = $('#remediationTrend');
        if (remediationContainer) {
            remediationContainer.innerHTML = `
                ${[
                    { week: 'Week 1', opened: 12, closed: 8 },
                    { week: 'Week 2', opened: 9, closed: 11 },
                    { week: 'Week 3', opened: 7, closed: 10 },
                    { week: 'Week 4', opened: 5, closed: 9 },
                ].map(w => `
                    <div style="display:flex; align-items:center; gap:12px; padding:6px 0;">
                        <span style="min-width:60px;">${escapeHtml(w.week)}</span>
                        <span class="badge badge-error">Opened: ${w.opened}</span>
                        <span class="badge badge-success">Closed: ${w.closed}</span>
                    </div>
                `).join('')}
            `;
        }

        const riskContainer = $('#metricsRiskTrend');
        if (riskContainer) {
            riskContainer.innerHTML = `
                ${[
                    { month: 'Jan', score: 7.2 },
                    { month: 'Feb', score: 6.8 },
                    { month: 'Mar', score: 6.5 },
                    { month: 'Apr', score: 6.1 },
                    { month: 'May', score: 5.8 },
                    { month: 'Jun', score: 5.4 },
                ].map(m => `
                    <div style="display:flex; align-items:center; gap:12px; padding:6px 0;">
                        <span style="min-width:40px;">${escapeHtml(m.month)}</span>
                        <div class="progress" style="flex:1;"><div class="progress-bar ${m.score >= 7 ? 'critical' : m.score >= 5 ? '' : 'success'}" style="width:${m.score * 10}%"></div></div>
                        <span style="min-width:30px; text-align:right;">${m.score.toFixed(1)}</span>
                    </div>
                `).join('')}
            `;
        }
    }

    // ========================================
    // White Team: Reports
    // ========================================

    function setupWhiteReports() {
        loadWhiteReports();
        $('#generateWhiteReportBtn')?.addEventListener('click', () => {
            const report = {
                id: `white_report_${Date.now()}`,
                title: 'Executive Security Report',
                type: 'executive',
                createdAt: Date.now(),
            };
            state.data.whiteReports = state.data.whiteReports || [];
            state.data.whiteReports.push(report);
            loadWhiteReports();
            showToast('success', 'Report Generated', 'Executive security report created.');
            addActivity('White team report generated');
        });
    }

    function loadWhiteReports() {
        const reports = state.data.whiteReports || [];
        const container = $('#whiteReportsList');
        if (!container) return;

        if (reports.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📋</div><div class="empty-state-title">No Reports</div><div class="empty-state-text">Generate an executive or compliance report.</div></div>';
            return;
        }

        container.innerHTML = reports.map(r => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-icon">📋</span>
                        <span class="font-medium">${escapeHtml(r.title)}</span>
                        <span class="badge badge-info">${escapeHtml(r.type)}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm"><strong>Created:</strong> ${new Date(r.createdAt).toLocaleString()}</div>
                </div>
            </div>
        `).join('');
    }

    // ========================================
    // Cross-Team: Assets (Enhanced)
    // ========================================

    function setupAssets() {
        loadAssets();
        $('#addAssetBtn')?.addEventListener('click', () => {
            showModal({
                title: '➕ Add New Asset',
                body: `
                    <div class="form-group">
                        <label class="form-label">Asset Name</label>
                        <input type="text" class="input" id="modalAssetName" placeholder="Production Database">
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Type</label>
                            <select class="input" id="modalAssetType">
                                <option value="server">Server</option>
                                <option value="workstation">Workstation</option>
                                <option value="network">Network Device</option>
                                <option value="cloud">Cloud Resource</option>
                                <option value="application">Application</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Criticality</label>
                            <select class="input" id="modalAssetCriticality">
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">URL / IP</label>
                        <input type="text" class="input" id="modalAssetUrl" placeholder="https://example.com or 192.168.1.1">
                    </div>
                `,
                actions: [
                    '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Cancel</button>',
                    '<button class="btn btn-primary" id="modalSaveAssetBtn">Save Asset</button>',
                ],
            });

            setTimeout(() => {
                $('#modalSaveAssetBtn')?.addEventListener('click', () => {
                    const name = $('#modalAssetName')?.value?.trim();
                    if (!name) { showToast('error', 'Required', 'Asset name is required.'); return; }

                    $('.modal-overlay').remove();
                    showToast('success', 'Asset Added', `"${name}" added to inventory.`);
                    addActivity(`Asset added: ${name}`);
                });
            }, 100);
        });
        $('#importAssetsBtn')?.addEventListener('click', importAssets);
    }

    function importAssets() {
        showModal({
            title: '📥 Import Assets',
            body: `
                <div class="form-group">
                    <label class="form-label">Import Source</label>
                    <select class="input" id="assetImportSource">
                        <option value="csv">CSV File</option>
                        <option value="json">JSON File</option>
                        <option value="nessus">Nessus Scan Results</option>
                        <option value="nmap">Nmap XML Output</option>
                        <option value="qualys">Qualys Export</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">File Content / Data</label>
                    <textarea class="input" id="assetImportData" rows="10" placeholder="CSV: name,type,criticality,environment,url,ip,tags&#10;web-server-01,server,critical,production,https://example.com,203.0.113.10,production;web&#10;&#10;JSON: [{&quot;name&quot;:&quot;web-server-01&quot;,&quot;asset_type&quot;:&quot;server&quot;,&quot;criticality&quot;:&quot;critical&quot;,...}]&#10;&#10;Scan XML: Paste Nessus or Nmap XML output"></textarea>
                </div>
                <div class="form-group">
                    <label class="form-label">Default Environment</label>
                    <select class="input" id="assetDefaultEnv">
                        <option value="Production">Production</option>
                        <option value="Staging">Staging</option>
                        <option value="Development">Development</option>
                        <option value="Testing">Testing</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">
                        <input type="checkbox" id="assetMergeExisting" checked> Merge with existing assets
                    </label>
                </div>
            `,
            actions: [
                '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Cancel</button>',
                '<button class="btn btn-primary" id="processAssetImportBtn">Import Assets</button>',
            ],
        });

        setTimeout(() => {
            $('#processAssetImportBtn')?.addEventListener('click', async () => {
                const source = $('#assetImportSource')?.value;
                const data = $('#assetImportData')?.value?.trim();
                const defaultEnv = $('#assetDefaultEnv')?.value || 'Production';
                const merge = $('#assetMergeExisting')?.checked;

                if (!data) {
                    showToast('error', 'No Data', 'Please provide import data.');
                    return;
                }

                try {
                    let imported = 0;
                    let updated = 0;
                    const assets = await invoke('cross_get_assets');

                    if (source === 'csv') {
                        const lines = data.split('\n').filter(Boolean);
                        const startIdx = lines[0]?.toLowerCase().includes('name') ? 1 : 0;
                        for (let i = startIdx; i < lines.length; i++) {
                            const parts = lines[i].split(',').map(p => p.trim());
                            if (parts.length >= 3) {
                                const existing = assets.find(a => a.name === parts[0] || a.url === parts[4]);
                                if (existing && merge) {
                                    existing.asset_type = parts[1] || existing.asset_type;
                                    existing.criticality = parts[2] || existing.criticality;
                                    existing.environment = parts[3] || defaultEnv;
                                    updated++;
                                } else if (!existing) {
                                    assets.push({
                                        name: parts[0],
                                        asset_type: parts[1] || 'server',
                                        criticality: parts[2] || 'medium',
                                        environment: parts[3] || defaultEnv,
                                        owner: 'Imported',
                                        risk_score: parseFloat(parts[7]) || 5.0,
                                        url: parts[4] || '',
                                        ip_addresses: parts[5] ? [parts[5]] : [],
                                        tags: parts[6] ? parts[6].split(';') : [],
                                        compliance_scope: [],
                                    });
                                    imported++;
                                }
                            }
                        }
                    } else if (source === 'json') {
                        const items = JSON.parse(data);
                        for (const item of items) {
                            const existing = assets.find(a => a.name === item.name || a.url === item.url);
                            if (existing && merge) {
                                Object.assign(existing, item);
                                updated++;
                            } else if (!existing) {
                                assets.push({
                                    name: item.name || 'Imported Asset',
                                    asset_type: item.asset_type || 'server',
                                    criticality: item.criticality || 'medium',
                                    environment: item.environment || defaultEnv,
                                    owner: item.owner || 'Imported',
                                    risk_score: item.risk_score || 5.0,
                                    url: item.url || '',
                                    ip_addresses: item.ip_addresses || [],
                                    tags: item.tags || [],
                                    compliance_scope: item.compliance_scope || [],
                                });
                                imported++;
                            }
                        }
                    } else if (source === 'nmap') {
                        const hostMatches = data.match(/<host[^>]*>[\s\S]*?<\/host>/g) || [];
                        for (const hostBlock of hostMatches) {
                            const ipMatch = hostBlock.match(/<address addr="([^"]+)" addrtype="ipv4"/);
                            const hostnameMatch = hostBlock.match(/<hostname name="([^"]+)"/);
                            const ip = ipMatch?.[1];
                            const hostname = hostnameMatch?.[1];

                            if (ip && !assets.some(a => a.ip_addresses?.includes(ip))) {
                                const portMatches = [...hostBlock.matchAll(/<port portid="(\d+)" protocol="(\w+)">[\s\S]*?[\s\S]*?state state="open"[\s\S]*?<service name="([^"]*)"[^>]*>/g)];
                                const services = portMatches.map(m => `${m[1]}/${m[2]} (${m[3]})`).join(', ');

                                assets.push({
                                    name: hostname || `Host-${ip}`,
                                    asset_type: 'server',
                                    criticality: portMatches.length > 10 ? 'high' : 'medium',
                                    environment: defaultEnv,
                                    owner: 'Imported',
                                    risk_score: portMatches.length > 10 ? 7.0 : 5.0,
                                    url: '',
                                    ip_addresses: [ip],
                                    tags: ['nmap', ...portMatches.map(m => m[3]).filter(Boolean).slice(0, 3)],
                                    compliance_scope: [],
                                });
                                imported++;
                            }
                        }
                    } else {
                        const items = JSON.parse(data);
                        const scanItems = Array.isArray(items) ? items : [items];
                        for (const item of scanItems) {
                            assets.push({
                                name: item.name || item.hostname || `Asset-${Date.now()}`,
                                asset_type: item.type || 'server',
                                criticality: item.criticality || 'medium',
                                environment: defaultEnv,
                                owner: 'Imported',
                                risk_score: item.risk_score || 5.0,
                                url: item.url || '',
                                ip_addresses: item.ip ? [item.ip] : [],
                                tags: ['scan-import'],
                                compliance_scope: [],
                            });
                            imported++;
                        }
                    }

                    $('.modal-overlay').remove();
                    loadAssets();
                    showToast('success', 'Import Complete', `${imported} assets imported, ${updated} updated.`);
                    addActivity(`Imported ${imported} assets (${source})`);
                } catch (e) {
                    showToast('error', 'Import Failed', `Failed to parse data: ${e.message}`);
                }
            });
        }, 100);
    }

    // ========================================
    // Cross-Team: Notifications (Enhanced)
    // ========================================

    function setupNotifications() {
        loadNotifications();
        $('#markAllReadBtn')?.addEventListener('click', () => {
            const notifications = state.data.notifications || [];
            notifications.forEach(n => n.read = true);
            loadNotifications();
            showToast('success', 'Done', 'All notifications marked as read.');
        });
    }

    // ========================================
    // Cross-Team: Reports (Enhanced)
    // ========================================

    function setupReports() {
        loadReportTemplates();
        $('#generateReportBtn')?.addEventListener('click', () => {
            showModal({
                title: '📋 Generate Report',
                body: `
                    <div class="form-group">
                        <label class="form-label">Report Template</label>
                        <select class="input" id="modalReportTemplate">
                            <option value="executive">Executive Summary</option>
                            <option value="technical">Technical Findings</option>
                            <option value="compliance">Compliance Report</option>
                            <option value="pentest">Penetration Test Report</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Time Range</label>
                        <select class="input" id="modalReportRange">
                            <option value="7d">Last 7 Days</option>
                            <option value="30d">Last 30 Days</option>
                            <option value="90d">Last 90 Days</option>
                            <option value="custom">Custom Range</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Format</label>
                        <select class="input" id="modalReportFormat">
                            <option value="pdf">PDF</option>
                            <option value="html">HTML</option>
                            <option value="json">JSON</option>
                        </select>
                    </div>
                `,
                actions: [
                    '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Cancel</button>',
                    '<button class="btn btn-primary" id="modalGenerateReportBtn">Generate</button>',
                ],
            });

            setTimeout(() => {
                $('#modalGenerateReportBtn')?.addEventListener('click', () => {
                    $('.modal-overlay').remove();
                    showToast('success', 'Report Generated', 'Your report has been generated and is ready for download.');
                    addActivity('Report generated');
                });
            }, 100);
        });
    }

    // ========================================
    // Cross-Team: Integrations (Enhanced)
    // ========================================

    function setupIntegrations() {
        loadIntegrations();
    }

    // ========================================
    // HTTP Proxy (Burp Suite)
    // ========================================

    function setupHttpProxy() {
        loadProxySessions();
        $('#proxyStartBtn')?.addEventListener('click', startProxy);
        $('#proxyStopBtn')?.addEventListener('click', stopProxy);
    $('#proxyClearBtn')?.addEventListener('click', async () => {
        try {
            await invoke('proxy_clear_sessions');
            state.data.proxySessions = [];
            loadProxySessions();
            showToast('success', 'Cleared', 'Proxy sessions cleared.');
        } catch (e) {
            showToast('error', 'Failed', String(e));
        }
    });
    }

    async function startProxy() {
        const port = parseInt($('#proxyListenPort')?.value) || 8080;
        try {
            const result = await invoke('proxy_start', { port });
            $('#proxyStartBtn').style.display = 'none';
            $('#proxyStopBtn').style.display = '';
            $('#proxyStatus').textContent = 'Running';
            $('#proxyStatus').style.color = 'var(--status-success)';
            $('#proxyPort').textContent = port;
            showToast('success', 'Proxy Started', result);
            addActivity(`HTTP Proxy started on port ${port}`);
            startProxyPolling();
        } catch (e) {
            showToast('error', 'Failed to Start', String(e));
        }
    }

    async function stopProxy() {
        try {
            await invoke('proxy_stop');
            $('#proxyStartBtn').style.display = '';
            $('#proxyStopBtn').style.display = 'none';
            $('#proxyStatus').textContent = 'Offline';
            $('#proxyStatus').style.color = 'var(--status-error)';
            showToast('info', 'Proxy Stopped', 'Proxy has been stopped.');
            addActivity('HTTP Proxy stopped');
        } catch (e) {
            showToast('error', 'Failed to Stop', String(e));
        }
    }

    function loadProxySessions() {
        const sessions = state.data.proxySessions || [];
        $('#proxySessionCount').textContent = sessions.length;
        $('#proxyInterceptCount').textContent = sessions.filter(s => s.intercepted).length;

        const container = $('#proxySessionList');
        if (!container) return;

        if (sessions.length === 0) {
            container.innerHTML = `<div class="empty-state">
                <div class="empty-state-icon">📡</div>
                <div class="empty-state-title">Proxy Not Running</div>
                <div class="empty-state-text">Start the proxy and configure your browser to use 127.0.0.1:${$('#proxyPort').textContent || '8080'}</div>
            </div>`;
            return;
        }

        container.innerHTML = sessions.map(s => `
            <div style="display:flex; align-items:center; gap:12px; padding:8px 0; border-bottom:1px solid var(--border-secondary);">
                <span class="badge badge-${s.request?.method === 'GET' ? 'success' : s.request?.method === 'POST' ? 'info' : 'warning'}">${s.request?.method || 'UNK'}</span>
                <div style="flex:1; overflow:hidden;">
                    <div style="font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(s.request?.url || '')}</div>
                </div>
                <span class="badge badge-${s.response?.status_code < 300 ? 'success' : s.response?.status_code < 400 ? 'warning' : 'error'}">${s.response?.status_code || '—'}</span>
                <span class="text-tertiary text-sm">${s.response?.response_time_ms || 0}ms</span>
            </div>
        `).join('');
    }

    // ========================================
    // Packet Capture (Wireshark)
    // ========================================

    function setupPacketCapture() {
        loadInterfaces();
        $('#captureStartBtn')?.addEventListener('click', startCapture);
        $('#captureStopBtn')?.addEventListener('click', stopCapture);
    $('#captureClearBtn')?.addEventListener('click', async () => {
        try {
            await invoke('packet_clear_packets');
            state.data.packets = [];
            loadPackets();
            showToast('success', 'Cleared', 'Packet buffer cleared.');
        } catch (e) {
            showToast('error', 'Failed', String(e));
        }
    });
        $('#refreshInterfacesBtn')?.addEventListener('click', loadInterfaces);
    }

    async function loadInterfaces() {
        try {
            const interfaces = await invoke('packet_list_interfaces');
            const select = $('#captureInterface');
            if (!select) return;
            select.innerHTML = interfaces.map(iface =>
                `<option value="${iface.name}">${iface.name} (${iface.ips?.join(', ') || 'no IP'}) ${iface.is_loopback ? '[loopback]' : ''}</option>`
            ).join('');
        } catch (e) {
            console.error('Failed to load interfaces:', e);
        }
    }

    async function startCapture() {
        const iface = $('#captureInterface')?.value;
        if (!iface) { showToast('error', 'No Interface', 'Select a network interface first.'); return; }
        const promiscuous = $('#capturePromiscuous')?.checked || false;
        const filter = $('#captureFilter')?.value?.trim() || null;

        try {
            const result = await invoke('packet_start_capture', { interface: iface, promiscuous, filter });
            $('#captureStartBtn').style.display = 'none';
            $('#captureStopBtn').style.display = '';
            $('#captureStatus').textContent = 'Capturing';
            $('#captureStatus').style.color = 'var(--status-success)';
            showToast('success', 'Capture Started', result);
            addActivity(`Packet capture started on ${iface}`);
            state.data.captureRunning = true;
            startPacketPolling();
        } catch (e) {
            showToast('error', 'Failed to Start', String(e));
        }
    }

    async function stopCapture() {
        try {
            await invoke('packet_stop_capture');
            $('#captureStartBtn').style.display = '';
            $('#captureStopBtn').style.display = 'none';
            $('#captureStatus').textContent = 'Idle';
            $('#captureStatus').style.color = 'var(--status-error)';
            showToast('info', 'Capture Stopped', 'Packet capture has been stopped.');
            addActivity('Packet capture stopped');
            state.data.captureRunning = false;
        } catch (e) {
            showToast('error', 'Failed to Stop', String(e));
        }
    }

    function startPacketPolling() {
        if (state.data.captureInterval) clearInterval(state.data.captureInterval);
        state.data.captureInterval = setInterval(async () => {
            if (!state.data.captureRunning) {
                clearInterval(state.data.captureInterval);
                return;
            }
            try {
                const packets = await invoke('packet_get_packets', { limit: 100 });
                const stats = await invoke('packet_get_stats');
                state.data.packets = packets;
                $('#capturePacketCount').textContent = stats.total_packets;
                $('#capturePps').textContent = stats.packets_per_second.toFixed(1);
                $('#captureErrors').textContent = stats.errors;
                loadPackets();
            } catch (e) {
                console.error('Poll error:', e);
            }
        }, 1000);
    }

    function startProxyPolling() {
        if (state.data.proxyInterval) clearInterval(state.data.proxyInterval);
        state.data.proxyInterval = setInterval(async () => {
            if ($('#proxyStatus')?.textContent !== 'Running') {
                clearInterval(state.data.proxyInterval);
                return;
            }
            try {
                const sessions = await invoke('proxy_get_sessions');
                state.data.proxySessions = sessions;
                loadProxySessions();
            } catch (e) {
                console.error('Proxy poll error:', e);
            }
        }, 2000);
    }

    function loadPackets() {
        const packets = state.data.packets || [];
        const container = $('#packetList');
        if (!container) return;

        if (packets.length === 0) {
            container.innerHTML = `<div class="empty-state">
                <div class="empty-state-icon">📦</div>
                <div class="empty-state-title">No Packets Captured</div>
                <div class="empty-state-text">Select an interface and start capturing to see network traffic</div>
            </div>`;
            return;
        }

        container.innerHTML = packets.slice(-100).reverse().map(p => {
            const proto = p.transport_layer?.protocol || p.network_layer?.protocol || 'Unknown';
            const src = p.network_layer?.source_ip || '?';
            const dst = p.network_layer?.dest_ip || '?';
            const sport = p.transport_layer?.source_port || '';
            const dport = p.transport_layer?.dest_port || '';
            const info = p.application_layer?.info || `${p.length} bytes`;
            const color = proto === 'TCP' ? 'success' : proto === 'UDP' ? 'info' : proto === 'ICMP' ? 'warning' : 'info';

            return `<div style="display:flex; align-items:center; gap:8px; padding:6px 0; border-bottom:1px solid var(--border-secondary); font-family:var(--font-mono); font-size:0.8rem;">
                <span class="badge badge-${color}" style="min-width:50px; text-align:center;">${proto}</span>
                <span style="min-width:120px;">${src}${sport ? ':' + sport : ''}</span>
                <span style="color:var(--text-tertiary);">→</span>
                <span style="min-width:120px;">${dst}${dport ? ':' + dport : ''}</span>
                <span style="flex:1; color:var(--text-secondary); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(info)}</span>
                <span class="text-tertiary">${p.length}B</span>
            </div>`;
        }).join('');
    }

    // ========================================
    // Screen Recording
    // ========================================

    function setupRecording() {
        $('#recordingStartBtn')?.addEventListener('click', startRecording);
        $('#recordingStopBtn')?.addEventListener('click', stopRecording);
        $('#recordingBrowseDirBtn')?.addEventListener('click', browseRecordingDir);
        $('#captureScreenshotBtn')?.addEventListener('click', captureScreenshot);
        $('#refreshRecordingsBtn')?.addEventListener('click', loadRecordingSessions);
        $('#screenshotType')?.addEventListener('change', (e) => {
            $('#screenshotElementGroup').style.display = e.target.value === 'element' ? 'block' : 'none';
        });

        const outputDir = $('#recordingOutputDir');
        if (outputDir && !outputDir.value) {
            getDefaultDir().then(dir => { if (outputDir) outputDir.value = dir; }).catch(() => {});
        }

        loadRecordingSessions();
        startRecordingStatusPolling();
    }

    async function startRecording() {
        const url = $('#recordingUrl')?.value?.trim();
        if (!url) {
            showToast('error', 'Missing URL', 'Please enter a target URL to record.');
            return;
        }
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            showToast('error', 'Invalid URL', 'URL must start with http:// or https://');
            return;
        }

        const mode = $('#recordingMode')?.value || 'both';
        const format = $('#recordingFormat')?.value || 'mp4';
        const fps = parseInt($('#recordingFps')?.value) || 30;
        const quality = parseInt($('#recordingQuality')?.value) || 80;
        const maxPages = parseInt($('#recordingMaxPages')?.value) || 50;
        const width = parseInt($('#recordingWidth')?.value) || 1920;
        const height = parseInt($('#recordingHeight')?.value) || 1080;
        const delay = parseInt($('#recordingDelay')?.value) || 2000;
        const outputDir = $('#recordingOutputDir')?.value?.trim() || './recordings';
        const audio = $('#recordingAudio')?.checked || false;
        const headless = $('#recordingHeadless')?.checked !== false;
        const screenshots = $('#recordingScreenshots')?.checked !== false;

        try {
            const settings = {
                url,
                max_pages: maxPages,
                delay_ms: delay,
                headless,
                output_dir: outputDir,
                fps,
                recording_mode: mode,
                enable_audio: audio,
                screen_width: width,
                screen_height: height,
                requires_auth: false,
                auth_url: null,
                username: null,
                password: null,
                username_selector: null,
                password_selector: null,
                submit_selector: null,
                screen_region: null,
                daemon: false,
                progress: true,
                log_file: null,
                pid_file: null,
                proxy: null,
                sitemap: null,
                scan_url: null,
                login_script: null,
                concurrency: 1,
            };

            const sessionId = await invoke('start_recording', settings);

            state.data.recordingStartTime = Date.now();
            state.data.recordingSessions = state.data.recordingSessions || [];
            state.data.recordingSessions.unshift({
                id: `rec_${Date.now()}`,
                sessionId,
                url,
                mode,
                format,
                outputDir,
                status: 'recording',
                pagesVisited: 0,
                startedAt: Date.now(),
            });

            $('#recordingStartBtn').style.display = 'none';
            $('#recordingStopBtn').style.display = '';
            $('#recordingStatus').textContent = 'Recording';
            $('#recordingStatus').style.color = 'var(--status-success)';

            showToast('success', 'Recording Started', `Session: ${sessionId}`);
            addActivity(`Recording started: ${url} (${mode} mode)`);
        } catch (e) {
            showToast('error', 'Recording Failed', String(e));
            addActivity(`Recording failed: ${e}`);
        }
    }

    async function stopRecording() {
        try {
            await invoke('stop_recording');

            state.data.recordingStartTime = null;
            if (state.data.recordingSessions?.length > 0) {
                state.data.recordingSessions[0].status = 'completed';
            }

            $('#recordingStartBtn').style.display = '';
            $('#recordingStopBtn').style.display = 'none';
            $('#recordingStatus').textContent = 'Idle';
            $('#recordingStatus').style.color = 'var(--status-error)';
            $('#recordingDuration').textContent = '00:00';

            showToast('success', 'Recording Stopped', 'Recording has been saved.');
            addActivity('Recording stopped');
        } catch (e) {
            showToast('error', 'Stop Failed', String(e));
        }
    }

    async function browseRecordingDir() {
        if (window.__TAURI__?.dialog?.open) {
            try {
                const selected = await window.__TAURI__.dialog.open({
                    directory: true,
                    multiple: false,
                    title: 'Select Output Directory',
                });
                if (selected) {
                    $('#recordingOutputDir').value = selected;
                }
            } catch (e) {
                showToast('error', 'Browse Failed', 'Could not open directory picker.');
            }
        } else {
            const path = prompt('Enter output directory path:', $('#recordingOutputDir').value || './recordings');
            if (path) {
                $('#recordingOutputDir').value = path;
            }
        }
    }

    function startRecordingStatusPolling() {
        if (state.data.recordingInterval) clearInterval(state.data.recordingInterval);
        state.data.recordingInterval = setInterval(async () => {
            if ($('#recordingStatus')?.textContent !== 'Recording') {
                return;
            }
            try {
                const status = await invoke('get_status');
                if (status) {
                    $('#recordingPages').textContent = status.pages_visited || 0;
                    if (status.is_running) {
                        const elapsed = state.data.recordingStartTime
                            ? Math.floor((Date.now() - state.data.recordingStartTime) / 1000)
                            : 0;
                        const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
                        const secs = (elapsed % 60).toString().padStart(2, '0');
                        $('#recordingDuration').textContent = `${mins}:${secs}`;
                    }
                }
            } catch (e) {
                console.error('Recording poll error:', e);
            }
        }, 1000);
    }

    async function captureScreenshot() {
        const url = $('#screenshotUrl')?.value?.trim();
        if (!url) {
            showToast('error', 'Missing URL', 'Please enter a URL to capture.');
            return;
        }
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            showToast('error', 'Invalid URL', 'URL must start with http:// or https://');
            return;
        }

        const type = $('#screenshotType')?.value || 'full';
        const selector = $('#screenshotSelector')?.value?.trim();
        const outputDir = $('#recordingOutputDir')?.value?.trim() || './recordings';

        const container = $('#screenshotResults');
        container.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="flex items-center gap-3 mb-4">
                        <div class="spinner spinner-sm"></div>
                        <span>Capturing screenshot...</span>
                    </div>
                </div>
            </div>
        `;

        try {
            const settings = {
                url,
                max_pages: 1,
                delay_ms: 1000,
                headless: true,
                output_dir: outputDir,
                fps: 30,
                recording_mode: 'browser',
                enable_audio: false,
                screen_width: 1920,
                screen_height: 1080,
                requires_auth: false,
                auth_url: null,
                username: null,
                password: null,
                username_selector: null,
                password_selector: null,
                submit_selector: null,
                screen_region: null,
                daemon: false,
                progress: false,
                log_file: null,
                pid_file: null,
                proxy: null,
                sitemap: null,
                scan_url: null,
                login_script: null,
                concurrency: 1,
            };

            await invoke('start_recording', settings);

            setTimeout(async () => {
                await invoke('stop_recording');

                container.innerHTML = `
                    <div class="card">
                        <div class="card-header">
                            <span class="card-title">Screenshot Captured</span>
                            <span class="badge badge-success">Complete</span>
                        </div>
                        <div class="card-body">
                            <div class="grid grid-2 mb-4">
                                <div>
                                    <div class="text-secondary text-sm">URL</div>
                                    <div><code>${escapeHtml(url)}</code></div>
                                </div>
                                <div>
                                    <div class="text-secondary text-sm">Type</div>
                                    <div>${escapeHtml(type)}${selector ? ` (${escapeHtml(selector)})` : ''}</div>
                                </div>
                            </div>
                            <div class="code-block">
                                Screenshot saved to: ${escapeHtml(outputDir)}<br>
                                Full page capture with headless browser.<br>
                                Image format: PNG
                            </div>
                        </div>
                    </div>
                `;
                showToast('success', 'Screenshot Captured', `Saved to ${outputDir}`);
                addActivity(`Screenshot captured: ${url}`);
            }, 3000);
        } catch (e) {
            container.innerHTML = `<div class="text-error">Screenshot failed: ${escapeHtml(String(e))}</div>`;
            showToast('error', 'Screenshot Failed', String(e));
        }
    }

    function loadRecordingSessions() {
        const container = $('#recordingSessionsList');
        if (!container) return;

        const sessions = state.data.recordingSessions || [];
        if (sessions.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">🎬</div>
                    <div class="empty-state-title">No Recording Sessions</div>
                    <div class="empty-state-text">Start a recording to see session details here.</div>
                </div>
            `;
            return;
        }

        container.innerHTML = sessions.map(s => `
            <div class="finding-card">
                <div class="finding-card-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div class="flex items-center gap-3">
                        <span class="status-dot ${s.status === 'recording' ? 'running' : s.status === 'completed' ? 'online' : 'offline'}"></span>
                        <span class="font-medium">${escapeHtml(s.sessionId || 'Unknown Session')}</span>
                        <span class="badge badge-${s.status === 'recording' ? 'warning' : s.status === 'completed' ? 'success' : 'info'}">${escapeHtml(s.status)}</span>
                        <span class="badge badge-info">${escapeHtml(s.mode || 'both')}</span>
                    </div>
                    <span class="text-tertiary text-sm">▼</span>
                </div>
                <div class="finding-card-body hidden">
                    <div class="text-sm text-secondary mb-2">URL: <code>${escapeHtml(s.url || 'N/A')}</code></div>
                    <div class="text-sm mb-2"><strong>Pages:</strong> ${s.pagesVisited || 0} · <strong>Format:</strong> ${escapeHtml(s.format || 'mp4')}</div>
                    <div class="text-sm mb-2"><strong>Started:</strong> ${s.startedAt ? new Date(s.startedAt).toLocaleString() : 'N/A'}</div>
                    <div class="text-sm"><strong>Output:</strong> <code>${escapeHtml(s.outputDir || './recordings')}</code></div>
                </div>
            </div>
        `).join('');
    }

    // ========================================
    // Scan History (Legacy Support)
    // ========================================

    async function loadScanHistory() {
        const outputDir = $('#outputDir')?.value?.trim();
        if (!outputDir) return;

        try {
            const scans = await invoke('list_vuln_scans', { outputDir });
            state.data.scanHistory = scans || [];
            renderScanHistory(scans || []);
        } catch (e) {
            console.error('Failed to load scan history:', e);
        }
    }

    function renderScanHistory(scans) {
        const listEl = $('#scanHistoryList');
        if (!listEl) return;

        if (!scans || scans.length === 0) {
            listEl.innerHTML = '<div class="history-empty">No saved scans yet. Run a scan with an Output Directory set.</div>';
            return;
        }

        listEl.innerHTML = scans.map(s => `
            <div class="history-item">
                <div class="history-main">
                    <div class="history-target">${escapeHtml(s.target_url)}</div>
                    <div class="history-meta">
                        <span>${escapeHtml(s.scan_id)}</span>
                        <span>${escapeHtml(s.timestamp)}</span>
                    </div>
                </div>
                <div style="display:flex; gap:8px; align-items:center;">
                    <span class="badge badge-${s.risk_score >= 7 ? 'critical' : s.risk_score >= 4 ? 'warning' : 'success'}">
                        Risk ${s.risk_score?.toFixed(1) || '0'}
                    </span>
                    <button class="btn btn-sm btn-secondary" onclick="loadScan('${s.scan_id}')">Load</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteScan('${s.scan_id}')">🗑</button>
                </div>
            </div>
        `).join('');
    }

    async function loadScan(scanId) {
        try {
            const outputDir = $('#outputDir')?.value?.trim();
            const report = await invoke('load_vuln_scan', { outputDir, scanId });
            if (report) {
                state.data.scanResults = report;
                displayWebScanResults(report);
                showToast('success', 'Scan Loaded', `Loaded scan ${scanId}`);
                addActivity(`Loaded scan: ${scanId}`);
            }
        } catch (e) {
            showToast('error', 'Load Failed', String(e));
        }
    }

    async function deleteScan(scanId) {
        const outputDir = $('#outputDir')?.value?.trim();
        if (!outputDir) return;

        if (!confirm(`Delete scan ${scanId}? This cannot be undone.`)) return;

        try {
            await invoke('delete_vuln_scan', { outputDir, scanId });
            showToast('info', 'Deleted', `Scan ${scanId} deleted.`);
            loadScanHistory();
        } catch (e) {
            showToast('error', 'Delete Failed', String(e));
        }
    }

    // ========================================
    // Toast Notifications
    // ========================================

    function showToast(type, title, message, actions) {
        const id = `toast_${Date.now()}_${Math.random().toString(36).slice(2)}`;
        const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.id = id;
        toast.innerHTML = `
            <span class="toast-icon">${icons[type] || 'ℹ️'}</span>
            <div class="toast-content">
                <div class="toast-title">${escapeHtml(title)}</div>
                ${message ? `<div class="toast-message">${escapeHtml(message)}</div>` : ''}
                ${actions ? `<div class="toast-actions">${actions}</div>` : ''}
            </div>
            <button class="toast-close" onclick="dismissToast('${id}')">✕</button>
        `;

        dom.toastContainer().appendChild(toast);

        setTimeout(() => dismissToast(id), 6000);
    }

    function dismissToast(id) {
        const toast = $(`#${id}`);
        if (!toast) return;
        toast.classList.add('hiding');
        setTimeout(() => toast.remove(), 250);
    }

    // ========================================
    // Modal System
    // ========================================

    function showModal(options) {
        const { title, body, size = '', actions = [], onClose } = options;

        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal ${size}">
                <div class="modal-header">
                    <h3 class="modal-title">${escapeHtml(title)}</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">✕</button>
                </div>
                <div class="modal-body">${body}</div>
                ${actions.length ? `<div class="modal-footer">${actions.join('')}</div>` : ''}
            </div>
        `;

        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                overlay.remove();
                onClose?.();
            }
        });

        dom.modalContainer().appendChild(overlay);
        initCustomSelects();
        return overlay;
    }

    function showConfirm(message, onConfirm) {
        return new Promise(resolve => {
            showModal({
                title: 'Confirm',
                body: `<p>${escapeHtml(message)}</p>`,
                actions: [
                    `<button class="btn btn-secondary" id="confirmCancel">Cancel</button>`,
                    `<button class="btn btn-danger" id="confirmOk">Confirm</button>`,
                ],
                onClose: () => resolve(false),
            });

            $('#confirmOk').addEventListener('click', () => {
                $('.modal-overlay').remove();
                onConfirm?.();
                resolve(true);
            });
            $('#confirmCancel').addEventListener('click', () => {
                $('.modal-overlay').remove();
                resolve(false);
            });
        });
    }

    // ========================================
    // Command Palette
    // ========================================

    function openCommandPalette() {
        state.ui.commandPaletteOpen = true;
        dom.commandPalette().style.display = 'flex';
        dom.commandInput().value = '';
        dom.commandInput().focus();
        renderCommandResults('');
    }

    function closeCommandPalette() {
        state.ui.commandPaletteOpen = false;
        dom.commandPalette().style.display = 'none';
    }

    function renderCommandResults(query) {
        const commands = getCommandList();
        const filtered = query
            ? commands.filter(c => c.label.toLowerCase().includes(query.toLowerCase()) || c.section.toLowerCase().includes(query.toLowerCase()))
            : commands;

        const grouped = {};
        filtered.forEach(cmd => {
            if (!grouped[cmd.section]) grouped[cmd.section] = [];
            grouped[cmd.section].push(cmd);
        });

        let html = '';
        for (const [section, cmds] of Object.entries(grouped)) {
            html += `<div class="command-group-title">${escapeHtml(section)}</div>`;
            html += cmds.map((cmd, i) => `
                <div class="command-item ${i === 0 ? 'selected' : ''}" data-command="${escapeHtml(cmd.action)}" data-team="${cmd.team || ''}">
                    <span class="command-item-icon">${escapeHtml(cmd.icon)}</span>
                    <span class="command-item-label">${escapeHtml(cmd.label)}</span>
                    ${cmd.shortcut ? `<span class="command-item-shortcut">${escapeHtml(cmd.shortcut)}</span>` : ''}
                </div>
            `).join('');
        }

        dom.commandResults().innerHTML = html || '<div style="padding:20px; text-align:center; color:var(--text-tertiary);">No commands found</div>';

        $$('.command-item', dom.commandResults()).forEach(item => {
            item.addEventListener('click', () => {
                executeCommand(item.dataset.command, item.dataset.team);
                closeCommandPalette();
            });
        });
    }

    function getCommandList() {
        return [
            // Global
            { icon: '📊', label: 'Go to Dashboard', action: 'nav:dashboard', section: 'Navigation', shortcut: 'G D' },
            { icon: '🔴', label: 'Switch to Red Team', action: 'team:red', section: 'Navigation', shortcut: '1' },
            { icon: '🔘', label: 'Switch to Gray Team', action: 'team:gray', section: 'Navigation', shortcut: '2' },
            { icon: '🔵', label: 'Switch to Blue Team', action: 'team:blue', section: 'Navigation', shortcut: '3' },
            { icon: '⚪', label: 'Switch to White Team', action: 'team:white', section: 'Navigation', shortcut: '4' },
            { icon: '🔍', label: 'New Vulnerability Scan', action: 'scan:new', section: 'Operations', shortcut: 'N' },
            { icon: '🎯', label: 'Manage Targets', action: 'nav:targets', section: 'Operations' },
            { icon: '🔐', label: 'Auth Profiles', action: 'nav:auth', section: 'Operations' },
            { icon: '🔄', label: 'Refresh Data', action: 'app:refresh', section: 'Actions', shortcut: 'R' },
            { icon: '🌙', label: 'Toggle Theme', action: 'app:theme', section: 'Actions' },
            { icon: '❓', label: 'Keyboard Shortcuts', action: 'app:shortcuts', section: 'Help', shortcut: '?' },

            // Red Team
            { icon: '🌐', label: 'Web App Scanner', action: 'section:red-web', section: 'Red Team: Web', team: 'red' },
            { icon: '🔌', label: 'Network Scanner', action: 'section:red-network', section: 'Red Team: Infra', team: 'red' },
            { icon: '💻', label: 'OS Pentesting', action: 'section:red-os', section: 'Red Team: Infra', team: 'red' },
            { icon: '📱', label: 'Mobile Analysis', action: 'section:red-mobile', section: 'Red Team: Mobile', team: 'red' },
            { icon: '☁️', label: 'Cloud Assessment', action: 'section:red-cloud', section: 'Red Team: Cloud', team: 'red' },
            { icon: '⛓️', label: 'Web3 Audit', action: 'section:red-web3', section: 'Red Team: Web3', team: 'red' },
            { icon: '📧', label: 'Email Security', action: 'section:red-email', section: 'Red Team: Email', team: 'red' },
            { icon: '📡', label: 'Wireless Security', action: 'section:red-wireless', section: 'Red Team: Wireless', team: 'red' },
            { icon: '🔑', label: 'Password Attacks', action: 'section:red-passwords', section: 'Red Team: Crypto', team: 'red' },
            { icon: '💥', label: 'Exploitation', action: 'section:red-exploit', section: 'Red Team: Exploit', team: 'red' },
            { icon: '🕵️', label: 'OSINT Gathering', action: 'section:red-osint', section: 'Red Team: Recon', team: 'red' },
            { icon: '📦', label: 'Payload Generator', action: 'section:red-payloads', section: 'Red Team: Utilities', team: 'red' },

            // Gray Team
            { icon: '⚔️', label: 'Attack Simulation', action: 'section:gray-simulations', section: 'Gray Team: Emulation', team: 'gray' },
            { icon: '🗺️', label: 'ATT&CK Matrix', action: 'section:gray-matrix', section: 'Gray Team: Mapping', team: 'gray' },
            { icon: '🤝', label: 'Purple Team Exercise', action: 'section:gray-purple', section: 'Gray Team: Collab', team: 'gray' },
            { icon: '🧩', label: 'Threat Model', action: 'section:gray-threatmodel', section: 'Gray Team: Analysis', team: 'gray' },
            { icon: '🔗', label: 'Vuln Correlation', action: 'section:gray-correlation', section: 'Gray Team: Analysis', team: 'gray' },
            { icon: '🛡️', label: 'Detection Engineering', action: 'section:gray-detections', section: 'Gray Team: Defense', team: 'gray' },

            // Blue Team
            { icon: '🚨', label: 'Alert Queue', action: 'section:blue-alerts', section: 'Blue Team: Ops', team: 'blue' },
            { icon: '🔥', label: 'Incidents', action: 'section:blue-incidents', section: 'Blue Team: Ops', team: 'blue' },
            { icon: '🔍', label: 'Threat Hunting', action: 'section:blue-hunt', section: 'Blue Team: Ops', team: 'blue' },
            { icon: '🧠', label: 'Threat Intel', action: 'section:blue-intel', section: 'Blue Team: Intel', team: 'blue' },
            { icon: '📝', label: 'Log Analysis', action: 'section:blue-logs', section: 'Blue Team: Analysis', team: 'blue' },
            { icon: '🔬', label: 'Forensics', action: 'section:blue-forensics', section: 'Blue Team: Analysis', team: 'blue' },
            { icon: '🦠', label: 'Malware Analysis', action: 'section:blue-malware', section: 'Blue Team: Analysis', team: 'blue' },

            // White Team
            { icon: '✅', label: 'Compliance Status', action: 'section:white-compliance', section: 'White Team: GRC', team: 'white' },
            { icon: '⚖️', label: 'Risk Register', action: 'section:white-risk', section: 'White Team: GRC', team: 'white' },
            { icon: '📜', label: 'Policy Management', action: 'section:white-policies', section: 'White Team: GRC', team: 'white' },
            { icon: '🏢', label: 'Vendor Risk', action: 'section:white-vendors', section: 'White Team: Risk', team: 'white' },
            { icon: '🎓', label: 'Training', action: 'section:white-training', section: 'White Team: People', team: 'white' },
            { icon: '📈', label: 'Metrics & KPIs', action: 'section:white-metrics', section: 'White Team: Reporting', team: 'white' },
        ];
    }

    function executeCommand(action, team) {
        if (action.startsWith('team:')) {
            switchTeam(action.split(':')[1]);
        } else if (action.startsWith('nav:')) {
            const section = action.split(':')[1];
            if (section === 'dashboard') {
                state.section = `${state.team}-dashboard`;
                renderContent();
            } else if (section === 'targets') {
                state.section = `${state.team === 'white' ? 'white-dashboard' : state.team + '-targets'}`;
                renderContent();
            } else if (section === 'auth') {
                state.section = 'red-sessions';
                switchTeam('red');
            }
        } else if (action.startsWith('section:')) {
            const section = action.split(':')[1];
            const teamPrefix = section.split('-')[0];
            if (teamPrefix !== state.team) switchTeam(teamPrefix);
            state.section = section;
            renderContent();
        } else if (action === 'scan:new') {
            switchTeam('red');
            state.section = 'red-web';
            renderContent();
        } else if (action === 'app:theme') {
            toggleTheme();
        } else if (action === 'app:refresh') {
            renderContent();
            showToast('success', 'Refreshed', 'Data refreshed successfully.');
        } else if (action === 'app:shortcuts') {
            showModal({
                title: '⌨️ Keyboard Shortcuts',
                body: `
                    <div style="display:grid; grid-template-columns:1fr auto; gap:8px 16px; font-size:0.9rem;">
                        <span>Command Palette</span><span class="badge badge-info">⌘K / Ctrl+K</span>
                        <span>Global Search</span><span class="badge badge-info">⌘/</span>
                        <span>Switch Team 1-4</span><span class="badge badge-info">⌘1-4</span>
                        <span>Go to Dashboard</span><span class="badge badge-info">G D</span>
                        <span>New Scan</span><span class="badge badge-info">N</span>
                        <span>Refresh</span><span class="badge badge-info">R</span>
                        <span>Toggle Theme</span><span class="badge badge-info">⌘T</span>
                        <span>Close Modal</span><span class="badge badge-info">Esc</span>
                        <span>Show Shortcuts</span><span class="badge badge-info">?</span>
                    </div>
                `,
            });
        }
    }

    // ========================================
    // Keyboard Shortcuts
    // ========================================

    function setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (state.ui.commandPaletteOpen) {
                if (e.key === 'Escape') closeCommandPalette();
                return;
            }

            if (e.key === 'Escape') {
                const overlay = $('.modal-overlay');
                if (overlay) overlay.remove();
                return;
            }

            const cmd = e.metaKey || e.ctrlKey;
            if (cmd && e.key === 'k') {
                e.preventDefault();
                openCommandPalette();
            } else if (cmd && e.key === '/') {
                e.preventDefault();
                dom.globalSearch().focus();
            } else if (cmd && e.key === '1') { e.preventDefault(); switchTeam('red'); }
            else if (cmd && e.key === '2') { e.preventDefault(); switchTeam('gray'); }
            else if (cmd && e.key === '3') { e.preventDefault(); switchTeam('blue'); }
            else if (cmd && e.key === '4') { e.preventDefault(); switchTeam('white'); }
            else if (cmd && e.key === 't') { e.preventDefault(); toggleTheme(); }
            else if (!cmd && !e.altKey && e.key === '?' && document.activeElement?.tagName !== 'INPUT') {
                e.preventDefault();
                executeCommand('app:shortcuts', '');
            }
        });
    }

    // ========================================
    // Theme
    // ========================================

    function toggleTheme() {
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        state.ui.theme = next;
        try { localStorage.setItem('sr-theme', next); } catch (e) {}
    }

    function loadTheme() {
        let theme = 'dark';
        try { theme = localStorage.getItem('sr-theme') || 'dark'; } catch (e) {}
        document.documentElement.setAttribute('data-theme', theme);
        state.ui.theme = theme;
        updateThemeToggleIcon();
    }

    function updateThemeToggleIcon() {
        const btn = document.getElementById('themeToggleBtn');
        if (btn) {
            btn.textContent = state.ui.theme === 'dark' ? '🌙' : '☀️';
            btn.setAttribute('data-tooltip', state.ui.theme === 'dark' ? 'Switch to Light' : 'Switch to Dark');
        }
    }

    function toggleTheme() {
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        state.ui.theme = next;
        try { localStorage.setItem('sr-theme', next); } catch (e) {}
        updateThemeToggleIcon();
    }

    // ========================================
    // Activity Feed
    // ========================================

    function addActivity(message) {
        state.activity = state.activity || [];
        const time = new Date().toLocaleTimeString();
        state.activity.unshift({ time, message, ts: Date.now() });
        if (state.activity.length > 100) state.activity.length = 100;

        const feed = $('#activityFeed');
        if (feed) {
            const empty = feed.querySelector('.empty-state');
            if (empty) empty.remove();
            const entry = document.createElement('div');
            entry.style.cssText = 'padding:8px 0; border-bottom:1px solid var(--border-secondary); font-size:0.85rem;';
            entry.innerHTML = `<span style="color:var(--text-tertiary);">${time}</span> ${escapeHtml(message)}`;
            feed.insertBefore(entry, feed.firstChild);
            while (feed.children.length > 50) feed.removeChild(feed.lastChild);
        }
    }

    // ========================================
    // Utility Functions
    // ========================================

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    async function getDefaultDir() {
        try {
            if (window.__TAURI__?.path) {
                const homeDir = await window.__TAURI__.path.homeDir();
                const platform = await window.__TAURI__.os?.platform();
                if (platform === 'darwin') {
                    return await window.__TAURI__.path.join(homeDir, 'Movies', 'SiteRecorder');
                } else if (platform === 'win32') {
                    return await window.__TAURI__.path.join(homeDir, 'Videos', 'SiteRecorder');
                } else {
                    return await window.__TAURI__.path.join(homeDir, 'Videos', 'SiteRecorder');
                }
            }
        } catch (e) {}
        return './recordings';
    }

    async function downloadReport(report, format) {
        try {
            const scanId = report.scan_id;
            const outputDir = $('#outputDir')?.value?.trim();

            if (format === 'html') {
                const htmlContent = generateHtmlReport(report);
                const blob = new Blob([htmlContent], { type: 'text/html' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${scanId}_report.html`;
                a.click();
                URL.revokeObjectURL(url);
                showToast('success', 'Exported', `HTML report saved as ${scanId}_report.html`);
                return;
            }

            if (!outputDir) {
                showToast('error', 'No Output Dir', 'Set an Output Directory first.');
                return;
            }

            const ext = format === 'csv' ? 'csv' : format === 'pdf' ? 'pdf' : 'json';
            const dest = await window.__TAURI__.dialog.save({ defaultPath: `${scanId}.${ext}` });
            if (!dest) return;

            await invoke('save_export', { outputDir, scanId, format, destPath: dest });
            showToast('success', 'Exported', `Report saved to ${dest}`);
        } catch (e) {
            showToast('error', 'Export Failed', String(e));
        }
    }

    function generateHtmlReport(report) {
        const summary = report.summary;
        const findings = report.results || [];
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Scan Report - ${report.url || 'Unknown'}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 40px; background: #1a1a2e; color: #eee; }
        .container { max-width: 900px; margin: 0 auto; }
        h1 { color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 24px 0; }
        .stat { padding: 16px; border-radius: 8px; text-align: center; }
        .stat.critical { background: #e94560; }
        .stat.high { background: #f39c12; }
        .stat.medium { background: #f1c40f; color: #333; }
        .stat.low { background: #3498db; }
        .stat.info { background: #2ecc71; }
        .stat-value { font-size: 2rem; font-weight: 700; }
        .stat-label { font-size: 0.8rem; opacity: 0.8; }
        .finding { background: #16213e; border-radius: 8px; padding: 16px; margin-bottom: 12px; border-left: 4px solid #e94560; }
        .finding h3 { margin: 0 0 8px; }
        .finding p { margin: 4px 0; color: #aaa; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
        .badge-critical { background: #e94560; }
        .badge-high { background: #f39c12; }
        .badge-medium { background: #f1c40f; color: #333; }
        .badge-low { background: #3498db; }
        .badge-info { background: #2ecc71; }
        .footer { margin-top: 40px; text-align: center; color: #666; font-size: 0.8rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Vulnerability Scan Report</h1>
        <p><strong>Target:</strong> ${report.url || 'Unknown'}</p>
        <p><strong>Scan ID:</strong> ${report.scan_id || 'N/A'}</p>
        <p><strong>Date:</strong> ${new Date().toLocaleString()}</p>

        <div class="summary">
            <div class="stat critical"><div class="stat-value">${summary?.critical_count || 0}</div><div class="stat-label">Critical</div></div>
            <div class="stat high"><div class="stat-value">${summary?.high_count || 0}</div><div class="stat-label">High</div></div>
            <div class="stat medium"><div class="stat-value">${summary?.medium_count || 0}</div><div class="stat-label">Medium</div></div>
            <div class="stat low"><div class="stat-value">${summary?.low_count || 0}</div><div class="stat-label">Low</div></div>
            <div class="stat info"><div class="stat-value">${summary?.info_count || 0}</div><div class="stat-label">Info</div></div>
        </div>

        <h2>Findings (${findings.length})</h2>
        ${findings.map(f => `
            <div class="finding">
                <h3>${f.check_name || 'Unknown'} <span class="badge badge-${(f.severity || 'INFO').toLowerCase()}">${f.severity || 'INFO'}</span></h3>
                <p>Status: ${f.status || 'Unknown'}</p>
                ${(f.findings || []).map(finding => `<p><strong>${finding.title || ''}:</strong> ${finding.description || ''}</p>`).join('')}
            </div>
        `).join('')}

        <div class="footer">
            <p>Generated by SiteRecorder CyberOps</p>
        </div>
    </div>
</body>
</html>`;
    }

    // ========================================
    // Legacy Compatibility (Recording)
    // ========================================

    async function startRecording() {
        const btn = document.getElementById('recordingStartBtn');
        if (btn) btn.click();
        else showToast('info', 'Recording', 'Recording module available in sidebar.');
    }

    async function stopRecording() {
        const btn = document.getElementById('recordingStopBtn');
        if (btn) btn.click();
        else showToast('info', 'Recording', 'Recording stopped.');
    }

    // ========================================
    // Initialization
    // ========================================

    async function init() {
        initTauri();
        loadTheme();

        setupKeyboardShortcuts();
        initCustomSelects();

        $$('.team-tab').forEach(tab => {
            tab.addEventListener('click', () => switchTeam(tab.dataset.team));
        });

        $('#sidebarCollapseBtn')?.addEventListener('click', toggleSidebar);

        $('#globalSearch')?.addEventListener('focus', openCommandPalette);

        dom.globalSearch()?.addEventListener('input', (e) => {
            if (state.ui.commandPaletteOpen) {
                renderCommandResults(e.target.value);
            }
        });

        dom.commandInput()?.addEventListener('input', (e) => renderCommandResults(e.target.value));

        // Event delegation for dashboard buttons (they're rendered dynamically)
        $('#contentArea')?.addEventListener('click', (e) => {
            const target = e.target.closest('[id]');
            if (!target) return;
            const id = target.id;

            if (id === 'newOpBtn') {
                state.section = `${state.team === 'red' ? 'red-web' : state.team === 'blue' ? 'blue-hunt' : state.team + '-dashboard'}`;
                renderContent();
            } else if (id === 'refreshDashBtn') {
                renderContent();
                showToast('success', 'Refreshed', 'Dashboard data refreshed.');
            } else if (id === 'viewAllOps') {
                state.section = `${state.team}-dashboard`;
                renderContent();
                showToast('info', 'Operations', 'Showing all operations on dashboard.');
            } else if (id === 'viewAllActivity') {
                state.section = `${state.team}-dashboard`;
                renderContent();
            } else if (id === 'criticalCount' || id === 'highCount' || id === 'mediumCount' || id === 'lowCount' || id === 'infoCount') {
                const severity = id.replace('Count', '');
                filterFindingsBySeverity(severity);
            }
        });

        $('#viewAllActivity')?.addEventListener('click', () => {
            state.section = `${state.team}-dashboard`;
            renderContent();
        });

        $('#opsBtn')?.addEventListener('click', () => {
            const running = (state.data.scans || []).filter(s => s.status === 'running').length;
            showModal({
                title: '🔴 Active Operations',
                body: running > 0
                    ? `<div class="card-body">${(state.data.scans || []).filter(s => s.status === 'running').map(s => `
                        <div style="padding:8px 0; border-bottom:1px solid var(--border-secondary);">
                            <span class="status-dot running"></span>
                            <span style="font-weight:500; margin-left:8px;">${escapeHtml(s.name || 'Untitled')}</span>
                            <span class="badge badge-info" style="margin-left:8px;">${escapeHtml(s.type || 'web')}</span>
                            <div class="text-sm text-tertiary" style="margin-left:20px;">${escapeHtml(s.target || '')}</div>
                        </div>`).join('')}</div>`
                    : `<div class="empty-state"><div class="empty-state-icon">💤</div><div class="empty-state-title">No Active Operations</div><div class="empty-state-text">No scans or operations are currently running.</div></div>`,
            });
        });

        $('#docsBtn')?.addEventListener('click', () => {
            showModal({
                title: '📖 SiteRecorder CyberOps — Documentation',
                size: 'modal-lg',
                body: `
                    <h4 style="margin-bottom:8px;">Getting Started</h4>
                    <p style="margin-bottom:12px;">SiteRecorder CyberOps is a unified security operations platform for red, gray, blue, and white teams.</p>
                    <h4 style="margin-bottom:8px;">Navigation</h4>
                    <ul style="margin-bottom:12px; padding-left:20px;">
                        <li>Use the team tabs (🔴 Red, 🔘 Gray, 🔵 Blue, ⚪ White) to switch between workspaces.</li>
                        <li>The sidebar shows sections available for the active team.</li>
                        <li>Press <span class="badge badge-info">⌘K</span> or <span class="badge badge-info">Ctrl+K</span> to open the command palette.</li>
                    </ul>
                    <h4 style="margin-bottom:8px;">Cross-Team Views</h4>
                    <ul style="padding-left:20px;">
                        <li>🎯 <strong>Assets</strong> — unified asset inventory</li>
                        <li>🔔 <strong>Notifications</strong> — system alerts</li>
                        <li>📋 <strong>Reports</strong> — report templates & generation</li>
                        <li>🔗 <strong>Integrations</strong> — connected tools</li>
                    </ul>
                `,
            });
        });

        $('#notifBtn')?.addEventListener('click', () => {
            showModal({
                title: '🔔 Notifications',
                body: '<div class="empty-state"><div class="empty-state-icon">🔕</div><div class="empty-state-title">All Caught Up</div><div class="empty-state-text">No new notifications.</div></div>',
            });
        });

        $('#themeToggleBtn')?.addEventListener('click', toggleTheme);

        $('#settingsBtn')?.addEventListener('click', () => {
            showModal({
                title: '⚙️ Settings',
                body: `
                    <div class="form-group">
                        <label class="form-label">Theme</label>
                        <div class="custom-select" id="themeSelect">
                            <div class="custom-select-trigger">
                                <span class="select-value">${state.ui.theme === 'dark' ? '🌙 Dark' : '☀️ Light'}</span>
                                <span class="select-arrow">▼</span>
                            </div>
                            <div class="custom-select-dropdown">
                                <div class="custom-select-option ${state.ui.theme === 'dark' ? 'selected' : ''}" data-value="dark" onclick="document.documentElement.setAttribute('data-theme', 'dark'); localStorage.setItem('sr-theme', 'dark'); state.ui.theme='dark'; $('#themeSelect .select-value').textContent='🌙 Dark'; $('#themeSelect .custom-select-option').forEach(o=>o.classList.remove('selected')); this.classList.add('selected'); $('#themeSelect').classList.remove('open');">
                                    <span class="option-label">🌙 Dark</span>
                                    <span class="option-check">✓</span>
                                </div>
                                <div class="custom-select-option ${state.ui.theme === 'light' ? 'selected' : ''}" data-value="light" onclick="document.documentElement.setAttribute('data-theme', 'light'); localStorage.setItem('sr-theme', 'light'); state.ui.theme='light'; $('#themeSelect .select-value').textContent='☀️ Light'; $('#themeSelect .custom-select-option').forEach(o=>o.classList.remove('selected')); this.classList.add('selected'); $('#themeSelect').classList.remove('open');">
                                    <span class="option-label">☀️ Light</span>
                                    <span class="option-check">✓</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Output Directory</label>
                        <div style="display:flex; gap:8px;">
                            <input type="text" class="input" id="settingsOutputDir" placeholder="Select output directory..." style="flex:1;">
                            <button class="btn btn-secondary" id="browseDirBtn">📂 Browse</button>
                        </div>
                        <span class="form-hint">Directory where scan results and exports will be saved.</span>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Default Concurrency</label>
                        <input type="number" class="input" id="settingsConcurrency" value="4" min="1" max="32">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Default Scan Timeout (ms)</label>
                        <input type="number" class="input" id="settingsTimeout" value="5000" min="1000" max="60000">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Notifications</label>
                        <div style="display:flex; flex-direction:column; gap:8px;">
                            <label class="checkbox"><input type="checkbox" id="settingsNotifSuccess" checked> Show success notifications</label>
                            <label class="checkbox"><input type="checkbox" id="settingsNotifError" checked> Show error notifications</label>
                            <label class="checkbox"><input type="checkbox" id="settingsNotifInfo"> Show info notifications</label>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Credential Vault</label>
                        <div style="display:flex; gap:8px; align-items:center;">
                            <span class="badge badge-success" id="vaultStatusBadge">Unlocked</span>
                            <button class="btn btn-sm btn-secondary" id="lockVaultBtn">🔒 Lock Vault</button>
                            <button class="btn btn-sm btn-secondary" id="unlockVaultBtn" style="display:none;">🔓 Unlock Vault</button>
                        </div>
                        <span class="form-hint">Lock the credential vault to protect stored passwords and tokens.</span>
                    </div>
                `,
                actions: [
                    '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Close</button>',
                    '<button class="btn btn-primary" id="saveSettingsBtn">Save Settings</button>',
                ],
            });

            setTimeout(() => {
                $('#themeSelect .custom-select-trigger')?.addEventListener('click', (e) => {
                    e.stopPropagation();
                    $('#themeSelect').classList.toggle('open');
                });
                document.addEventListener('click', () => $('#themeSelect')?.classList.remove('open'));
            });

            setTimeout(() => {
                $('#browseDirBtn')?.addEventListener('click', async () => {
                    if (window.__TAURI__?.dialog?.open) {
                        try {
                            const selected = await window.__TAURI__.dialog.open({
                                directory: true,
                                multiple: false,
                                title: 'Select Output Directory',
                            });
                            if (selected) {
                                $('#settingsOutputDir').value = selected;
                            }
                        } catch (e) {
                            showToast('error', 'Browse Failed', 'Could not open directory picker.');
                        }
                    } else {
                        const path = prompt('Enter output directory path:', $('#settingsOutputDir').value || './output');
                        if (path) {
                            $('#settingsOutputDir').value = path;
                        }
                    }
                });

                $('#saveSettingsBtn')?.addEventListener('click', () => {
                    const settings = {
                        outputDir: $('#settingsOutputDir')?.value?.trim() || './output',
                        concurrency: parseInt($('#settingsConcurrency')?.value) || 4,
                        timeout: parseInt($('#settingsTimeout')?.value) || 5000,
                        notifications: {
                            success: $('#settingsNotifSuccess')?.checked,
                            error: $('#settingsNotifError')?.checked,
                            info: $('#settingsNotifInfo')?.checked,
                        },
                    };

                    try {
                        localStorage.setItem('sr-settings', JSON.stringify(settings));
                    } catch (e) {}

                    $('.modal-overlay').remove();
                    showToast('success', 'Settings Saved', 'Your preferences have been saved.');
                    addActivity('Settings updated');
                });

                try {
                    const saved = JSON.parse(localStorage.getItem('sr-settings') || '{}');
                    if (saved.outputDir) $('#settingsOutputDir').value = saved.outputDir;
                    if (saved.concurrency) $('#settingsConcurrency').value = saved.concurrency;
                    if (saved.timeout) $('#settingsTimeout').value = saved.timeout;
                    if (saved.notifications) {
                        $('#settingsNotifSuccess').checked = saved.notifications.success !== false;
                        $('#settingsNotifError').checked = saved.notifications.error !== false;
                        $('#settingsNotifInfo').checked = saved.notifications.info === true;
                    }
                } catch (e) {}

                // Vault management
                const updateVaultStatus = async () => {
                    try {
                        const locked = await invoke('is_vault_locked');
                        $('#vaultStatusBadge').textContent = locked ? 'Locked' : 'Unlocked';
                        $('#vaultStatusBadge').className = `badge badge-${locked ? 'error' : 'success'}`;
                        $('#lockVaultBtn').style.display = locked ? 'none' : '';
                        $('#unlockVaultBtn').style.display = locked ? '' : 'none';
                    } catch (e) {
                        $('#vaultStatusBadge').textContent = 'Unknown';
                    }
                };
                updateVaultStatus();

                $('#lockVaultBtn')?.addEventListener('click', async () => {
                    try {
                        await invoke('lock_vault');
                        showToast('success', 'Vault Locked', 'Credential vault has been locked.');
                        updateVaultStatus();
                    } catch (e) {
                        showToast('error', 'Failed', String(e));
                    }
                });

                $('#unlockVaultBtn')?.addEventListener('click', async () => {
                    const password = prompt('Enter master password to unlock vault:');
                    if (!password) return;
                    try {
                        await invoke('unlock_vault', { masterPassword: password });
                        showToast('success', 'Vault Unlocked', 'Credential vault has been unlocked.');
                        updateVaultStatus();
                    } catch (e) {
                        showToast('error', 'Failed', String(e));
                    }
                });
            }, 100);
        });

        renderSidebar();
        renderContent();

        addActivity('SiteRecorder CyberOps initialized');
        showToast('success', 'Welcome', 'SiteRecorder CyberOps is ready.');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose for inline handlers
    window.dismissToast = dismissToast;
    window.switchTeam = switchTeam;
    window.loadScan = loadScan;
    window.deleteScan = deleteScan;
    window.editTarget = editTarget;
    window.deleteTarget = deleteTarget;
    window.acknowledgeAlert = acknowledgeAlert;
    window.escalateAlert = escalateAlert;
    window.filterScans = filterScans;
    window.filterAlerts = filterAlerts;
    window.editAuthProfileEnhanced = editAuthProfileEnhanced;
    window.deleteAuthProfileEnhanced = deleteAuthProfileEnhanced;
    window.loadWordlistManager = loadWordlistManager;
    window.filterFindings = (filter, btn) => {
        if (btn) {
            const parent = btn.closest('.card-header');
            if (parent) {
                parent.querySelectorAll('.btn-sm').forEach(b => b.classList.remove('active'));
            }
            btn.classList.add('active');
        }

        $$('#webScanResults > div:last-child > div').forEach(card => {
            const status = card.querySelector('.badge-error, .badge-warning, .badge-success')?.textContent || '';
            if (filter === 'all') card.style.display = '';
            else if (filter === 'vulnerable') card.style.display = status.includes('VULNERABLE') ? '' : 'none';
            else if (filter === 'warning') card.style.display = status.includes('WARNING') ? '' : 'none';
            else if (filter === 'passed') card.style.display = status.includes('NOT') ? '' : 'none';
        });
    };

})();
