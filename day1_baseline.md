**Security findings this build**
Total findings: 120

By tool
Item 	        Count
Trivy 	      96
Checkov 	    17
Semgrep OSS 	7

By level (error = blocks the build)
Item 	    Count
error 	  113
warning 	7

Top 10 rules
Item 	                  Count
Trivy: CVE-2026-53612 	9
Trivy: CVE-2026-53613 	9
Trivy: CVE-2026-53614 	9
Trivy: CVE-2026-53615 	9
Trivy: CVE-2026-31789 	3
Trivy: CVE-2025-15467 	3
Trivy: CVE-2025-69421 	3
Trivy: CVE-2026-14456 	3
Trivy: CVE-2026-28387 	3
Trivy: CVE-2026-28388 	3

Top weakness types (CWE)
Item 	    Count
CWE-78 	  3
CWE-770 	3
CWE-125 	3
CWE-89 	  1
CWE-704 	1
CWE-668 	1
CWE-489 	1


ZAP_SCAN artifacts 

Name                                   	                                   Risk Level   	Number of Instances
Content Security Policy (CSP) Header Not Set 	                             Medium 	      Systemic
Missing Anti-clickjacking Header 	                                         Medium 	      1
Application Error Disclosure 	                                             Low 	          4
Server Leaks Version Information via "Server" HTTP Response Header Field 	 Low 	          Systemic
X-Content-Type-Options Header Missing 	                                   Low 	          3
Information Disclosure - Suspicious Comments 	                             Informational 	1
Modern Web Application 	                                                   Informational 	4
