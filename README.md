# LogSpear
**Incident Summarizer for Security Operations**

Security logs are unreadable for humans. LogSpear bridges this gap by transforming raw security logs into actionable intelligence.

## Overview

LogSpear is a cybersecurity tool designed to assist Security Operations Center (SOC) analysts in making sense of complex security logs. By leveraging Large Language Models (LLMs) and intelligent parsing, LogSpear converts cryptic log data into clear, human-readable incident summaries with actionable recommendations.

## The Problem

Security logs from various sources (Nmap, AWS CloudWatch, firewall logs, etc.) generate massive amounts of data that are:
- Difficult to parse manually
- Time-consuming to analyze
- Easy to miss critical anomalies in
- Technical and inaccessible to non-experts

## The Solution

LogSpear allows SOC analysts to upload raw log files in `.json` or `.csv` format. The tool then:

1. **Parses** the log data using intelligent loaders
2. **Identifies** anomalies and suspicious patterns
3. **Explains** the risk in plain English
4. **Suggests** immediate remediation steps

## Key Features

- **Multi-Format Support**: Accepts `.json` and `.csv` log files from various sources (Nmap, AWS CloudWatch, Syslog, etc.)
- **LLM-Powered Analysis**: Uses specialized prompts to identify security anomalies
- **Plain English Explanations**: Translates technical log entries into understandable risk assessments
- **Actionable Remediation**: Provides immediate, practical steps to address identified threats
- **Needle in the Haystack**: Leverages LangChain's CSVLoader to parse large log files and surface critical events that might otherwise go unnoticed

## Unique Feature

LogSpear's standout capability is its use of **LangChain's CSVLoader** to efficiently parse and analyze large volumes of log data, enabling it to find "needle in the haystack" security events that could be buried in thousands of routine log entries.

## Use Cases

- Incident response and triage
- Security log auditing
- Threat hunting
- Compliance reporting
- Security awareness and training

## Getting Started

*Coming soon: Installation and usage instructions*

## License

See [LICENSE](LICENSE) file for details.
