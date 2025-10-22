# ipSearcher

A professional reconnaissance tool designed for network security analysis and penetration testing. ipSearcher automates the process of scanning domains, identifying open ports, detecting services, and enumerating FTP servers.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)

## Features

- **Automated Port Scanning**: Fast and comprehensive port discovery using nmap
- **Service Detection**: Identifies services running on discovered ports
- **Aggressive Scanning Mode**: In-depth analysis with OS detection and version scanning
- **FTP Enumeration**:
  - Anonymous login detection
  - Automated file and directory enumeration
  - Recursive file downloading from FTP servers
- **Comprehensive Logging**: Detailed logs of all operations saved to results directory
- **Extensible Architecture**: Built to support additional service modules in future releases

## Planned Features

Additional service detection and enumeration capabilities are planned for future versions, including:

- HTTP/HTTPS service analysis
- SMB enumeration
- SSH service detection
- Database service identification
- And more...

## Prerequisites

The tool automatically checks for and installs required dependencies:

- `nmap` - Network exploration and security auditing
- `dirsearch` - Web path scanner (planned feature)
- Python 3.x
- Root/sudo privileges (required for nmap)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/photomanai/ipSearcher.git
cd ipSearcher
```

2. Run the tool (dependencies will be automatically installed on first run):

```bash
python3 Search.py <domain>
```

## Usage

### Basic Scan

```bash
python3 Search.py example.com
```

### Aggressive Mode

Automatically performs aggressive scanning without prompts:

```bash
python3 Search.py example.com -y
```

### Command Line Options

```
positional arguments:
  domain                Domain or IP address to scan

optional arguments:
  -h, --help            Show help message and exit
  -t TEST, --test TEST  Test message (development option)
  -y                    Enable aggressive mode (no prompts)
```

## Output Structure

Results are automatically saved to the `./results` directory:

```
results/
├── nmapScan.txt       # Initial port scan results
├── serviceScan.txt    # Detailed service information
├── agresiveScan.txt   # Aggressive scan output (if performed)
├── mainLogs.log       # Complete operation logs
└── ftp/               # Downloaded FTP files (if accessible)
```

## How It Works

1. **Port Discovery**: Scans the target for open ports using nmap
2. **Service Detection**: Identifies services running on discovered ports
3. **Aggressive Analysis**: Optionally performs OS detection and version scanning
4. **Service-Specific Actions**:
   - FTP: Tests for anonymous access and downloads accessible files
   - Additional services: Coming in future releases

## Legal Disclaimer

⚠️ **IMPORTANT**: This tool is intended for authorized security testing and educational purposes only.

- Only scan networks and systems you own or have explicit permission to test
- Unauthorized scanning may be illegal in your jurisdiction
- The authors assume no liability for misuse of this tool
- Always follow responsible disclosure practices

## Contributing

Contributions are welcome! This project is under active development with plans to add support for additional services.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-service`)
3. Commit your changes (`git commit -m 'Add new service detection'`)
4. Push to the branch (`git push origin feature/new-service`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

[photomanai](https://github.com/photomanai)

## Acknowledgments

- Built with [nmap](https://nmap.org/) for network scanning
- Inspired by the need for automated reconnaissance tools in security testing

---

**⚡ Stay tuned for updates with additional service detection modules!**
