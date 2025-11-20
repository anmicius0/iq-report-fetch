# IQ Server Report Fetcher

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A robust Go CLI tool designed to fetch the latest policy violation reports from Sonatype IQ Server APIs and export them as CSV files. This tool systematically scans all organizations within your IQ Server instance, ensuring comprehensive coverage of policy violations across your applications.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output Format](#output-format)
- [Build](#build)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Comprehensive Scanning**: Automatically scans all organizations in your IQ Server instance
- **Latest Reports**: Fetches the most recent build reports for each application
- **Detailed Violations**: Parses policy violations including threat levels, constraints, and CVE information
- **Secure Authentication**: Uses basic authentication to securely connect to IQ Server
- **Timestamped Output**: Generates uniquely named CSV files with atomic writes to prevent data corruption
- **Configurable**: Flexible configuration via environment variables
- **Logging**: Comprehensive logging with both console and file output for debugging and monitoring
- **Cross-Platform**: Builds available for multiple operating systems and architectures

## Prerequisites

- Go 1.21 or later
- Access to a Sonatype IQ Server instance with v2 API enabled
- Valid credentials (username and password or token) for IQ Server authentication

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/anmicius0/iqserver-report-fetch-go.git
   cd iqserver-report-fetch-go
   ```

2. **Install dependencies**:

   ```bash
   make install-deps
   ```

3. **Configure the environment** (see [Configuration](#configuration) section below).

## Configuration

Create a configuration file by copying the example:

```bash
cp config/.env.example config/.env
```

Edit `config/.env` with your IQ Server details:

```env
# IQ Server connection (required)
IQ_SERVER_URL=http://your-iq-server:8070/api/v2
IQ_USERNAME=your_username
IQ_PASSWORD=your_password_or_token

# Report output directory (optional)
# If not set, defaults to "reports_output" relative to the project root.
REPORT_OUTPUT_DIR=reports_output
```

### Configuration Parameters

- `IQ_SERVER_URL`: The base URL of your IQ Server instance, including the `/api/v2` path
- `IQ_USERNAME`: Your IQ Server username
- `IQ_PASSWORD`: Your IQ Server password or API token
- `REPORT_OUTPUT_DIR`: Directory where CSV reports will be saved (optional, defaults to `reports_output`)

## Usage

Run the tool to generate a policy violation report:

```bash
make run
```

This will:

1. Connect to your configured IQ Server
2. Fetch the latest policy violation reports for all applications across all organizations
3. Generate a timestamped CSV file in the output directory
4. Display the path to the generated report

### Example Output

```
2023-11-20_14-30-15.csv written to reports_output/
```

## Output Format

The generated CSV file contains the following columns:

| Column          | Description                                |
| --------------- | ------------------------------------------ |
| No.             | Sequential number for each violation       |
| Application     | Name of the application                    |
| Organization    | Organization the application belongs to    |
| Policy          | Name of the violated policy                |
| Component       | The component that triggered the violation |
| Threat          | Threat level of the violation              |
| Policy/Action   | Action associated with the policy          |
| Constraint Name | Name of the constraint violated            |
| Condition       | Specific condition that was met            |
| CVE             | Associated CVE identifiers (if any)        |

### Sample CSV Content

```csv
No.,Application,Organization,Policy,Component,Threat,Policy/Action,Constraint Name,Condition,CVE
1,MyApp,MyOrg,Security-High,commons-beanutils:1.9.4,8,Fail,High Risk CVEs,CVE Count >= 1,CVE-2019-10086
2,MyApp,MyOrg,License-Banned,log4j-core:2.14.1,9,Fail,Banned Licenses,License Category is Banned,-
```

## Build

Build binaries for different platforms:

```bash
# Build for macOS ARM64 (default)
make build-darwin-arm64

# Build for Linux AMD64
make build-linux-amd64

# Build for Windows AMD64
make build-windows-amd64

# Build for all platforms
make all
```

Built binaries will be placed in the `bin/` directory.

## Testing

Run the test suite:

```bash
make test
```

This will execute all unit tests with verbose output, ensuring the reliability of the tool's components.

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes and add tests
4. Run tests: `make test`
5. Commit your changes: `git commit -am 'Add some feature'`
6. Push to the branch: `git push origin feature/your-feature-name`
7. Submit a pull request

### Development Setup

For development, ensure you have Go 1.21+ installed. After cloning:

```bash
make install-deps
cp config/.env.example config/.env
# Edit config/.env with test credentials
make test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Note**: This tool requires appropriate permissions on your IQ Server instance. Ensure your user account has read access to applications and organizations you want to scan.
