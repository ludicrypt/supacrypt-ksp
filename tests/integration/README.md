# Windows KSP Integration Testing

This directory contains comprehensive integration tests for the Supacrypt KSP provider in real-world enterprise environments.

## Test Structure

- `scripts/` - PowerShell automation scripts
- `scenarios/` - Test scenario implementations  
- `validation/` - Result validation and reporting
- `test_data/` - Test certificates and configurations
- `results/` - Test execution results and metrics
- `documentation/` - Test plans and runbooks

## Test Categories

1. **Enterprise Applications**: IIS, SQL Server, Active Directory
2. **Office Suite**: Document signing, email encryption
3. **Development Tools**: Visual Studio, PowerShell, SignTool
4. **Performance**: Scale testing, load testing, stability
5. **Security**: FIPS compliance, security policies
6. **Interoperability**: Cross-provider scenarios

## Prerequisites

- Windows Server 2019+ or Windows 10/11 Enterprise
- Administrative privileges
- Supacrypt KSP provider installed
- Test backend service running
- Enterprise test applications installed

## Execution

Run `scripts/setup/master_setup.ps1` to prepare the test environment, then execute scenario scripts as needed.

See documentation/ for detailed test plans and execution guides.