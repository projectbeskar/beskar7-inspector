# Beskar7-Inspector Documentation

This directory contains comprehensive documentation for deploying, testing, and troubleshooting the Beskar7 hardware inspection image.

## Documentation Index

### Getting Started
- **[Deployment Guide](deployment.md)** - How to deploy the inspector to your infrastructure
- **[Quick Start](quick-start.md)** - Get up and running in 15 minutes
- **[Testing Guide](testing.md)** - Test the inspector with QEMU or real hardware

### Reference
- **[Architecture](architecture.md)** - How the inspector works internally
- **[iPXE Boot Scripts](ipxe-examples.md)** - Example boot scripts and configurations
- **[API Integration](api-integration.md)** - How the inspector communicates with Beskar7

### Operations
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions
- **[Network Requirements](network-requirements.md)** - Firewall, DHCP, and network setup

## Overview

Beskar7-Inspector is a lightweight Alpine Linux-based image that:
1. Boots via iPXE network boot
2. Detects hardware (CPU, RAM, disks, NICs)
3. Reports findings to Beskar7 controller
4. Kexecs into the final operating system

**Key Features:**
- No ISO required - boots over network
- Vendor-agnostic hardware detection
- Small footprint (~60MB total)
- Fast boot and inspection (<2 minutes typical)

## Quick Links

- **Main Beskar7 Repository:** https://github.com/wrkode/beskar7
- **Issue Tracker:** https://github.com/projectbeskar/beskar7-inspector/issues
- **Main Documentation:** https://github.com/wrkode/beskar7/tree/main/docs

## Components

### Built Artifacts
- `dist/vmlinuz` - Linux kernel (~8-10MB)
- `dist/initrd.img` - Root filesystem with inspection scripts (~50-80MB)

### Scripts
- `scripts/01-hardware-inspect.sh` - Hardware detection
- `scripts/02-network-setup.sh` - Network configuration
- `scripts/03-report-to-beskar7.sh` - API communication
- `scripts/04-download-os.sh` - Target OS download
- `scripts/05-kexec-boot.sh` - Kexec into final OS

### Configuration
- `config/inspector.conf` - Inspector configuration
- `templates/boot.ipxe.tmpl` - iPXE boot script template

## Typical Deployment

```
┌─────────────┐
│   Server    │  1. PXE boot
└──────┬──────┘
       │
       v
┌─────────────┐
│    DHCP     │  2. Get IP, chainload iPXE
└──────┬──────┘
       │
       v
┌─────────────┐
│ HTTP Server │  3. Fetch boot script
└──────┬──────┘  4. Load vmlinuz + initrd
       │
       v
┌─────────────┐
│  Inspector  │  5. Boot Alpine Linux
│   (Alpine)  │  6. Detect hardware
└──────┬──────┘  7. POST report
       │
       v
┌─────────────┐
│  Beskar7    │  8. Receive report
│ Controller  │  9. Validate hardware
└─────────────┘
```

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check the troubleshooting guide
- Review the main Beskar7 documentation

## Version

Current version: **1.0**

Release date: November 2025

Compatible with: **Beskar7 v0.4.0-alpha+**

