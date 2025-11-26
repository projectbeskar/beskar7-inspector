# Beskar7-Inspector

**Alpine Linux-based hardware inspection image for Beskar7 bare-metal provisioning**

## Overview

Beskar7-Inspector is a lightweight, bootable Alpine Linux image that boots via iPXE, inspects bare-metal server hardware, reports back to Beskar7, and then kexecs into the final operating system.

## Features

- 🔍 **Hardware Detection** - CPU, memory, disks, NICs
- 📊 **Detailed Reporting** - Structured JSON reports to Beskar7 API
- 🚀 **Fast Boot** - < 60 seconds from power-on to report
- 🔄 **Kexec Support** - Seamless transition to target OS
- 🛡️ **Vendor Agnostic** - Works on any x86_64 server
- 📦 **Minimal Size** - ~100MB compressed

## Architecture

```
Power On → PXE Boot → iPXE → Inspector Image → Inspect → Report → Kexec → Target OS
                         ↓                          ↓          ↓
                    boot.ipxe              Hardware Data   Beskar7 API
```

## Quick Start

### Prerequisites

- Docker or Podman
- Boot server with iPXE support
- Beskar7 controller running

### Build

```bash
# Clone repository
git clone https://github.com/projectbeskar/beskar7-inspector.git
cd beskar7-inspector

# Build inspection image
make build

# Output: build/vmlinuz and build/initrd.img
```

### Deploy

```bash
# Copy to boot server
make deploy BOOT_SERVER=boot.example.com BOOT_PATH=/var/www/boot/inspector/

# Or manually:
scp build/vmlinuz boot-server:/var/www/boot/inspector/
scp build/initrd.img boot-server:/var/www/boot/inspector/
```

### iPXE Boot Script

Create `/var/www/boot/ipxe/inspect.ipxe`:

```ipxe
#!ipxe

echo Booting Beskar7 Inspector...

# Set API endpoint
set beskar7-api http://beskar7-inspection.beskar7-system.svc.cluster.local:8082

# Get host info from DHCP or set manually
set beskar7-namespace ${beskar7-namespace:default}
set beskar7-host ${beskar7-host:unknown}

# Boot inspection kernel
kernel http://boot-server/inspector/vmlinuz \
    beskar7.api=${beskar7-api} \
    beskar7.namespace=${beskar7-namespace} \
    beskar7.host=${beskar7-host} \
    console=tty0 \
    console=ttyS0,115200

initrd http://boot-server/inspector/initrd.img

boot
```

## How It Works

### 1. Boot Phase
- Server PXE boots
- iPXE chainloads boot script
- Kernel and initrd downloaded
- Boot with beskar7.* parameters

### 2. Inspection Phase
- Alpine Linux boots in RAM
- Detection scripts execute:
  - CPU: cores, model, frequency
  - Memory: capacity, speed, type
  - Disks: size, type, model
  - NICs: MAC, speed, driver
  - System: manufacturer, model, serial

### 3. Reporting Phase
- Generate JSON report
- POST to Beskar7 API endpoint
- Retry on failure (3 attempts)
- Wait for acknowledgment

### 4. Provisioning Phase
- Receive target OS URL from Beskar7
- Download kernel + initrd
- Verify checksums
- Kexec into target OS

## Configuration

### Kernel Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `beskar7.api` | Beskar7 API endpoint | `http://beskar7.local:8082` |
| `beskar7.namespace` | Kubernetes namespace | `default` |
| `beskar7.host` | PhysicalHost name | `server-01` |
| `beskar7.timeout` | Inspection timeout (seconds) | `600` |
| `beskar7.debug` | Enable debug output | `true` |

### Environment Variables

Set in `/config/inspector.conf`:

```bash
# Retry configuration
RETRY_COUNT=3
RETRY_DELAY=5

# Timeout configuration
INSPECTION_TIMEOUT=300
DOWNLOAD_TIMEOUT=600

# Debug mode
DEBUG=false
```

## Development

### Project Structure

```
beskar7-inspector/
├── Dockerfile               # Alpine image builder
├── Makefile                 # Build automation
├── scripts/                 # Inspection scripts
│   ├── 00-init.sh          # Initialize environment
│   ├── 01-hardware-inspect.sh  # Hardware detection
│   ├── 02-network-setup.sh     # Network setup
│   ├── 03-report-to-beskar7.sh # Report submission
│   ├── 04-download-os.sh       # OS download
│   ├── 05-kexec-boot.sh        # Kexec boot
│   └── utils.sh                # Utilities
├── config/                  # Configuration
├── templates/               # JSON templates
└── tests/                   # Test scripts
```

### Building Locally

```bash
# Build image
make build

# Test in QEMU
make test-vm

# Run tests
make test

# Clean build artifacts
make clean
```

### Testing

```bash
# Unit tests
make test-unit

# Integration test in VM
make test-integration

# Test on real hardware
make test-hardware HARDWARE=192.168.1.100
```

## API Integration

### Inspection Report Format

The inspector POSTs this JSON to Beskar7:

```json
{
  "namespace": "default",
  "hostName": "server-01",
  "manufacturer": "Dell Inc.",
  "model": "PowerEdge R750",
  "serialNumber": "ABC123",
  "cpus": [
    {
      "id": "0",
      "vendor": "Intel",
      "model": "Xeon Gold 6254",
      "cores": 18,
      "threads": 36,
      "frequency": "3.1GHz"
    }
  ],
  "memory": [
    {
      "id": "DIMM0",
      "type": "DDR4",
      "capacity": "32GB",
      "speed": "3200MHz"
    }
  ],
  "disks": [
    {
      "name": "/dev/sda",
      "model": "Samsung 870 EVO",
      "sizeGB": 500,
      "type": "SSD",
      "serialNumber": "S5H1NS0T123456"
    }
  ],
  "nics": [
    {
      "name": "eth0",
      "macAddress": "00:25:90:f0:79:00",
      "driver": "ixgbe",
      "speed": "1Gbps",
      "ipAddresses": ["192.168.1.100"]
    }
  ],
  "bootModeDetected": "UEFI",
  "firmwareVersion": "2.15.0"
}
```

### Response

```json
{
  "status": "success",
  "message": "Inspection report received",
  "targetOS": "http://images.example.com/kairos-v2.8.1.tar.gz"
}
```

## Troubleshooting

### Inspector doesn't boot

**Check:**
1. iPXE boot script syntax
2. HTTP server accessibility
3. Kernel parameters passed correctly
4. Serial console output

**Debug:**
```bash
# Enable debug mode in boot script
kernel ... beskar7.debug=true
```

### Can't reach Beskar7 API

**Check:**
1. Network connectivity
2. DNS resolution
3. Firewall rules
4. API endpoint URL

**Debug:**
```bash
# From inspector (if you can get shell):
curl -v http://beskar7-api:8082/healthz
```

### Hardware detection incomplete

**Check:**
1. Required tools installed (dmidecode, lshw, etc.)
2. Permissions (some tools need root)
3. Hardware compatibility

**Debug:**
```bash
# Manual detection test:
dmidecode -t system
lscpu -J
lsblk -J
```

## Performance

| Metric | Target | Typical |
|--------|--------|---------|
| Boot time | < 30s | 15-20s |
| Inspection time | < 30s | 10-15s |
| Report time | < 5s | 2-3s |
| **Total** | **< 60s** | **30-40s** |

## Hardware Compatibility

Tested on:
- ✅ Dell PowerEdge (iDRAC)
- ✅ HPE ProLiant (iLO)
- ✅ Lenovo ThinkSystem (XCC)
- ✅ Supermicro (BMC)
- ✅ Whitebox x86_64 servers

Requirements:
- x86_64 CPU
- 2GB+ RAM
- Network interface
- PXE/UEFI boot support

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

Apache License 2.0

## Support

- **Issues:** https://github.com/projectbeskar/beskar7-inspector/issues
- **Docs:** https://github.com/wrkode/beskar7
- **Beskar7 Repo:** https://github.com/wrkode/beskar7

## Acknowledgments

Built for Beskar7, inspired by:
- Tinkerbell (tinkerbell.org)
- Flatcar Linux ignition
- Metal³ (metal3.io)

---

**Status:** Production Ready  
**Version:** 1.0  
**Size:** ~100MB  
**Boot Time:** ~30-40 seconds

