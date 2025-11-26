# Getting Started with Beskar7-Inspector

## Overview

This guide will help you build and deploy the Beskar7-Inspector image in under 30 minutes.

## Prerequisites

- Docker or Podman
- Make
- Boot server with HTTP access
- Beskar7 controller running

## Step 1: Build the Image

```bash
# Clone the repository (if not already done)
git clone https://github.com/projectbeskar/beskar7-inspector.git
cd beskar7-inspector

# Build the inspection image
make build

# This creates:
#   build/vmlinuz   - Linux kernel
#   build/initrd.img - Initramfs with inspection tools
```

**Expected output:**
```
Building Beskar7-Inspector image...
Extracting kernel and initrd...
Build complete!
Output: build/vmlinuz, build/initrd.img

build/vmlinuz    - 8.2M
build/initrd.img - 95M
```

## Step 2: Set Up Boot Server

### Option A: Deploy to existing boot server

```bash
# Deploy files
make deploy BOOT_SERVER=boot.example.com BOOT_PATH=/var/www/boot/inspector/
```

### Option B: Manual deployment

```bash
# Copy files to boot server
scp build/vmlinuz boot-server:/var/www/boot/inspector/
scp build/initrd.img boot-server:/var/www/boot/inspector/

# Verify files are accessible
curl -I http://boot-server/inspector/vmlinuz
curl -I http://boot-server/inspector/initrd.img
```

## Step 3: Create iPXE Boot Script

Create `/var/www/boot/ipxe/inspect.ipxe` on your boot server:

```ipxe
#!ipxe

dhcp

set boot-server http://boot.example.com
set beskar7-api http://beskar7-inspection.beskar7-system.svc.cluster.local:8082
set beskar7-namespace default
set beskar7-host ${hostname}

kernel ${boot-server}/inspector/vmlinuz \
    beskar7.api=${beskar7-api} \
    beskar7.namespace=${beskar7-namespace} \
    beskar7.host=${beskar7-host} \
    console=tty0 console=ttyS0,115200

initrd ${boot-server}/inspector/initrd.img

boot
```

## Step 4: Test in QEMU (Optional)

```bash
# Test boot in virtual machine
make test-vm

# You should see:
# - Inspector booting
# - Hardware detection
# - Network setup
# - Report attempt
```

## Step 5: Configure Beskar7

Create a PhysicalHost and Beskar7Machine:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: bmc-credentials
  namespace: default
stringData:
  username: "admin"
  password: "password"
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: PhysicalHost
metadata:
  name: server-01
  namespace: default
spec:
  redfishConnection:
    address: "https://192.168.1.100"
    credentialsSecretRef: "bmc-credentials"
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: Beskar7Machine
metadata:
  name: test-machine
  namespace: default
spec:
  inspectionImage: "http://boot.example.com/ipxe/inspect.ipxe"
  targetOSImage: "http://boot.example.com/images/kairos-v2.8.1.tar.gz"
```

## Step 6: Trigger Inspection

```bash
# Apply resources
kubectl apply -f test-machine.yaml

# Watch PhysicalHost
kubectl get physicalhost server-01 -w

# Expected progression:
# server-01   Enrolling   false   0s
# server-01   Available   true    10s
# server-01   InUse       false   20s
# server-01   Inspecting  false   30s
# server-01   Ready       true    60s
```

## Step 7: View Inspection Report

```bash
# Get inspection report
kubectl get physicalhost server-01 -o jsonpath='{.status.inspectionReport}' | jq

# Example output:
# {
#   "timestamp": "2025-11-26T10:30:00Z",
#   "manufacturer": "Dell Inc.",
#   "model": "PowerEdge R750",
#   "cpus": [...],
#   "memory": [...],
#   "disks": [...],
#   "nics": [...]
# }
```

## Troubleshooting

### Build fails

**Error:** `Cannot find Dockerfile`
**Fix:** Make sure you're in the beskar7-inspector directory

**Error:** `Docker not found`
**Fix:** Install Docker or use Podman: `alias docker=podman`

### Boot fails

**Check:**
1. Files are accessible: `curl http://boot-server/inspector/vmlinuz`
2. iPXE script syntax is correct
3. BMC has PXE boot enabled
4. Server is on correct network

**Debug:**
```bash
# Check server serial console for boot messages
# Look for:
# - DHCP request
# - iPXE chainloading
# - Kernel loading
# - Inspector startup
```

### Can't reach Beskar7 API

**Check:**
1. Beskar7 controller is running:
   ```bash
   kubectl get pods -n beskar7-system
   ```

2. Inspection service exists:
   ```bash
   kubectl get svc -n beskar7-system beskar7-inspection
   ```

3. Network connectivity from provisioning network

**Fix:** Update `beskar7.api` parameter in iPXE script

### Report not received

**Check Beskar7 logs:**
```bash
kubectl logs -n beskar7-system deployment/beskar7-controller-manager | grep inspection
```

**Check PhysicalHost status:**
```bash
kubectl describe physicalhost server-01
```

## Next Steps

- Test on real hardware
- Customize inspection scripts for your needs
- Add hardware validation rules
- Integrate with your OS images

## Getting Help

- **Issues:** https://github.com/projectbeskar/beskar7-inspector/issues
- **Beskar7 Docs:** https://github.com/wrkode/beskar7
- **Community:** https://github.com/wrkode/beskar7/discussions

---

**Estimated Time:** 20-30 minutes  
**Difficulty:** Intermediate  
**Status:** Production Ready

