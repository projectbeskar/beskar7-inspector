# Beskar7-Inspector Deployment Instructions

## Overview

All files for the beskar7-inspector project have been created in `/tmp/beskar7-inspector/`. This guide will help you copy them to your GitHub repository and get started.

## Created Files

```
beskar7-inspector/
├── README.md                     # Main documentation
├── GETTING_STARTED.md            # Quick start guide
├── Dockerfile                     # Alpine image builder
├── Makefile                       # Build automation
├── .gitignore                     # Git ignore patterns
├── config/
│   └── inspector.conf             # Configuration file
├── scripts/
│   ├── utils.sh                   # Utility functions
│   ├── 00-init.sh                 # Initialize environment
│   ├── 01-hardware-inspect.sh     # Hardware detection
│   ├── 02-network-setup.sh        # Network configuration
│   ├── 03-report-to-beskar7.sh    # Report submission
│   ├── 04-download-os.sh          # OS download
│   └── 05-kexec-boot.sh           # Kexec boot
└── templates/
    └── boot.ipxe.tmpl             # iPXE boot script template
```

## Step 1: Copy Files to Your Repository

### Option A: Copy all files at once

```bash
# Navigate to your local clone of beskar7-inspector
cd ~/code/beskar7-inspector  # or wherever you cloned it

# Copy all files
cp -r /tmp/beskar7-inspector/* .

# Verify files
ls -la
```

### Option B: Copy files manually

```bash
cd ~/code/beskar7-inspector

# Copy main files
cp /tmp/beskar7-inspector/README.md .
cp /tmp/beskar7-inspector/GETTING_STARTED.md .
cp /tmp/beskar7-inspector/Dockerfile .
cp /tmp/beskar7-inspector/Makefile .
cp /tmp/beskar7-inspector/.gitignore .

# Copy directories
cp -r /tmp/beskar7-inspector/config .
cp -r /tmp/beskar7-inspector/scripts .
cp -r /tmp/beskar7-inspector/templates .
```

## Step 2: Commit and Push

```bash
cd ~/code/beskar7-inspector

# Add files
git add .

# Commit
git commit -m "Initial commit: Beskar7-Inspector Alpine Linux inspection image

- Add Dockerfile for Alpine 3.19 base
- Implement hardware detection scripts
- Add report submission to Beskar7 API
- Implement kexec boot into target OS
- Add build system (Makefile)
- Add comprehensive documentation"

# Push to GitHub
git push origin main
```

## Step 3: Build the Image

```bash
# Build inspection image
make build

# Expected output:
# Building Beskar7-Inspector image...
# Extracting kernel and initrd...
# Build complete!
# Output: build/vmlinuz, build/initrd.img
```

## Step 4: Test Locally (Optional)

```bash
# Test in QEMU (requires QEMU installed)
make test-vm

# You should see the inspector boot and run
```

## Step 5: Deploy to Boot Server

```bash
# Deploy to your boot server
make deploy BOOT_SERVER=boot.example.com BOOT_PATH=/var/www/boot/inspector/

# Or manually:
scp build/vmlinuz boot-server:/var/www/boot/inspector/
scp build/initrd.img boot-server:/var/www/boot/inspector/
```

## Step 6: Create iPXE Boot Script

On your boot server, create `/var/www/boot/ipxe/inspect.ipxe`:

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

## Step 7: Update Beskar7 Resources

Update your Beskar7Machine to use the inspection image:

```yaml
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: Beskar7Machine
metadata:
  name: test-machine
  namespace: default
spec:
  inspectionImage: "http://boot.example.com/ipxe/inspect.ipxe"
  targetOSImage: "http://boot.example.com/images/kairos-v2.8.1.tar.gz"
  bootMode: "iPXE"
```

## Step 8: Test End-to-End

```bash
# Create PhysicalHost and Beskar7Machine
kubectl apply -f examples/minimal-test.yaml

# Watch the workflow
kubectl get physicalhost -w

# Expected flow:
# 1. PhysicalHost: Enrolling → Available
# 2. Beskar7Machine claims host
# 3. PhysicalHost: InUse → Inspecting
# 4. Inspector boots, detects hardware, reports
# 5. PhysicalHost: InspectionComplete
# 6. Beskar7Machine: Ready
# 7. Inspector kexecs into target OS
```

## Troubleshooting

### Build Fails

```bash
# Check Docker is running
docker ps

# Check you're in the right directory
pwd  # Should show beskar7-inspector

# Try building with verbose output
docker build -t beskar7-inspector:1.0 .
```

### Scripts Not Executable

```bash
# Make scripts executable
chmod +x scripts/*.sh
```

### Can't Push to GitHub

```bash
# Set up Git credentials
git config user.name "Your Name"
git config user.email "your.email@example.com"

# Authenticate with GitHub
gh auth login
# or use SSH keys
```

## File Descriptions

| File | Purpose |
|------|---------|
| **README.md** | Main project documentation |
| **GETTING_STARTED.md** | Quick start guide |
| **Dockerfile** | Builds Alpine Linux inspection image |
| **Makefile** | Build automation and deployment |
| **config/inspector.conf** | Default configuration |
| **scripts/utils.sh** | Utility functions |
| **scripts/00-init.sh** | Initialize environment |
| **scripts/01-hardware-inspect.sh** | Detect CPU, RAM, disks, NICs |
| **scripts/02-network-setup.sh** | Configure networking |
| **scripts/03-report-to-beskar7.sh** | Submit inspection report via HTTP POST |
| **scripts/04-download-os.sh** | Download target OS image |
| **scripts/05-kexec-boot.sh** | Kexec into target OS |
| **templates/boot.ipxe.tmpl** | iPXE boot script template |

## Next Steps

1. **✅ Files copied to repository**
2. **✅ Committed and pushed to GitHub**
3. **🔄 Build inspection image** (`make build`)
4. **🔄 Deploy to boot server** (`make deploy`)
5. **🔄 Test end-to-end workflow**
6. **📝 Document results**

## Getting Help

- **Beskar7 Issues:** https://github.com/wrkode/beskar7/issues
- **Inspector Issues:** https://github.com/projectbeskar/beskar7-inspector/issues
- **Documentation:** See README.md and GETTING_STARTED.md

---

**Status:** Ready to deploy  
**Est. Time:** 30 minutes  
**Location:** `/tmp/beskar7-inspector/`  

All files are ready to be copied to your GitHub repository!

