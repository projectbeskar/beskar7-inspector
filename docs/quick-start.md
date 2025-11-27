# Quick Start Guide

Get Beskar7-Inspector up and running in 15 minutes.

## Prerequisites

- Docker installed
- A test machine or VM
- Network connectivity

## Step 1: Build the Inspector (2 minutes)

```bash
git clone https://github.com/projectbeskar/beskar7-inspector.git
cd beskar7-inspector
make build
```

Output:
```
dist/vmlinuz      (~10 MB)
dist/initrd.img   (~60 MB)
```

## Step 2: Start HTTP Server (30 seconds)

```bash
cd dist
python3 -m http.server 8080
```

Leave this running in a terminal.

## Step 3: Test with QEMU (2 minutes)

In a new terminal:

```bash
cd beskar7-inspector

qemu-system-x86_64 \
    -kernel dist/vmlinuz \
    -initrd dist/initrd.img \
    -append "beskar7.api=http://10.0.2.2:8082 beskar7.token=test123 beskar7.namespace=default beskar7.host=quickstart-test console=ttyS0" \
    -m 2048 \
    -nographic
```

**What to expect:**
- Alpine Linux boots (~10 seconds)
- Inspection scripts run
- Hardware detection output
- Attempt to POST report (will fail without Beskar7 controller - that's OK for now)

**To exit QEMU:** Press `Ctrl+A` then `X`

## Step 4: Deploy to Real Infrastructure (10 minutes)

### 4.1 Copy Files to Boot Server

```bash
# SSH to your boot server
ssh user@boot-server

# Create directory
sudo mkdir -p /var/www/boot/inspector

# Copy files (from your build machine)
scp dist/vmlinuz user@boot-server:/tmp/
scp dist/initrd.img user@boot-server:/tmp/

# Move to web root
ssh user@boot-server
sudo mv /tmp/vmlinuz /tmp/initrd.img /var/www/boot/inspector/
sudo chmod 644 /var/www/boot/inspector/*
```

### 4.2 Create Boot Script

```bash
# On boot server
sudo tee /var/www/boot/inspect.ipxe << 'EOF'
#!ipxe
kernel http://YOUR_BOOT_SERVER_IP/inspector/vmlinuz \
    beskar7.api=http://YOUR_BESKAR7_IP:8082 \
    beskar7.token=test-token \
    beskar7.namespace=default \
    beskar7.host=${mac:hexhyp} \
    console=ttyS0,115200

initrd http://YOUR_BOOT_SERVER_IP/inspector/initrd.img
boot
EOF
```

Replace:
- `YOUR_BOOT_SERVER_IP` with your HTTP server IP
- `YOUR_BESKAR7_IP` with your Beskar7 controller IP

### 4.3 Configure Test Server

1. Power on server
2. Enter BIOS (usually DEL, F2, or F12)
3. Enable PXE/Network Boot
4. Set boot order: Network first
5. Save and reboot

### 4.4 Watch It Boot

Monitor via serial console or BMC virtual console.

You should see:
```
PXE Boot...
iPXE initializing...
Loading kernel... ok
Loading initrd... ok
Booting...
[    0.000000] Linux version 6.6...
Welcome to Alpine Linux!
Starting Beskar7 Inspector...
Detecting hardware...
CPU: 16 cores detected
Memory: 64 GB detected
Disks: 2 found
NICs: 4 found
Reporting to Beskar7...
```

## Validation

### Check HTTP Server Logs

In the terminal running Python http.server:
```
GET /vmlinuz
GET /initrd.img
```

### Check Beskar7 Controller

```bash
kubectl logs -n beskar7-system -l app.kubernetes.io/name=beskar7 --tail=50
```

Look for:
```
INFO inspection-server Received inspection report namespace=default host=test-server
```

### Check PhysicalHost Status

```bash
kubectl get physicalhost test-server -o jsonpath='{.status.inspectionReport}' | jq
```

Should show hardware details.

## What's Next?

Now that you have it working:

1. **Configure DHCP** for automatic PXE boot
   - See [deployment.md](deployment.md) for DHCP configuration

2. **Set up multiple servers**
   - Register PhysicalHost resources in Kubernetes
   - Create Beskar7Machine resources
   - Let automation handle the rest

3. **Customize boot scripts**
   - See [ipxe-examples.md](ipxe-examples.md) for advanced configurations

4. **Integrate with your environment**
   - See [api-integration.md](api-integration.md) for API details

## Troubleshooting

### QEMU test fails

**Problem:** QEMU won't start or kernel panics

**Solution:**
```bash
# Check files exist
ls -lh dist/

# Try with more verbose output
qemu-system-x86_64 \
    -kernel dist/vmlinuz \
    -initrd dist/initrd.img \
    -append "console=ttyS0 debug" \
    -m 2048 \
    -nographic
```

### HTTP server not accessible

**Problem:** Cannot download vmlinuz/initrd.img

**Solution:**
```bash
# Check firewall
sudo ufw allow 8080/tcp

# Test locally
curl http://localhost:8080/vmlinuz -I

# Test from another machine
curl http://BOOT_SERVER_IP:8080/vmlinuz -I
```

### Real server won't PXE boot

**Problem:** Server doesn't network boot

**Solution:**
1. Verify PXE is enabled in BIOS
2. Check network cable is connected
3. Verify DHCP server is running
4. Check DHCP logs for requests

```bash
# Check DHCP logs
sudo tail -f /var/log/syslog | grep -i dhcp
```

## Success Criteria

You're ready to move on when:

- [ ] `make build` completes successfully
- [ ] QEMU test boots and runs inspection
- [ ] HTTP server serves files
- [ ] Real server PXE boots the inspector
- [ ] Inspection report reaches Beskar7 controller
- [ ] PhysicalHost shows inspection data

## Next Steps

Continue to the [full deployment guide](deployment.md) for production setup with DHCP, nginx, and multiple servers.

