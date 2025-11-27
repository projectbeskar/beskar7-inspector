# Testing Guide

Comprehensive testing procedures for Beskar7-Inspector.

## Overview

This guide covers three levels of testing:
1. **Unit Testing** - Individual component validation
2. **Integration Testing** - End-to-end workflow with QEMU
3. **Hardware Testing** - Validation on real physical servers

## Prerequisites

### For All Testing
- Built inspector image (`make build` completed)
- Basic networking knowledge
- Access to test infrastructure

### For QEMU Testing
- QEMU installed: `sudo apt install qemu-system-x86`
- 4GB free RAM
- Terminal with serial console support

### For Hardware Testing
- Physical server with BMC/UEFI
- Network access to server
- Serial console or BMC virtual console access

## Unit Testing

### Test 1: Build Validation

```bash
# Build should complete without errors
make build

# Verify output files
ls -lh dist/

# Expected output:
# -rw-r--r-- 1 user user  8.5M vmlinuz
# -rw-r--r-- 1 user user   58M initrd.img

# Validate file types
file dist/vmlinuz
# Should contain: "Linux kernel x86 boot executable"

file dist/initrd.img
# Should contain: "gzip compressed data"
```

### Test 2: Script Syntax Validation

```bash
# Check all scripts for syntax errors
for script in scripts/*.sh; do
    echo "Checking $script..."
    bash -n "$script" || echo "FAILED: $script"
done

# Should see no error messages
```

### Test 3: Docker Image Structure

```bash
# Inspect built image
docker run --rm beskar7-inspector:1.0 ls -la /

# Should show:
# /vmlinuz
# /initrd.img

# Verify file sizes match
docker run --rm beskar7-inspector:1.0 stat -c "%s %n" /vmlinuz /initrd.img
```

### Test 4: Template Validation

```bash
# Check iPXE template syntax
cat templates/boot.ipxe.tmpl

# Validate variables are properly defined
grep -E '\$\{[A-Z_]+\}' templates/boot.ipxe.tmpl
```

## Integration Testing with QEMU

### Test 5: Basic Boot Test

```bash
# Simple boot test
qemu-system-x86_64 \
    -kernel dist/vmlinuz \
    -initrd dist/initrd.img \
    -append "console=ttyS0" \
    -m 2048 \
    -nographic

# Expected output:
# Linux boot messages
# Alpine Linux login prompt
# (Ctrl+A, X to exit)
```

### Test 6: Inspector Boot with Parameters

```bash
# Boot with all required parameters
qemu-system-x86_64 \
    -kernel dist/vmlinuz \
    -initrd dist/initrd.img \
    -append "beskar7.api=http://10.0.2.2:8082 beskar7.token=test123 beskar7.namespace=default beskar7.host=test-qemu console=ttyS0 debug" \
    -m 2048 \
    -nographic \
    2>&1 | tee qemu-test.log

# Check log for:
grep "Beskar7 Inspector" qemu-test.log
grep "Hardware detection" qemu-test.log
grep "CPU" qemu-test.log
grep "Memory" qemu-test.log
```

### Test 7: Network Testing with QEMU

```bash
# Boot with network interface
qemu-system-x86_64 \
    -kernel dist/vmlinuz \
    -initrd dist/initrd.img \
    -append "beskar7.api=http://10.0.2.2:8082 beskar7.token=test123 beskar7.namespace=default beskar7.host=test-qemu console=ttyS0" \
    -m 2048 \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -nographic

# Inspector should detect network interface
# Look for: "eth0: link up"
```

### Test 8: Hardware Detection in QEMU

```bash
# Boot with varied hardware
qemu-system-x86_64 \
    -kernel dist/vmlinuz \
    -initrd dist/initrd.img \
    -append "beskar7.api=http://10.0.2.2:8082 beskar7.token=test console=ttyS0" \
    -m 4096 \
    -smp 4 \
    -drive file=/tmp/test-disk.img,format=raw,if=virtio \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -nographic

# Create test disk first:
# qemu-img create -f raw /tmp/test-disk.img 10G

# Expected detection:
# CPU: 4 cores
# Memory: 4096 MB
# Disk: 10 GB
# NIC: virtio
```

### Test 9: Mock Beskar7 API Test

```bash
# Start mock API server
cat > /tmp/mock-api.py << 'EOF'
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class MockAPI(BaseHTTPRequestHandler):
    def do_POST(self):
        if '/api/v1/inspection/' in self.path:
            length = int(self.headers['Content-Length'])
            body = self.rfile.read(length)
            print(f"Received inspection report:")
            print(json.dumps(json.loads(body), indent=2))
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "accepted"}')
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

print("Mock Beskar7 API listening on port 8082...")
HTTPServer(('0.0.0.0', 8082), MockAPI).serve_forever()
EOF

chmod +x /tmp/mock-api.py
python3 /tmp/mock-api.py &
MOCK_PID=$!

# Run QEMU test
qemu-system-x86_64 \
    -kernel dist/vmlinuz \
    -initrd dist/initrd.img \
    -append "beskar7.api=http://10.0.2.2:8082 beskar7.token=test beskar7.namespace=default beskar7.host=qemu console=ttyS0" \
    -m 2048 \
    -nographic

# Stop mock server
kill $MOCK_PID
```

## Hardware Testing

### Test 10: Single Server Boot Test

```bash
# Prerequisites:
# 1. HTTP server running with vmlinuz and initrd.img
# 2. iPXE boot script configured
# 3. DHCP configured for PXE boot
# 4. Beskar7 controller running

# Steps:
1. Create PhysicalHost resource:
   kubectl apply -f - << EOF
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: PhysicalHost
metadata:
  name: test-server-01
  namespace: default
spec:
  redfishConnection:
    address: "https://BMC_IP"
    credentialsSecretRef: "bmc-credentials"
EOF

2. Power on server via BMC or physical power button

3. Watch console output:
   # Via serial console:
   screen /dev/ttyUSB0 115200
   
   # Via BMC virtual console (iDRAC/iLO)

4. Monitor Beskar7 controller:
   kubectl logs -n beskar7-system -l app.kubernetes.io/name=beskar7 -f

5. Check PhysicalHost status:
   kubectl get physicalhost test-server-01 -o yaml

# Expected flow:
# - Server PXE boots
# - DHCP provides IP
# - iPXE loads
# - Boot script fetched
# - Kernel + initrd loaded
# - Alpine boots
# - Inspection runs
# - Report POSTed
# - PhysicalHost updated with inspection data
```

### Test 11: Multiple Server Test

```bash
# Test concurrent inspection of multiple servers

# Create PhysicalHost resources
for i in {1..3}; do
  kubectl apply -f - << EOF
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: PhysicalHost
metadata:
  name: test-server-0$i
  namespace: default
spec:
  redfishConnection:
    address: "https://192.168.1.10$i"
    credentialsSecretRef: "bmc-credentials"
EOF
done

# Power on all servers
# Watch for race conditions or resource contention

# Monitor inspection completion
watch -n 2 'kubectl get physicalhost -o custom-columns=NAME:.metadata.name,STATE:.status.state,PHASE:.status.inspectionPhase,READY:.status.ready'

# Verify all completed successfully
kubectl get physicalhost -o json | jq '.items[] | {name: .metadata.name, phase: .status.inspectionPhase, cpus: .status.inspectionReport.cpus.count}'
```

### Test 12: Hardware Variation Test

Test with different hardware types:

```bash
# Test matrix:
# - Dell PowerEdge
# - HP ProLiant
# - Supermicro
# - Lenovo ThinkSystem
# - Generic whitebox

# For each server:
1. Record vendor/model
2. Boot inspector
3. Collect inspection report
4. Validate all hardware detected correctly
5. Document any issues or quirks

# Create test report:
cat > hardware-test-report.md << 'EOF'
# Hardware Test Report

## Server 1: Dell PowerEdge R730
- CPU Detection: OK (2x Intel Xeon E5-2640 v4)
- Memory Detection: OK (64 GB DDR4)
- Disk Detection: OK (2x 500GB SSD)
- NIC Detection: OK (4x 1Gbps)
- Boot Time: 45 seconds
- Issues: None

## Server 2: HP ProLiant DL360 Gen10
- CPU Detection: OK
- Memory Detection: OK
- Disk Detection: OK
- NIC Detection: OK
- Boot Time: 52 seconds
- Issues: None

(... continue for each server type tested ...)
EOF
```

### Test 13: Network Failure Recovery

```bash
# Test behavior when network is unavailable

# Test scenarios:
1. Boot server with network cable unplugged
   # Expected: Inspector detects no network, logs error

2. Boot server, then disconnect network mid-inspection
   # Expected: Inspector retries, logs timeout

3. Boot server with unreachable Beskar7 controller
   # Expected: Inspector reports error, retries

# Monitor logs for retry behavior
tail -f /var/log/syslog | grep -i inspector
```

### Test 14: Inspection Timeout Test

```bash
# Test timeout handling

# Modify inspection script to add artificial delay:
# (In scripts/01-hardware-inspect.sh)
# sleep 600  # 10 minute delay

# Rebuild and deploy

# Boot server and monitor:
# - PhysicalHost inspection phase should transition to Timeout
# - Server should power off
# - PhysicalHost should return to Available state

# Verify timeout handling:
kubectl get physicalhost test-server -o jsonpath='{.status.inspectionPhase}'
# Should show: Timeout
```

## Validation Checklist

### Build Phase
- [ ] `make build` completes without errors
- [ ] dist/vmlinuz exists and is ~8-10MB
- [ ] dist/initrd.img exists and is ~50-80MB
- [ ] Docker image builds successfully
- [ ] All scripts pass syntax check

### QEMU Phase
- [ ] Basic boot succeeds
- [ ] Inspector boots with parameters
- [ ] Network interface detected
- [ ] Hardware detection runs
- [ ] Mock API receives report
- [ ] Boot completes in <60 seconds

### Hardware Phase
- [ ] Single server boots successfully
- [ ] Hardware detected accurately
- [ ] Report POSTed to controller
- [ ] PhysicalHost status updated
- [ ] Multiple servers work concurrently
- [ ] Different hardware types supported
- [ ] Network failures handled gracefully
- [ ] Timeouts handled correctly

## Performance Benchmarks

Expected timing (on typical hardware):

```
PXE boot:           5-10 seconds
iPXE chainload:     2-5 seconds
Kernel load:        5-10 seconds
Initrd load:        10-15 seconds
Alpine boot:        5-10 seconds
Hardware detection: 5-15 seconds
Report generation:  1-2 seconds
Report POST:        1-2 seconds
─────────────────────────────────
Total:              34-69 seconds (typical: ~45 seconds)
```

## Debugging Failed Tests

### Get Detailed Logs

```bash
# QEMU: Run with debug output
qemu-system-x86_64 ... -append "... debug loglevel=7" ...

# Hardware: Access serial console
screen /dev/ttyUSB0 115200

# Controller: Check logs
kubectl logs -n beskar7-system -l app.kubernetes.io/name=beskar7 --tail=100
```

### Common Issues

**Problem:** Kernel panic on boot

**Solution:**
- Verify kernel and initrd match
- Check kernel command line syntax
- Ensure sufficient memory (min 1GB)

**Problem:** No network detected

**Solution:**
- Check network cable
- Verify DHCP working
- Test with different NIC driver

**Problem:** Report not received

**Solution:**
- Check Beskar7 controller accessible
- Verify firewall allows port 8082
- Check token is correct

## Next Steps

After successful testing:
- Document hardware compatibility
- Update boot scripts for production
- Set up monitoring and alerting
- Integrate with CI/CD pipeline

## Resources

- [Troubleshooting Guide](troubleshooting.md)
- [Deployment Guide](deployment.md)
- [API Integration](api-integration.md)

