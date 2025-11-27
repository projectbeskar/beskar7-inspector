# Deployment Guide

This guide covers deploying Beskar7-Inspector to your infrastructure.

## Prerequisites

### Infrastructure Requirements

1. **HTTP Boot Server**
   - Web server (nginx, Apache, or Python http.server)
   - Accessible from servers to be inspected
   - Sufficient bandwidth for multiple simultaneous downloads

2. **DHCP Server**
   - Configured for PXE boot
   - iPXE chainloading support
   - Can provide boot script URL

3. **Beskar7 Controller**
   - Running and accessible on port 8082
   - Inspection API endpoint enabled
   - Network connectivity from servers

4. **Network Infrastructure**
   - DHCP available (UDP 67/68)
   - HTTP accessible (TCP 80 or 8080)
   - API accessible (TCP 8082)

### Build Requirements

- Docker installed
- Make installed
- Internet connection (for Alpine packages)

## Step 1: Build the Inspector Image

```bash
# Clone the repository
git clone https://github.com/projectbeskar/beskar7-inspector.git
cd beskar7-inspector

# Build the image
make build

# Verify output
ls -lh dist/
# Should see:
#   vmlinuz      (~8-10 MB)
#   initrd.img   (~50-80 MB)
```

## Step 2: Deploy to HTTP Boot Server

### Option A: Quick Test with Python

```bash
# Start HTTP server in dist directory
cd dist
python3 -m http.server 8080

# Files now available at:
# http://YOUR_IP:8080/vmlinuz
# http://YOUR_IP:8080/initrd.img
```

### Option B: Production Deployment with nginx

```bash
# Create directory structure
sudo mkdir -p /var/www/boot/inspector

# Copy files
sudo cp dist/vmlinuz /var/www/boot/inspector/
sudo cp dist/initrd.img /var/www/boot/inspector/

# Set permissions
sudo chmod 644 /var/www/boot/inspector/*
sudo chown -R www-data:www-data /var/www/boot/

# Create nginx configuration
sudo tee /etc/nginx/sites-available/boot-server << 'EOF'
server {
    listen 80;
    server_name boot.example.com;
    
    root /var/www/boot;
    
    location /inspector/ {
        autoindex on;
        add_header Cache-Control "public, max-age=3600";
    }
    
    # Optional: serve iPXE boot scripts
    location ~ \.ipxe$ {
        add_header Content-Type "text/plain";
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/boot-server /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Option C: Apache HTTP Server

```bash
# Create directory
sudo mkdir -p /var/www/html/inspector

# Copy files
sudo cp dist/vmlinuz /var/www/html/inspector/
sudo cp dist/initrd.img /var/www/html/inspector/

# Apache configuration
sudo tee /etc/apache2/sites-available/boot-server.conf << 'EOF'
<VirtualHost *:80>
    ServerName boot.example.com
    DocumentRoot /var/www/html
    
    <Directory /var/www/html/inspector>
        Options +Indexes
        Require all granted
    </Directory>
</VirtualHost>
EOF

# Enable site
sudo a2ensite boot-server
sudo systemctl reload apache2
```

## Step 3: Create iPXE Boot Script

Create an iPXE boot script that servers will fetch:

```bash
# Create boot script
sudo tee /var/www/boot/inspect.ipxe << 'EOF'
#!ipxe

echo ========================================
echo Beskar7 Hardware Inspector
echo ========================================
echo.

# Configuration - UPDATE THESE VALUES
set base-url http://boot.example.com/inspector
set api-url http://beskar7.cluster.local:8082
set api-token YOUR_INSPECTION_TOKEN_HERE

# Get hostname from DHCP or generate one
isset ${hostname} && set beskar7-host ${hostname} || set beskar7-host ${mac:hexhyp}

echo Loading kernel...
kernel ${base-url}/vmlinuz \
    beskar7.api=${api-url} \
    beskar7.token=${api-token} \
    beskar7.namespace=default \
    beskar7.host=${beskar7-host} \
    console=tty0 console=ttyS0,115200n8 \
    quiet

echo Loading initrd...
initrd ${base-url}/initrd.img

echo Booting inspector...
boot || shell
EOF

# Set permissions
sudo chmod 644 /var/www/boot/inspect.ipxe
```

### Dynamic Boot Script (Per-Host Configuration)

For production deployments, you may want to generate boot scripts dynamically:

```bash
# Create a CGI script or use a templating system
sudo tee /var/www/boot/inspect.cgi << 'EOF'
#!/bin/bash
echo "Content-Type: text/plain"
echo ""

# Get client IP
CLIENT_IP="${REMOTE_ADDR}"

# Look up host configuration (example with simple file lookup)
HOST_CONFIG="/var/www/boot/hosts/${CLIENT_IP}.conf"
if [ -f "${HOST_CONFIG}" ]; then
    source "${HOST_CONFIG}"
else
    # Default configuration
    NAMESPACE="default"
    TOKEN="default-token"
fi

cat << IPXE
#!ipxe
kernel http://boot.example.com/inspector/vmlinuz \
    beskar7.api=http://beskar7.cluster.local:8082 \
    beskar7.token=${TOKEN} \
    beskar7.namespace=${NAMESPACE} \
    beskar7.host=${CLIENT_IP} \
    console=ttyS0,115200

initrd http://boot.example.com/inspector/initrd.img
boot
IPXE
EOF

chmod +x /var/www/boot/inspect.cgi
```

## Step 4: Configure DHCP Server

### Option A: dnsmasq

```bash
# Edit /etc/dnsmasq.conf
sudo tee -a /etc/dnsmasq.conf << 'EOF'

# PXE Boot Configuration
dhcp-range=192.168.1.100,192.168.1.200,12h

# Match EFI clients
dhcp-match=set:efi-x86_64,option:client-arch,7
dhcp-match=set:efi-x86,option:client-arch,6

# Serve iPXE binary to EFI clients
dhcp-boot=tag:efi-x86_64,ipxe.efi
dhcp-boot=tag:efi-x86,ipxe.efi

# When iPXE is running, serve boot script
dhcp-boot=tag:!efi-x86_64,tag:!efi-x86,http://boot.example.com/inspect.ipxe

# Alternative: detect iPXE by user-class
dhcp-userclass=set:ipxe,iPXE
dhcp-boot=tag:ipxe,http://boot.example.com/inspect.ipxe
EOF

# Restart dnsmasq
sudo systemctl restart dnsmasq
```

### Option B: ISC DHCP Server

```bash
# Edit /etc/dhcp/dhcpd.conf
sudo tee -a /etc/dhcp/dhcpd.conf << 'EOF'

subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;
    option routers 192.168.1.1;
    option domain-name-servers 8.8.8.8, 8.8.4.4;
    
    # PXE Boot configuration
    option architecture-type code 93 = unsigned integer 16;
    
    class "pxeclients" {
        match if substring (option vendor-class-identifier, 0, 9) = "PXEClient";
        
        if option architecture-type = 00:07 {
            # UEFI x86_64
            filename "ipxe.efi";
        } elsif option architecture-type = 00:06 {
            # UEFI x86
            filename "ipxe.efi";
        }
    }
    
    class "ipxeclients" {
        match if exists user-class and option user-class = "iPXE";
        filename "http://boot.example.com/inspect.ipxe";
    }
    
    next-server boot.example.com;
}
EOF

# Restart DHCP server
sudo systemctl restart isc-dhcp-server
```

## Step 5: Configure Physical Servers

### BIOS/UEFI Configuration

For each server you want to inspect:

1. **Enter BIOS/UEFI Setup**
   - Usually DEL, F2, F10, or F12 during boot

2. **Enable Network Boot**
   - Look for "PXE Boot", "Network Boot", or "UEFI Network Boot"
   - Enable on the primary network interface

3. **Set Boot Order**
   - Put Network Boot first (or second after local disk)
   - Ensure UEFI mode (not Legacy/BIOS mode)

4. **Save and Reboot**

### Vendor-Specific Settings

**Dell iDRAC:**
```
System Setup -> Boot Settings -> Boot Mode: UEFI
System Setup -> Boot Settings -> Boot Sequence: PXE Device 1
```

**HPE iLO:**
```
System Configuration -> BIOS/Platform Configuration -> Boot Options
Boot Mode: UEFI
Network Boot: Enabled
Boot Order: Network first
```

**Supermicro:**
```
Boot -> Boot Mode Select: UEFI
Boot -> Boot Option Priorities: Network Device first
```

## Step 6: Verify Deployment

### Test Boot Script Accessibility

```bash
# From a test machine
curl http://boot.example.com/inspect.ipxe

# Should see iPXE script content
```

### Test Kernel/Initrd Download

```bash
# Check file sizes
curl -I http://boot.example.com/inspector/vmlinuz
curl -I http://boot.example.com/inspector/initrd.img

# Should return 200 OK with Content-Length
```

### Test DHCP Configuration

```bash
# From a test client
sudo dhclient -v eth0

# Should receive:
# - IP address
# - Boot filename (ipxe.efi or inspect.ipxe)
```

## Step 7: Test with QEMU (Optional)

Before testing on real hardware, validate with QEMU:

```bash
# Download iPXE EFI binary
wget http://boot.ipxe.org/ipxe.efi

# Boot with QEMU
qemu-system-x86_64 \
    -kernel dist/vmlinuz \
    -initrd dist/initrd.img \
    -append "beskar7.api=http://10.0.2.2:8082 beskar7.token=test123 beskar7.namespace=default beskar7.host=qemu-test console=ttyS0" \
    -m 2048 \
    -nographic
```

## Step 8: Test on Real Hardware

1. Power on a server
2. Watch console output (serial console or BMC virtual console)
3. Verify:
   - DHCP request succeeds
   - iPXE loads
   - Boot script fetched
   - Kernel loads
   - Initrd loads
   - Alpine boots
   - Inspection starts

4. Monitor Beskar7 controller logs:
```bash
kubectl logs -n beskar7-system -l app.kubernetes.io/name=beskar7 -f
```

5. Check PhysicalHost status:
```bash
kubectl get physicalhost <name> -o yaml
```

## Deployment Checklist

- [ ] Inspector image built successfully
- [ ] Files deployed to HTTP server
- [ ] HTTP server accessible from target servers
- [ ] iPXE boot script created and accessible
- [ ] DHCP server configured for PXE boot
- [ ] Beskar7 controller running and accessible
- [ ] Firewall rules allow required traffic
- [ ] Test server BIOS configured for PXE boot
- [ ] Successful test boot (QEMU or real hardware)
- [ ] Inspection report received by controller

## Troubleshooting

See [troubleshooting.md](troubleshooting.md) for common issues and solutions.

## Next Steps

- [Testing Guide](testing.md) - Comprehensive testing procedures
- [iPXE Examples](ipxe-examples.md) - Advanced boot script examples
- [API Integration](api-integration.md) - Understanding the inspection API

