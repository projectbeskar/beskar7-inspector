#!/bin/bash
# Beskar7-Inspector Hardware Detection

set -e

source /opt/beskar7-inspector/utils.sh

log_info "===== Starting Hardware Inspection ====="

# Output file
REPORT_FILE=$WORK_DIR/hardware-report.json

# Check required tools
check_required_tools dmidecode lscpu lsblk ip jq || {
    log_error "Required tools missing"
    exit 1
}

log_info "Detecting system information..."

# System Information
MANUFACTURER=$(dmidecode -s system-manufacturer 2>/dev/null | tr -d '\n' || echo "Unknown")
MODEL=$(dmidecode -s system-product-name 2>/dev/null | tr -d '\n' || echo "Unknown")
SERIAL=$(dmidecode -s system-serial-number 2>/dev/null | tr -d '\n' || echo "Unknown")
BIOS_VERSION=$(dmidecode -s bios-version 2>/dev/null | tr -d '\n' || echo "Unknown")

log_info "  Manufacturer: $MANUFACTURER"
log_info "  Model: $MODEL"
log_info "  Serial: $SERIAL"

# Detect boot mode
if [ -d /sys/firmware/efi ]; then
    BOOT_MODE="UEFI"
else
    BOOT_MODE="Legacy"
fi
log_info "  Boot Mode: $BOOT_MODE"

# CPU Information
log_info "Detecting CPU information..."
CPU_JSON=$(lscpu -J 2>/dev/null || echo '{"lscpu":[]}')
CPU_COUNT=$(grep -c ^processor /proc/cpuinfo)
CPU_MODEL=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
CPU_CORES=$(lscpu | grep "^Core(s)" | awk '{print $NF}')
CPU_THREADS=$(lscpu | grep "^Thread(s)" | awk '{print $NF}')
CPU_MHZ=$(lscpu | grep "^CPU MHz" | awk '{print $NF}')

log_info "  CPUs: $CPU_COUNT"
log_info "  Model: $CPU_MODEL"
log_info "  Cores per CPU: $CPU_CORES"
log_info "  Threads per core: $CPU_THREADS"

# Memory Information
log_info "Detecting memory information..."
MEM_TOTAL_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM_TOTAL_GB=$((MEM_TOTAL_KB / 1024 / 1024))

log_info "  Total Memory: ${MEM_TOTAL_GB}GB"

# Detailed memory info from dmidecode
MEMORY_MODULES=$(dmidecode -t memory 2>/dev/null | grep -A 20 "Memory Device" | grep -E "Size|Type:|Speed:|Locator:" | paste - - - - | grep -v "No Module" || echo "")

# Disk Information
log_info "Detecting disk information..."
DISKS_JSON=$(lsblk -J -o NAME,SIZE,TYPE,MODEL,SERIAL 2>/dev/null | jq -c '.blockdevices[] | select(.type=="disk")')

# Network Information
log_info "Detecting network information..."
NICS_JSON=$(ip -j addr 2>/dev/null | jq -c '.[] | select(.link_type!="loopback")')

# Build JSON report
log_info "Generating inspection report..."

cat > $REPORT_FILE << EOF
{
  "namespace": "$BESKAR7_NAMESPACE",
  "hostName": "$BESKAR7_HOST",
  "manufacturer": "$MANUFACTURER",
  "model": "$MODEL",
  "serialNumber": "$SERIAL",
  "bootModeDetected": "$BOOT_MODE",
  "firmwareVersion": "$BIOS_VERSION",
  "cpus": [
EOF

# Add CPU info
FIRST_CPU=true
for i in $(seq 0 $((CPU_COUNT - 1))); do
    if [ "$FIRST_CPU" = false ]; then
        echo "," >> $REPORT_FILE
    fi
    FIRST_CPU=false
    
    cat >> $REPORT_FILE << CPUEOF
    {
      "id": "$i",
      "vendor": "$(lscpu | grep "Vendor ID" | awk '{print $NF}' || echo 'Unknown')",
      "model": "$CPU_MODEL",
      "cores": ${CPU_CORES:-1},
      "threads": ${CPU_THREADS:-1},
      "frequency": "${CPU_MHZ:-0}MHz"
    }
CPUEOF
done

cat >> $REPORT_FILE << EOF

  ],
  "memory": [
EOF

# Add memory info (simplified - one entry for total)
cat >> $REPORT_FILE << MEMEOF
    {
      "id": "Total",
      "type": "DDR4",
      "capacity": "${MEM_TOTAL_GB}GB",
      "speed": "Unknown"
    }
MEMEOF

cat >> $REPORT_FILE << EOF

  ],
  "disks": [
EOF

# Add disk info
FIRST_DISK=true
while IFS= read -r disk_json; do
    if [ -z "$disk_json" ]; then continue; fi
    
    if [ "$FIRST_DISK" = false ]; then
        echo "," >> $REPORT_FILE
    fi
    FIRST_DISK=false
    
    DISK_NAME=$(echo "$disk_json" | jq -r '.name // "unknown"')
    DISK_SIZE=$(echo "$disk_json" | jq -r '.size // "0"')
    DISK_MODEL=$(echo "$disk_json" | jq -r '.model // "Unknown"')
    DISK_SERIAL=$(echo "$disk_json" | jq -r '.serial // "Unknown"')
    
    # Determine disk type
    DISK_TYPE="HDD"
    if echo "$DISK_NAME" | grep -q "nvme"; then
        DISK_TYPE="NVMe"
    elif [ -f "/sys/block/$DISK_NAME/queue/rotational" ]; then
        if [ "$(cat /sys/block/$DISK_NAME/queue/rotational)" = "0" ]; then
            DISK_TYPE="SSD"
        fi
    fi
    
    # Convert size to GB (simplified)
    DISK_SIZE_GB=$(echo "$DISK_SIZE" | sed 's/[^0-9]//g' | awk '{print int($1/1024/1024/1024)}')
    
    cat >> $REPORT_FILE << DISKEOF
    {
      "name": "/dev/$DISK_NAME",
      "model": "$DISK_MODEL",
      "sizeGB": ${DISK_SIZE_GB:-0},
      "type": "$DISK_TYPE",
      "serialNumber": "$DISK_SERIAL"
    }
DISKEOF
done <<< "$DISKS_JSON"

cat >> $REPORT_FILE << EOF

  ],
  "nics": [
EOF

# Add NIC info
FIRST_NIC=true
while IFS= read -r nic_json; do
    if [ -z "$nic_json" ]; then continue; fi
    
    if [ "$FIRST_NIC" = false ]; then
        echo "," >> $REPORT_FILE
    fi
    FIRST_NIC=false
    
    NIC_NAME=$(echo "$nic_json" | jq -r '.ifname // "unknown"')
    NIC_MAC=$(echo "$nic_json" | jq -r '.address // "unknown"')
    NIC_STATE=$(echo "$nic_json" | jq -r '.operstate // "unknown"')
    
    # Get IP addresses
    NIC_IPS=$(echo "$nic_json" | jq -r '[.addr_info[].local] | join(", ")' 2>/dev/null || echo "")
    
    # Get speed (if available)
    NIC_SPEED="Unknown"
    if [ -f "/sys/class/net/$NIC_NAME/speed" ]; then
        SPEED_MBPS=$(cat /sys/class/net/$NIC_NAME/speed 2>/dev/null || echo "0")
        if [ "$SPEED_MBPS" != "0" ] && [ "$SPEED_MBPS" != "-1" ]; then
            if [ $SPEED_MBPS -ge 1000 ]; then
                NIC_SPEED="$((SPEED_MBPS/1000))Gbps"
            else
                NIC_SPEED="${SPEED_MBPS}Mbps"
            fi
        fi
    fi
    
    # Get driver
    NIC_DRIVER=$(readlink /sys/class/net/$NIC_NAME/device/driver 2>/dev/null | xargs basename || echo "Unknown")
    
    cat >> $REPORT_FILE << NICEOF
    {
      "name": "$NIC_NAME",
      "macAddress": "$NIC_MAC",
      "driver": "$NIC_DRIVER",
      "speed": "$NIC_SPEED",
      "ipAddresses": ["$NIC_IPS"]
    }
NICEOF
done <<< "$NICS_JSON"

cat >> $REPORT_FILE << EOF

  ]
}
EOF

log_info "Hardware inspection complete"
log_debug "Report saved to: $REPORT_FILE"

# Show summary
log_info "Inspection Summary:"
log_info "  System: $MANUFACTURER $MODEL"
log_info "  CPUs: $CPU_COUNT x $CPU_CORES cores"
log_info "  Memory: ${MEM_TOTAL_GB}GB"
log_info "  Disks: $(echo "$DISKS_JSON" | wc -l)"
log_info "  NICs: $(echo "$NICS_JSON" | wc -l)"

