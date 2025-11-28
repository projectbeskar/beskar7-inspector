#!/bin/bash
# Beskar7-Inspector Report Submission

set -e

. /opt/beskar7-inspector/utils.sh

log_info "===== Submitting Inspection Report to Beskar7 ====="

# Check report file exists
REPORT_FILE=$WORK_DIR/hardware-report.json
if [ ! -f "$REPORT_FILE" ]; then
    log_error "Report file not found: $REPORT_FILE"
    exit 1
fi

# Validate JSON
if ! jq empty $REPORT_FILE 2>/dev/null; then
    log_error "Invalid JSON in report file"
    cat $REPORT_FILE
    exit 1
fi

log_info "Report file validated"
log_debug "Report contents:"
if [ "$DEBUG" = "true" ]; then
    jq '.' $REPORT_FILE
fi

# API endpoint
API_ENDPOINT="$BESKAR7_API/api/v1/inspection"
log_info "API Endpoint: $API_ENDPOINT"

# Submit report with retries
log_info "Submitting inspection report..."

submit_report() {
    local response
    response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d @$REPORT_FILE \
        --max-time 30 \
        "$API_ENDPOINT" 2>&1)
    
    local http_code=$(echo "$response" | tail -1)
    local body=$(echo "$response" | head -n -1)
    
    log_debug "HTTP Status: $http_code"
    log_debug "Response: $body"
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        log_info "✓ Report submitted successfully"
        echo "$body" > $WORK_DIR/api-response.json
        return 0
    else
        log_error "✗ Report submission failed (HTTP $http_code)"
        log_error "Response: $body"
        return 1
    fi
}

if retry_command 3 5 submit_report; then
    log_info "Report submission complete"
    
    # Parse response for target OS URL (if provided)
    if [ -f $WORK_DIR/api-response.json ]; then
        TARGET_OS=$(jq -r '.targetOS // empty' $WORK_DIR/api-response.json 2>/dev/null || echo "")
        if [ -n "$TARGET_OS" ]; then
            log_info "Target OS URL received: $TARGET_OS"
            echo "$TARGET_OS" > $WORK_DIR/target-os-url.txt
        else
            log_info "No target OS URL in response (inspection only)"
        fi
    fi
else
    log_error "Failed to submit report after multiple attempts"
    log_error "Entering debug mode..."
    
    # Save debug info
    echo "=== Debug Information ===" > $WORK_DIR/debug.log
    echo "Report file:" >> $WORK_DIR/debug.log
    cat $REPORT_FILE >> $WORK_DIR/debug.log
    echo "" >> $WORK_DIR/debug.log
    echo "Network test:" >> $WORK_DIR/debug.log
    curl -v $API_ENDPOINT >> $WORK_DIR/debug.log 2>&1
    
    # Don't exit - allow inspection to continue for debugging
    log_warn "Continuing despite report submission failure"
fi

