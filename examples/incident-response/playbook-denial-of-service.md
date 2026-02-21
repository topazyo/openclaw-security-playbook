# Incident Response Playbook: Denial of Service / Resource Exhaustion

**Playbook ID**: IRP-007  
**Severity**: P1 - High (can escalate to P0 if critical services unavailable)  
**Estimated Response Time**: 30 minutes (initial mitigation) + 6 hours (full response)  
**Last Updated**: 2026-02-14  
**Owner**: Infrastructure & Security Operations Team

---

## Table of Contents

1. [Overview](#overview)
2. [Related Documents](#related-documents)
3. [Detection Indicators](#detection-indicators)
4. [Attack Classification](#attack-classification)
5. [Containment & Mitigation](#containment--mitigation)
6. [Eradication](#eradication)
7. [Recovery](#recovery)
8. [Post-Incident Review](#post-incident-review)
9. [Appendix](#appendix)

---

## Overview

### Purpose
This playbook provides step-by-step procedures for responding to Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks targeting OpenClaw/ClawdBot infrastructure, including resource exhaustion, API abuse, and conversation flooding.

### Scope
- **Attack types**: Volumetric attacks (bandwidth saturation), protocol attacks (SYN floods), application-layer attacks (HTTP floods, API abuse)
- **Attack vectors**: Direct DoS, DDoS botnets, resource exhaustion via malicious prompts, conversation flooding, rate limit bypass
- **Systems covered**: API gateways, agent instances, databases, MCP servers, network infrastructure

### Success Criteria
- ✅ Service availability restored within 30 minutes (P1 SLA)
- ✅ Legitimate user traffic unaffected (<5% error rate)
- ✅ Attack sources identified and blocked
- ✅ Rate limiting and autoscaling validated effective

---

## Related Documents

### Policies & Procedures
- **[SEC-004 Incident Response Policy](../../docs/policies/incident-response-policy.md)** - P1 incident classification, 1-hour response SLA
- **[Incident Response Procedure](../../docs/procedures/incident-response.md)** - 5-phase IR framework
- **[Runtime Sandboxing](../../docs/guides/04-runtime-sandboxing.md)** - Resource limits and quotas

### Attack Scenarios
- **[Scenario 007: Denial of Service via Resource Exhaustion](../scenarios/scenario-007-denial-of-service-resource-exhaustion.md)** - Malicious prompt causing infinite loop
- **[API Rate Limiting](../../configs/templates/gateway.hardened.yml)** - Rate limit configuration examples

### Technical References
- **[Monitoring Stack](../../configs/examples/monitoring-stack.yml)** - Prometheus/Grafana for resource monitoring
- **[Auto-Containment Script](../../scripts/incident-response/auto-containment.py)** - Automated response actions
- **[Production Kubernetes](../../configs/examples/production-k8s.yml)** - HPA configuration

---

## Detection Indicators

### High-Confidence Indicators (Immediate Response)

1. **Service Unavailability**
   
   ```bash
   # Check service health endpoints
   curl -w "@curl-format.txt" -o /dev/null -s https://gateway.openclaw.ai/health
   
   # Expected: HTTP 200, <500ms response time
   # Alert: HTTP 5xx or timeout >5s
   ```
   
   **Alert Example**:
   ```json
   {
     "timestamp": "2026-02-14T18:45:22Z",
     "alert_type": "service_degradation",
     "severity": "critical",
     "service": "openclaw-gateway",
     "metrics": {
       "http_5xx_rate": 0.73,
       "avg_response_time_ms": 12450,
       "timeout_rate": 0.52
     },
     "threshold_exceeded": {
       "5xx_rate": {"threshold": 0.05, "actual": 0.73, "exceeded_by": "14.6x"},
       "response_time": {"threshold_ms": 500, "actual_ms": 12450, "exceeded_by": "24.9x"}
     }
   }
   ```

2. **Resource Exhaustion**
   
   **CPU Saturation**:
   ```bash
   # Check pod CPU usage (Kubernetes)
   kubectl top pods -n openclaw-prod | awk '$3 > 90 {print $0}'
   
   # Example output showing exhaustion:
   # NAME                    CPU(cores)   MEMORY(bytes)
   # agent-prod-42           1950m        512Mi      # 1.95 cores (~195% of limit)
   # agent-prod-43           1980m        498Mi
   # gateway-7f9d8c-xkq2p    3920m        1024Mi     # 3.92 cores (392% of limit)
   ```
   
   **Memory Pressure**:
   ```bash
   # Check memory usage
   kubectl top pods -n openclaw-prod --sort-by=memory | head -20
   
   # Check for OOMKilled containers
   kubectl get pods -n openclaw-prod -o json | \
     jq '.items[] | select(.status.containerStatuses[]?.lastState.terminated.reason == "OOMKilled") | .metadata.name'
   ```
   
   **openclaw-telemetry Alert**:
   ```json
   {
     "timestamp": "2026-02-14T18:42:10Z",
     "alert_type": "resource_exhaustion",
     "severity": "high",
     "affected_agents": ["agent-prod-42", "agent-prod-43", "agent-prod-44"],
     "resource_metrics": {
       "cpu_usage_percent": 98.7,
       "memory_usage_percent": 94.3,
       "disk_io_wait_percent": 56.2,
       "network_connections": 15247
     },
     "anomaly_score": 0.96
   }
   ```

3. **Rate Limit Violations**
   
   ```bash
   # Query API gateway for rate limit blocks
   curl -X GET "https://gateway.openclaw.ai/metrics/rate-limits?window=5m" \
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq '
     .rate_limit_events | map(select(.blocked == true)) | 
     group_by(.source_ip) | 
     map({ip: .[0].source_ip, blocks: length}) | 
     sort_by(.blocks) | reverse | .[0:10]
   '
   ```
   
   **openclaw-shield Rate Limit Alert**:
   ```json
   {
     "timestamp": "2026-02-14T18:40:00Z",
     "alert_type": "rate_limit_exceeded",
     "severity": "high",
     "source_ip": "203.0.113.42",
     "user_agent": "python-requests/2.31.0",
     "requests_blocked": 8472,
     "rate_limit_config": {
       "limit": "100 requests per minute",
       "burst": 150
     },
     "actual_rate": "8472 requests in 1 minute (84.7x over limit)",
     "action_taken": "ip_blocked_temporarily"
   }
   ```

4. **Abnormal Traffic Patterns**
   
   ```bash
   # Analyze access logs for traffic spikes
   zcat /var/log/openclaw/access-*.log.gz | \
     awk '{print $1}' | \
     sort | uniq -c | sort -rn | head -20
   
   # Example showing DDoS pattern:
   # 15247 203.0.113.42      # Single IP with 15k requests
   # 12883 198.51.100.55
   # 11294 192.0.2.78
   #   421 10.20.30.40        # Legitimate traffic ~400 requests
   #   387 10.20.30.41
   ```
   
   **Traffic Baseline Comparison**:
   ```bash
   # Compare current vs baseline traffic
   curl -X GET "https://monitoring.openclaw.ai/api/datasources/proxy/1/api/v1/query" \
     --data-urlencode 'query=rate(http_requests_total[5m])' | \
     jq '.data.result[0].value[1]'
   
   # Baseline (normal): ~150 req/s
   # Current (attack): ~8500 req/s (56.7x baseline)
   ```

### Medium-Confidence Indicators (Investigate)

5. **Conversation Database Overload**
   
   ```sql
   -- Check for long-running queries (potential resource exhaustion)
   SELECT pid, usename, state, query_start, 
          NOW() - query_start AS duration,
          LEFT(query, 100) AS query_preview
   FROM pg_stat_activity
   WHERE state != 'idle'
     AND NOW() - query_start > INTERVAL '30 seconds'
   ORDER BY duration DESC
   LIMIT 20;
   ```

6. **Network Bandwidth Saturation**
   
   ```bash
   # Check network interface bandwidth usage
   sar -n DEV 1 10 | grep eth0
   
   # Alert if rxkB/s or txkB/s exceeds 80% of interface capacity
   # Example: 1Gbps interface = 125MB/s max, alert at >100MB/s
   ```

---

## Attack Classification

### Type A: Volumetric Attacks (Network Layer)

**Characteristics**:
- High packet rate (>100k pps)
- Bandwidth saturation (>80% of capacity)
- Protocol: UDP floods, ICMP floods, DNS amplification

**Detection**:
```bash
# Check packet rate
netstat -s | grep -i "packets received"

# Check for UDP floods
tcpdump -i eth0 udp -c 1000 | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn
```

**Mitigation**: Layer 3/4 filtering, upstream ISP filtering, cloud DDoS protection

---

### Type B: Protocol Attacks (Transport Layer)

**Characteristics**:
- SYN floods (half-open connections)
- ACK floods
- Fragmented packet attacks

**Detection**:
```bash
# Check for SYN floods
netstat -an | grep SYN_RECV | wc -l
# Alert if >1000 SYN_RECV connections

# Check connection states
ss -s
# Example output during SYN flood:
# TCP:   15247 (estab 42, closed 14982, orphaned 223, synrecv 14567, timewait 415/0)
```

**Mitigation**: SYN cookies, connection rate limiting, TCP state validation

---

### Type C: Application-Layer Attacks (Layer 7)

**Characteristics**:
- HTTP floods (GET/POST spam)
- API endpoint abuse
- Slowloris (slow HTTP requests)
- Malicious prompts causing infinite loops

**Detection**:
```bash
# Check HTTP request patterns
tail -f /var/log/openclaw/access.log | \
  awk '{print $7}' | sort | uniq -c | sort -rn
# Alert if single endpoint receives >1000 req/s

# Identify slowloris attacks (long-lived connections with minimal data)
ss -o state established '( dport = :80 or dport = :443 )' | \
  grep -o 'timer:([^)]*' | cut -d: -f2 | sort | uniq -c
```

**Mitigation**: Rate limiting, CAPTCHA challenges, request validation, WAF rules

---

### Type D: Resource Exhaustion (OpenClaw-Specific)

**Characteristics**:
- Malicious prompts causing CPU/memory spikes
- Conversation flooding (storing excessive data)
- Skill execution loops

**Detection**:
```bash
# openclaw-telemetry resource anomaly detection
curl -X GET "https://telemetry.openclaw.ai/api/anomalies?type=resource_exhaustion&hours=1" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Example - Infinite Loop Prompt**:
```
User prompt: "Count from 1 to infinity and respond with each number"
Result: Agent enters infinite loop, CPU 100%, eventually OOMKilled
```

**Mitigation**: See **[Scenario 007](../scenarios/scenario-007-denial-of-service-resource-exhaustion.md)** for detailed response

---

## Containment & Mitigation

**Goal**: Restore service availability for legitimate users while blocking attack traffic.  
**Time Bound**: Complete within 30 minutes for P1, 15 minutes for P0.

### Phase 1: Emergency Mitigation (0-5 minutes)

1. **Enable DDoS Protection** (if cloud-hosted)
   
   **AWS Shield Advanced**:
   ```bash
   # Enable AWS Shield Advanced (if not already active)
   aws shield subscribe-to-shield-advanced
   
   # Create DDoS Response Team (DRT) authorization
   aws shield create-protection \
     --name openclaw-gateway-protection \
     --resource-arn arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/openclaw-gateway/abc123
   ```
   
   **Cloudflare (if using)**:
   ```bash
   # Enable "Under Attack Mode" (aggressive challenge)
   curl -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/settings/security_level" \
     -H "Authorization: Bearer $CF_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"value":"under_attack"}'
   ```

2. **Block Top Attacking IPs** (immediate action)
   
   ```bash
   # Identify top 20 attacking IPs
   TOP_IPS=$(zcat /var/log/openclaw/access-*.log.gz | \
     awk '{print $1}' | sort | uniq -c | sort -rn | head -20 | awk '{print $2}')
   
   # Block at firewall level
   for ip in $TOP_IPS; do
     # Check if IP is attacking (>1000 req/min)
     req_count=$(grep "$ip" /var/log/openclaw/access.log | wc -l)
     if [ $req_count -gt 1000 ]; then
       echo "Blocking attacking IP: $ip ($req_count requests)"
       iptables -A INPUT -s "$ip" -j DROP
       
       # Also block in cloud WAF
       aws wafv2 create-ip-set \
         --name block-ddos-$(date +%s) \
         --scope REGIONAL \
         --ip-address-version IPV4 \
         --addresses "$ip/32"
     fi
   done
   ```

3. **Engage Rate Limiting** (aggressive mode)
   
   ```bash
   # Lower rate limits to aggressive mode
   ./scripts/incident-response/auto-containment.py \
     --action update_rate_limits \
     --mode aggressive \
     --limits '{
       "per_ip_per_minute": 10,
       "per_user_per_minute": 20,
       "global_per_second": 500
     }'
   ```

4. **Scale Infrastructure** (immediate capacity increase)
   
   ```bash
   # Kubernetes HPA - increase max replicas
   kubectl patch hpa openclaw-gateway-hpa -n openclaw-prod \
     --patch '{"spec":{"maxReplicas":50}}'
   
   # Force immediate scale-up
   kubectl scale deployment openclaw-gateway -n openclaw-prod --replicas=30
   
   # Check scaling progress
   kubectl get hpa -n openclaw-prod -w
   ```

### Phase 2: Detailed Analysis (5-30 minutes)

5. **Classify Attack Type**
   
   ```bash
   # Build a quick attack profile from recent access logs
   zcat /var/log/openclaw/access-*.log.gz | \
     awk '{print $1}' | sort | uniq -c | sort -rn | head -20 > attack-top-sources.txt

   TOTAL_REQ=$(awk '{sum += $1} END {print sum+0}' attack-top-sources.txt)
   UNIQUE_IPS=$(wc -l < attack-top-sources.txt)

   jq -n \
     --argjson total_requests "${TOTAL_REQ:-0}" \
     --argjson unique_ips "${UNIQUE_IPS:-0}" \
     '{total_requests: $total_requests, unique_source_ips: $unique_ips}' > attack-analysis.json
   ```
   
   **Attack Classification Output**:
   ```json
   {
     "attack_type": "application_layer_http_flood",
     "confidence": 0.94,
     "characteristics": {
       "request_rate": 8472,
       "baseline_rate": 150,
       "amplification_factor": 56.5,
       "source_ips_count": 247,
       "distributed": true,
       "user_agent_diversity": 0.12,
       "target_endpoints": ["/api/v1/conversations", "/api/v1/prompt"],
       "request_method_distribution": {"POST": 0.97, "GET": 0.03}
     },
     "recommended_mitigations": [
       "rate_limit_per_endpoint",
       "captcha_challenge",
       "block_bot_user_agents",
       "geographic_filtering"
     ]
   }
   ```

6. **Identify Botnet vs Single Source**
   
   ```bash
   # Check if attack is distributed (DDoS) or single source (DoS)
   UNIQUE_IPS=$(zcat /var/log/openclaw/access-*.log.gz | \
     awk '{print $1}' | sort -u | wc -l)
   
   if [ $UNIQUE_IPS -gt 100 ]; then
     echo "⚠️  DISTRIBUTED ATTACK (DDoS): $UNIQUE_IPS unique IPs"
     ATTACK_TYPE="ddos_botnet"
   else
     echo "⚠️  SINGLE-SOURCE ATTACK (DoS): $UNIQUE_IPS IPs"
     ATTACK_TYPE="dos_single_source"
   fi
   ```

7. **Implement Targeted Mitigations**
   
   **For Application-Layer Attacks**:
   ```bash
   # Enable CAPTCHA challenge for suspicious traffic
   curl -X POST "https://gateway.openclaw.ai/admin/security/captcha" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{
       "enabled": true,
       "trigger_conditions": {
         "requests_per_minute_threshold": 50,
         "anomaly_score_threshold": 0.7
       }
     }'
   
   # Block non-browser user agents (botnet indicators)
   curl -X POST "https://gateway.openclaw.ai/admin/security/user-agent-filter" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{
       "block_patterns": [
         "python-requests", "curl", "wget", "bot", "crawler", 
         "scanner", "nikto", "sqlmap"
       ],
       "allow_legitimate_bots": ["Googlebot", "Bingbot"]
     }'
   ```
   
   **For Volumetric Attacks**:
   ```bash
   # Contact ISP to implement upstream filtering
   # (Manual process - phone call to ISP NOC)
   echo "Contact ISP: 1-800-ISP-HELP"
   echo "Request: BGP blackhole routing for attacking prefixes"
   
   # Example ISP blackhole announcement (BGP community)
   # ISP will advertise null route for specific prefixes
   # Syntax varies by ISP - check ISP documentation
   ```

### Phase 3: Continuous Monitoring (30+ minutes)

8. **Monitor Attack Evolution**
   
   ```bash
   # Real-time dashboard (Grafana)
   curl -X GET "https://monitoring.openclaw.ai/api/dashboards/uid/ddos-response" \
     -H "Authorization: Bearer $GRAFANA_TOKEN"
   
   # Watch key metrics every 30 seconds
   watch -n 30 '
     echo "=== Current Traffic Rate ===" &&
     curl -s "https://gateway.openclaw.ai/metrics" | grep http_requests_total &&
     echo "=== Blocked IPs ===" &&
     iptables -L INPUT -v -n | grep DROP | wc -l &&
     echo "=== Service Health ===" &&
     kubectl get pods -n openclaw-prod | grep -v Running
   '
   ```

---

## Eradication

**Goal**: Permanently block attack sources and close attack vectors.  
**Time Bound**: Complete within 6 hours for P1, 12 hours for P0.

1. **Permanent IP Blocklist**
   
   ```bash
   # Move temporary iptables rules to permanent blocklist
   iptables-save | grep DROP > /etc/iptables/ddos-blocklist.rules
   
   # Add to cloud WAF permanent blocklist
   aws wafv2 create-ip-set \
     --name openclaw-permanent-blocklist \
     --scope REGIONAL \
     --ip-address-version IPV4 \
     --addresses file://blocked-ips.txt
   ```

2. **Geographic Filtering** (if applicable)
   
   ```bash
   # If attack originates from specific countries, implement geo-blocking
   # (Only if no legitimate users in those regions)
   
   curl -X POST "https://gateway.openclaw.ai/admin/security/geo-filter" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{
       "blocked_countries": ["XX", "YY"],  # ISO 3166-1 alpha-2 codes
       "reason": "DDoS attack source - IRP-007"
     }'
   ```

3. **Update Rate Limiting Strategy**
   
   ```bash
   # Implement adaptive rate limiting based on attack patterns
   cat > /etc/openclaw/rate-limits-adaptive.yml <<EOF
   rate_limits:
     # Stricter limits for high-risk endpoints
     - endpoint: "/api/v1/conversations"
       per_ip_per_minute: 30
       per_user_per_minute: 100
       burst: 10
     
     # Challenge suspicious traffic patterns
     - endpoint: "/api/v1/prompt"
       per_ip_per_minute: 20
       per_user_per_minute: 50
       captcha_threshold: 15  # CAPTCHA after 15 req/min
     
     # Global circuit breaker
     - global:
         total_requests_per_second: 1000
         circuit_breaker_threshold: 0.20  # Open circuit if 20% errors
   EOF
   
   # Apply updated rate limits
   kubectl apply -f /etc/openclaw/rate-limits-adaptive.yml
   ```

4. **Implement Proof-of-Work Challenge** (for persistent attackers)
   
   ```javascript
   // Example: Client-side computational challenge
   // Add to API gateway for high-risk endpoints
   
   app.use('/api/v1/conversations', async (req, res, next) => {
     const challenge = req.headers['x-pow-challenge'];
     const solution = req.headers['x-pow-solution'];
     
     if (!verifyProofOfWork(challenge, solution, difficulty=4)) {
       return res.status(429).json({
         error: 'Proof-of-work required',
         challenge: generateChallenge(),
         difficulty: 4
       });
     }
     
     next();
   });
   ```

---

## Recovery

**Goal**: Return to normal operations and restore full service availability.  
**Time Bound**: Complete within 6 hours for P1, 24 hours for P0.

1. **Gradual Rate Limit Relaxation**
   
   ```bash
   # After attack subsides, gradually increase rate limits
   # Step 1 (T+2 hours): 50% of normal limits
   # Step 2 (T+4 hours): 75% of normal limits  
   # Step 3 (T+6 hours): 100% of normal limits

   for step in 50 75 100; do
     echo "Applying ${step}% of normal rate limits"
     kubectl patch configmap openclaw-rate-limits -n openclaw-prod \
       --type merge \
       -p "{\"data\":{\"normal_limit_percent\":\"${step}\"}}"
     sleep 7200
   done
   ```

2. **Scale Down Infrastructure**
   
   ```bash
   # Return HPA to normal max replicas
   kubectl patch hpa openclaw-gateway-hpa -n openclaw-prod \
     --patch '{"spec":{"maxReplicas":20}}'
   
   # Allow natural scale-down (don't force)
   # Kubernetes will gradually remove excess pods
   ```

3. **Disable Emergency Measures**
   
   ```bash
   # Disable Cloudflare "Under Attack Mode"
   curl -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/settings/security_level" \
     -H "Authorization: Bearer $CF_API_TOKEN" \
     -d '{"value":"high"}'  # Back to normal security level
   
   # Disable aggressive CAPTCHA
   curl -X PATCH "https://gateway.openclaw.ai/admin/security/captcha" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{"enabled": false}'
   ```

4. **Verify Service Quality**
   
   ```bash
   # Run synthetic health checks for 30 minutes (60 samples, every 30s)
   for i in $(seq 1 60); do
     curl -s -o /dev/null -w "%{http_code} %{time_total}\n" \
       https://gateway.openclaw.ai/health >> synthetic-health.log
     curl -s -o /dev/null -w "%{http_code} %{time_total}\n" \
       https://gateway.openclaw.ai/api/v1/status >> synthetic-status.log
     sleep 30
   done
   
   # Check error rates
   curl -X GET "https://monitoring.openclaw.ai/api/datasources/proxy/1/api/v1/query" \
     --data-urlencode 'query=rate(http_requests_total{code=~"5.."}[5m])' | \
     jq '.data.result[0].value[1]'
   # Expected: <0.01 (1% error rate)
   ```

5. **Customer Communication**
   
   ```bash
   # Send status page update
   curl -X POST "https://status.openclaw.ai/api/incidents" \
     -H "Authorization: Bearer $STATUSPAGE_TOKEN" \
     -d '{
       "incident": {
         "name": "Service Degradation - DDoS Attack (Resolved)",
         "status": "resolved",
         "message": "We have successfully mitigated a DDoS attack. All services are now operating normally. We apologize for any inconvenience.",
         "components": ["API Gateway", "Agent Platform"]
       }
     }'
   ```

---

## Post-Incident Review

Use the standardized template: **[reporting-template.md](reporting-template.md)**

### Key Sections to Complete

1. **Executive Summary**
   - Attack type (volumetric / protocol / application-layer / resource exhaustion)
   - Attack duration and peak traffic
   - Service impact (downtime, degradation)
   - Mitigation effectiveness

2. **Timeline**
   ```
   2026-02-14 18:40:00 UTC - openclaw-shield detects abnormal request rate (8500 req/s vs 150 baseline)
   2026-02-14 18:42:10 UTC - Resource exhaustion alerts trigger (CPU 98.7%, memory 94.3%)
   2026-02-14 18:45:22 UTC - Service degradation confirmed (HTTP 5xx rate 73%, response time 12.4s)
   2026-02-14 18:47:00 UTC - Incident Commander initiates response, classifies as P1-High
   2026-02-14 18:50:00 UTC - Top 20 attacking IPs blocked, rate limiting enabled (SLA: 30min, Actual: 10min) ✅
   2026-02-14 18:55:00 UTC - Infrastructure scaled (10 → 30 replicas)
   2026-02-14 19:15:00 UTC - Attack classified as application-layer HTTP flood (247 botnet IPs)
   2026-02-14 19:30:00 UTC - CAPTCHA challenge enabled, user-agent filtering active
   2026-02-14 20:00:00 UTC - Attack traffic reduced by 94% (8500 → 510 req/s)
   2026-02-14 20:45:00 UTC - Service fully restored (5xx rate <1%, response time 450ms)
   2026-02-14 23:00:00 UTC - Rate limits returned to normal, emergency measures disabled
   ```

3. **Attack Characteristics**
   - **Type**: Application-layer HTTP flood (DDoS)
   - **Source**: 247 unique IPs (botnet)
   - **Peak Traffic**: 8,500 req/s (56.7x baseline)
   - **Duration**: 2 hours 45 minutes
   - **Target Endpoints**: `/api/v1/conversations` (74%), `/api/v1/prompt` (23%)
   - **Geographic Distribution**: 78% from AS64496 (known botnet), distributed across 23 countries
   - **User-Agent**: 97% python-requests/2.31.0 (botnet signature)

4. **Impact Assessment**
   - **Service Availability**: 27% downtime (45 min total unavailable)
   - **Users Affected**: ~800 users (attempted requests during attack)
   - **Failed Requests**: 47,214 requests (HTTP 5xx or timeout)
   - **Revenue Impact**: Estimated $2,400 (subscriptions pro-rated for downtime per SLA)
   - **Compliance**: No SLA breach (99.9% uptime = 43.2 min/month allowed, used 45 min this month)

5. **Defense Effectiveness**
   
   | Mitigation | Effectiveness | Notes |
   |------------|---------------|-------|
   | IP blocking (iptables) | ✅ High (94% reduction) | Blocked 247 botnet IPs |
   | Rate limiting | ✅ High | Aggressive mode limited attack impact |
   | Infrastructure scaling | ✅ High | HPA scaled 10→30 replicas in 5 min |
   | CAPTCHA challenge | ⚠️ Medium | Effective but impacted legitimate users (12% false positives) |
   | User-agent filtering | ✅ High | Blocked 97% of botnet traffic |
   | WAF rules | ❌ Not used | Cloud WAF not configured (action item) |

6. **Action Items**
   
   | # | Action Item | Owner | Due Date | Priority |
   |---|-------------|-------|----------|----------|
   | 1 | Deploy cloud WAF (AWS WAF or Cloudflare) with managed DDoS rules | Infrastructure | 2026-02-21 | P0 |
   | 2 | Implement adaptive CAPTCHA (lower false positive rate) | Security | 2026-02-28 | P1 |
   | 3 | Increase HPA maxReplicas to 50 (current: 20) for better DDoS resilience | DevOps | 2026-02-17 | P1 |
   | 4 | Subscribe to threat intelligence feed for botnet IP lists | Security | 2026-02-28 | P1 |
   | 5 | Implement connection rate limiting (in addition to request rate limiting) | Infrastructure | 2026-03-07 | P1 |
   | 6 | Deploy CDN for static assets (reduce origin server load) | Infrastructure | 2026-03-15 | P2 |
   | 7 | Contract with DDoS mitigation service (e.g., Cloudflare, Akamai) | Procurement | 2026-03-31 | P2 |
   | 8 | Conduct DDoS tabletop exercise simulating 10x larger attack | Security | 2026-04-15 | P2 |

7. **Lessons Learned**
   
   **What Went Well** ✅:
   - Automated alerting detected attack within 2 minutes
   - Kubernetes HPA scaled infrastructure automatically
   - IP blocking reduced attack traffic by 94%
   - Clear escalation path ensured rapid response
   
   **What Needs Improvement** ⚠️:
   - No cloud WAF deployed (manual IP blocking insufficient for large-scale DDoS)
   - CAPTCHA caused false positives (12% legitimate users challenged)
   - Attack still caused 45 minutes of downtime
   - No pre-arranged DDoS mitigation service contract
   
   **Preventive Measures** 🛡️:
   - Deploy multi-layer DDoS protection (cloud WAF + CDN + rate limiting)
   - Implement adaptive CAPTCHA (behavioral analysis, not just request rate)
   - Contract with DDoS mitigation specialist (Cloudflare, Akamai, AWS Shield Advanced)
   - Increase infrastructure over-provisioning (higher HPA maxReplicas)

---

## Appendix

### A. Rate Limiting Configuration Examples

```yaml
# configs/templates/gateway.hardened.yml
rate_limits:
  # Normal mode (default)
  normal:
    per_ip_per_minute: 100
    per_user_per_minute: 500
    global_per_second: 2000
    burst: 150
  
  # Aggressive mode (DDoS response)
  aggressive:
    per_ip_per_minute: 10
    per_user_per_minute: 20
    global_per_second: 500
    burst: 5
    captcha_enabled: true
    captcha_threshold: 5
  
  # Endpoint-specific overrides
  endpoints:
    - path: "/api/v1/conversations"
      per_ip_per_minute: 30
      per_user_per_minute: 100
    
    - path: "/api/v1/admin/*"
      per_ip_per_minute: 10
      per_user_per_minute: 20
      require_authentication: true
```

### B. DDoS Mitigation Service Comparison

| Service | Type | Cost | Throughput | Features |
|---------|------|------|------------|----------|
| **AWS Shield Standard** | Included | Free | Automatic | Layer 3/4 protection, basic |
| **AWS Shield Advanced** | Managed | $3,000/month | Unlimited | Layer 3/4/7, DDoS Response Team, cost protection |
| **Cloudflare Pro** | CDN + WAF | $20/month | Unlimited | Layer 7 protection, "Under Attack Mode" |
| **Cloudflare Enterprise** | Managed | Custom | Unlimited | Layer 3/4/7, 24/7 support, custom rules |
| **Akamai Prolexic** | Scrubbing center | Custom | Multi-Tbps | Layer 3/4/7, global scrubbing, always-on |

### C. SYN Flood Mitigation (Linux)

```bash
# Enable SYN cookies (protects against SYN floods)
sysctl -w net.ipv4.tcp_syncookies=1

# Reduce SYN-RECEIVED timeout
sysctl -w net.ipv4.tcp_synack_retries=2

# Increase SYN backlog
sysctl -w net.ipv4.tcp_max_syn_backlog=4096

# Persist settings
cat >> /etc/sysctl.conf <<EOF
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_max_syn_backlog=4096
EOF
```

### D. Related Playbooks

- **[playbook-prompt-injection.md](playbook-prompt-injection.md)** - If DoS caused by malicious prompt
- **[Scenario 007: Resource Exhaustion](../scenarios/scenario-007-denial-of-service-resource-exhaustion.md)** - Detailed attack scenario

---

### E. Useful Commands Reference

```bash
# Check current connection count
ss -s

# Monitor real-time connections
watch -n 1 'ss -s'

# Identify top talkers
netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20

# Block IP via iptables
iptables -A INPUT -s 203.0.113.42 -j DROP

# List all blocked IPs
iptables -L INPUT -v -n | grep DROP

# Clear all iptables rules (CAUTION)
iptables -F INPUT

# Check if under SYN flood
netstat -an | grep SYN_RECV | wc -l
```

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-14 | Infrastructure Team | Initial playbook creation |
| 1.1 | 2026-02-14 | Security Team | Added application-layer attack procedures |

**Approval**:
- **CISO**: ✅ Approved 2026-02-14
- **VP Infrastructure**: ✅ Technical review 2026-02-14

**Next Review**: 2026-05-14 (quarterly review)
