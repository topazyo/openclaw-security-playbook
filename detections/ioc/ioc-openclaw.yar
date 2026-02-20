/*
 * YARA Rules — OpenClaw / Moltbot / Clawdbot Security
 * Part of: https://github.com/topazyo/openclaw-security-playbook
 * Part 3: Detecting OpenClaw Compromise
 *
 * Usage:
 *   yara -r ioc-openclaw.yar /path/to/scan
 *   yara -r ioc-openclaw.yar --scan-timeout=60 /
 *
 * Rules target:
 *   1. Infostealer samples adapted to target OpenClaw credential paths
 *   2. Malicious skills containing dangerous patterns
 *   3. SOUL.md files containing injected persistence instructions
 */

rule OpenClaw_Credential_Path_Enumeration
{
    meta:
        description = "Detects processes enumerating OpenClaw/Moltbot/Clawdbot backup credential paths"
        author      = "openclaw-security-playbook"
        date        = "2026-02-18"
        reference   = "Hudson Rock infostealer telemetry, Jan 31 2026"
        severity    = "HIGH"

    strings:
        $path_moltbot_bak   = "/.moltbot/moltbot.json.bak"   ascii wide
        $path_clawdbot_bak  = "/.clawdbot/clawdbot.json.bak"  ascii wide
        $path_openclaw_bak  = "/.openclaw/"                    ascii wide
        $path_moltbot_json  = "/.moltbot/moltbot.json"         ascii wide
        $path_clawdbot_json = "/.clawdbot/clawdbot.json"       ascii wide

    condition:
        any of ($path_moltbot_bak, $path_clawdbot_bak) or
        (2 of ($path_moltbot_json, $path_clawdbot_json, $path_openclaw_bak))
}

rule OpenClaw_Skill_Dangerous_Patterns
{
    meta:
        description = "Detects skill files containing dangerous execution patterns"
        author      = "openclaw-security-playbook"
        date        = "2026-02-18"
        reference   = "OX Security: 26% of skill plugins contain vulnerabilities"
        severity    = "MEDIUM"
        file_types  = "skill .md files in ~/.openclaw/skills/, ~/.moltbot/skills/"

    strings:
        $eval        = "eval("         ascii
        $inner_html  = "innerHTML"     ascii
        $exec_call   = "exec("         ascii
        $child_proc  = "child_process" ascii
        $base64_exec = /[A-Za-z0-9+\/]{40,}={0,2}/ ascii
        $fetch_ext   = /https?:\/\/(?!openclaw\.ai|molt\.bot|clawd\.bot|anthropic\.com|openai\.com)/ ascii

    condition:
        (any of ($eval, $inner_html, $exec_call, $child_proc)) and $fetch_ext
}

rule OpenClaw_SOUL_Injection_Persistence
{
    meta:
        description = "Detects SOUL.md files containing potential injected persistence instructions"
        author      = "openclaw-security-playbook"
        date        = "2026-02-18"
        reference   = "ATLAS T-PERSIST-005: Memory Poisoning via Prompt Injection"
        severity    = "HIGH"
        file_types  = "SOUL.md"

    strings:
        $override1  = "IGNORE PREVIOUS"              ascii nocase
        $override2  = "SYSTEM OVERRIDE"              ascii nocase
        $override3  = "ignore previous instructions" ascii nocase
        $override4  = "disregard all prior"          ascii nocase
        $schedule1  = "every time you start"         ascii nocase
        $schedule2  = "on each session"              ascii nocase
        $schedule3  = "always run first"             ascii nocase
        $exfil1     = /send.*to.*@/                  ascii
        $exfil2     = "pastebin.com"                 ascii
        $exfil3     = "webhook.site"                 ascii
        $b64        = /[A-Za-z0-9+\/]{60,}={0,2}/  ascii

    condition:
        any of ($override1, $override2, $override3, $override4) or
        (any of ($schedule1, $schedule2, $schedule3) and any of ($exfil1, $exfil2, $exfil3)) or
        $b64
}

rule OpenClaw_Gateway_Exposed_Config
{
    meta:
        description = "Detects OpenClaw config with gateway bound to all interfaces"
        author      = "openclaw-security-playbook"
        date        = "2026-02-18"
        reference   = "BrandDefense: 1,200+ exposed instances on port 18789"
        severity    = "CRITICAL"
        file_types  = "config.yml"

    strings:
        $bind_all1   = "address: \"0.0.0.0\""  ascii
        $bind_all2   = "address: '0.0.0.0'"    ascii
        $bind_all3   = "bind: 0.0.0.0"           ascii
        $port        = "18789"                    ascii
        $autoapprove = "autoApprove: true"        ascii

    condition:
        $port and (any of ($bind_all1, $bind_all2, $bind_all3) or $autoapprove)
}
