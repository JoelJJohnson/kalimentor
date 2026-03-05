# Hooks System

Hooks let you fire shell commands automatically in response to agent events — notifications, logging, integrations, custom automation.

---

## Configuration

Place hooks in `~/.kalimentor/hooks.yaml`:

```yaml
hooks:
  - name: notify_on_flag
    event: on_flag
    run: notify-send "KaliMentor" "Flag captured: $TOOL_OUTPUT"

  - name: log_shell_commands
    event: post_tool
    match: bash
    run: echo "[$SESSION_ID] $TOOL_INPUT" >> ~/kalimentor-audit.log

  - name: alert_on_finding
    event: on_finding
    run: curl -s -X POST "$SLACK_WEBHOOK" -d "{\"text\":\"Finding: $TOOL_OUTPUT\"}"
```

See `config/hooks.example.yaml` for more examples.

---

## Hook Points

| Event | Fires when |
|-------|-----------|
| `pre_tool` | Before any tool executes |
| `post_tool` | After any tool completes |
| `pre_session` | Session starts |
| `post_session` | Session ends (quit or exit) |
| `on_finding` | `record_finding` tool is called |
| `on_shell` | A shell (reverse shell / bind shell) is detected in bash output |
| `on_flag` | `/flag` command is used |

---

## Environment Variables

These are available in every hook's `run` command:

| Variable | Value |
|----------|-------|
| `$TARGET` | Session target IP/URL |
| `$SESSION_ID` | Current session ID |
| `$TOOL_NAME` | Name of the tool that fired |
| `$TOOL_INPUT` | JSON-encoded tool input |
| `$TOOL_OUTPUT` | Tool output (truncated to 2000 chars) |
| `$PHASE` | Current engagement phase |
| `$CHALLENGE` | Challenge type (machine, web, defend, …) |

---

## Match Filter

The `match` field is an optional regex applied to `$TOOL_NAME`. If provided, the hook only fires when the tool name matches:

```yaml
hooks:
  # Only fires for bash tool
  - name: audit_bash
    event: post_tool
    match: bash
    run: echo "$TOOL_INPUT" >> ~/bash-audit.log

  # Fires for any file tool (read_file, write_file, list_directory)
  - name: log_file_ops
    event: post_tool
    match: ".*file.*"
    run: echo "File op: $TOOL_NAME" >> ~/file-ops.log
```

---

## Examples

### Desktop Notifications (Linux)

```yaml
hooks:
  - name: notify_flag
    event: on_flag
    run: notify-send "🚩 Flag!" "$TOOL_OUTPUT"

  - name: notify_finding
    event: on_finding
    run: notify-send "🔍 Finding" "$TOOL_OUTPUT"
```

### Slack Integration

```yaml
hooks:
  - name: slack_flag
    event: on_flag
    run: |
      curl -s -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-type: application/json' \
        --data "{\"text\":\"🚩 Flag captured on $TARGET: $TOOL_OUTPUT\"}"
```

### Audit Logging

```yaml
hooks:
  - name: full_audit
    event: post_tool
    run: |
      echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [$SESSION_ID] $TOOL_NAME: $TOOL_INPUT" \
        >> ~/.kalimentor/audit.log
```

### Auto-Screenshot on Shell

```yaml
hooks:
  - name: screenshot_shell
    event: on_shell
    run: scrot ~/screenshots/shell-$SESSION_ID-$(date +%s).png
```

### Burp Suite Integration (start proxy before web sessions)

```yaml
hooks:
  - name: start_burp
    event: pre_session
    match: ".*"
    run: |
      if [ "$CHALLENGE" = "web" ]; then
        burpsuite &
      fi
```

---

## Hook Execution

- Hooks run as background shell processes — they don't block the agent loop
- Failed hooks are logged to `~/.kalimentor/hook-errors.log` but don't interrupt the session
- Hooks inherit the shell environment where kalimentor was launched
- Add custom env vars to `~/.kalimentor/.env`
