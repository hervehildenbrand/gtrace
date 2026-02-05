# gtrace Demo - Full 75-second showcase
# Records animated terminal demo for GitHub README (GIF) and LinkedIn (MP4)
#
# Usage:
#   vhs demo/gtrace-demo.tape
#
# Prerequisites:
#   - gtrace built and in PATH (or use go run)
#   - sudo access for local traces (ICMP raw sockets)
#   - GlobalPing API access (optional API key for higher rate limits)

Output demo/gtrace-demo.gif
Output demo/gtrace-demo.mp4

Require gtrace

# -- Terminal appearance --
Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 18
Set Width 1400
Set Height 800
Set Padding 20
Set Margin 20
Set MarginFill "#1a1a2e"
Set BorderRadius 8
Set WindowBar "Colorful"
Set WindowBarSize 40
Set Theme "Catppuccin Mocha"

# -- Timing --
Set TypingSpeed 50ms
Set Framerate 30
Set PlaybackSpeed 1.0
Set WaitTimeout 60s

# ============================================================
# Scene 1: Title Card (4s)
# ============================================================

Type "# gtrace - Network Path Analysis Beyond traceroute"
Sleep 500ms
Enter
Sleep 3s
Type "clear"
Enter
Sleep 500ms

# ============================================================
# Scene 2: MTR Mode - Local Trace (20s)
# Real-time TUI with ASN enrichment, RTT sparklines, shortcuts
# ============================================================

Type "sudo gtrace cloudflare.com"
Sleep 500ms
Enter
Sleep 12s

# Toggle display mode: DNS -> IP
Type "n"
Sleep 3s

# Toggle display mode: IP -> Both
Type "n"
Sleep 3s

# Quit MTR
Type "q"
Sleep 1s

# ============================================================
# Scene 3: Simple Trace with MPLS Detection (12s)
# Text output mode showing MPLS labels on backbone networks
# ============================================================

Type "# Detect MPLS labels on backbone networks"
Sleep 300ms
Enter
Sleep 500ms
Type "sudo gtrace www.internet2.edu --simple --max-hops 15"
Sleep 500ms
Enter
Sleep 10s

# ============================================================
# Scene 4: GlobalPing Multi-Source Trace (20s)
# Remote tracing from 500+ global probe locations, no sudo
# ============================================================

Type "# Trace from 500+ global probe locations"
Sleep 300ms
Enter
Sleep 500ms
Type "gtrace cloudflare.com --from 'Tokyo,London,Sao Paulo'"
Sleep 500ms
Enter
Sleep 18s

# ============================================================
# Scene 5: Compare Mode - Local vs Remote (15s)
# Side-by-side comparison of your path vs the world
# ============================================================

Type "# Compare your path vs the world"
Sleep 300ms
Enter
Sleep 500ms
Type "sudo gtrace 8.8.8.8 --compare --from 'New York'"
Sleep 500ms
Enter
Sleep 13s

# ============================================================
# Scene 6: Closing (4s)
# ============================================================

Type "clear"
Enter
Sleep 500ms
Type "# github.com/hervehildenbrand/gtrace"
Sleep 300ms
Enter
Sleep 4s
