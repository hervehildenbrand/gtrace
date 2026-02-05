# gtrace Teaser - Short 30-second clip
# Quick showcase of MTR mode + GlobalPing for social media
#
# Usage:
#   vhs demo/gtrace-teaser.tape

Output demo/gtrace-teaser.gif
Output demo/gtrace-teaser.mp4

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
# Scene 1: MTR Mode - Quick Look (12s)
# ============================================================

Type "sudo gtrace cloudflare.com"
Sleep 500ms
Enter
Sleep 10s
Type "q"
Sleep 1s

# ============================================================
# Scene 2: GlobalPing - Remote Trace (12s)
# ============================================================

Type "gtrace cloudflare.com --from 'Tokyo,London'"
Sleep 500ms
Enter
Sleep 11s

# ============================================================
# Scene 3: Closing (5s)
# ============================================================

Type "clear"
Enter
Sleep 500ms
Type "# github.com/hervehildenbrand/gtrace"
Sleep 300ms
Enter
Sleep 4s
