# Re-record with VHS when ffmpeg and ttyd are installed:
#   vhs docs/demo.tape
Output docs/demo.gif

Set Shell "bash"
Set FontSize 22
Set Width 1100
Set Height 420
Set Padding 24
Set Theme "Catppuccin Mocha"

Type "uv run python -m examples.quickstart"
Enter
Sleep 45s
