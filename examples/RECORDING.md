# Recording the demo as a video

`examples/demo.sh` is a paced walkthrough made for recording. It runs the real
reproduction (nat REDIRECT + SO_ORIGINAL_DST) on loopback and needs root.

## Option A — terminal recording (cleanest, smallest file)

On the Linux box / VM where c2sink runs:

```sh
pip install asciinema
cd c2sink
sudo asciinema rec demo.cast --overwrite --cols 100 --rows 32 -c "bash examples/demo.sh"
```

Share it as:
- **a link**: `asciinema upload demo.cast` → paste the URL (Rodrigo presses play in the browser), or
- **a GIF**: `agg --theme monokai --font-size 16 demo.cast demo.gif`
  (install agg from https://github.com/asciinema/agg), or
- **an MP4** (best for LinkedIn/WhatsApp): `ffmpeg -i demo.gif -movflags +faststart -pix_fmt yuv420p demo.mp4`

A ready-made `demo.cast` and `demo.mp4` from one real run are already in this
folder, so you can send those directly or re-record your own.

## Option B — screen recorder (if you want your face/voice or a real desktop)

- **Linux**: OBS Studio, or `ffmpeg -f x11grab -framerate 30 -i :0.0 -c:v libx264 demo.mp4`
- **macOS**: QuickTime Player → File → New Screen Recording (or Cmd-Shift-5)
- **Windows**: Xbox Game Bar (Win-G), or OBS

Make the terminal large, run `bash examples/demo.sh`, stop when it prints the
closing line. Trim the start/end in any editor.

## What the video shows (≈30 s)

1. the feed (3 blackholed C2s with labels)
2. the sink starting
3. the blackhole prefixes being pointed at the sink (one iptables line)
4. three infected subscribers beaconing — each gets 0 bytes back
5. the subscriber report (who is infected, what they are)
6. the feed-health report (which C2s are live, false-positive signal)

Keep it under a minute; let the two reports sit on screen long enough to read.
