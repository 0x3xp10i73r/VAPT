# Capturing the cleartext traffic in Wireshark

Goal: a `.pcap` that shows `Authorization: Bearer <canary>` travelling in plain
HTTP, with no TLS anywhere in the stream. Two commands, then a display filter.

---

## Fast path

```bash
cd ~/VAPT

# 1. start the capture in one terminal (port pinned, so the filter is trivial)
sudo tcpdump -i lo -s0 -U -w /tmp/plaintext.pcap 'tcp port 8899'

# 2. in another terminal, run the PoC against that exact port
env -u PYTHONHOME -u PYTHONPATH python3 poc/17-check-plaintext.py \
    --host 127.0.0.1 --port 8899

# 3. stop the capture with Ctrl-C, then open it
wireshark /tmp/plaintext.pcap
```

Or let the wrapper do all three:

```bash
./poc/capture-plaintext.sh                       # loopback, port 8899
./poc/capture-plaintext.sh --port 9999            # different port
./poc/capture-plaintext.sh --out ~/plain.pcap     # keep the file elsewhere
```

It asks for sudo once, starts `tcpdump`, drives the PoC, stops the capture, and
if `tshark` is installed it prints the decoded requests and proves the
`Authorization` header is extractable from the file.

---

## WSL: where to capture

WSL2 runs its own kernel and network namespace. **Wireshark running on Windows
cannot see WSL's `lo` interface** — the loopback traffic never leaves the VM. Two
workable setups:

### A. Capture inside WSL, view anywhere (recommended)

```bash
sudo apt install -y tcpdump
# ... capture as above ...
# copy the file somewhere Windows can open it
cp /tmp/plaintext.pcap /mnt/c/Users/<you>/Desktop/
```

Then open it with the Windows Wireshark — `.pcap` is portable, dissection is
identical.

### B. Run Wireshark inside WSL

On Windows 11 with WSLg, GUI apps work:

```bash
sudo apt install -y wireshark
sudo wireshark        # root is needed to open a capture interface
```

Wireshark will offer `lo`, `eth0` and `any`. For `--host 127.0.0.1`, pick **`lo`**.

### Which interface?

| PoC endpoint | Interface inside WSL | Notes |
|---|---|---|
| `--host 127.0.0.1` (default when no outward address) | `lo` | simplest; what the fast path uses |
| `--host <WSL eth0 address>` e.g. `172.20.10.2` | `eth0` | traffic is real Ethernet, not loopback |
| `--host` omitted, WSL has a private address | that address | the script prints `endpoint:` — match it |
| `any` | `any` | works, but frames are Linux-cooked (SLL), which some filters dislike |

If you capture from **Windows** instead, you can only see traffic that crosses
the WSL vNIC — i.e. the `eth0` case, on the `vEthernet (WSL)` interface. Loopback
traffic is invisible from there. That is why option A is recommended.

---

## The one gotcha: Decode As → HTTP

Wireshark auto-detects HTTP only on well-known ports (80, 8080, 8000, 3128…).
On port 8899 the traffic decodes as raw TCP with the comment *"TCP segment of a
reassembled PDU"*. Fix it once:

1. Click any packet in the stream.
2. **Right-click → Decode As…**
3. In the list, find the row for TCP port **8899**, set its value to **HTTP**.
4. OK. Every packet in that conversation now dissects as HTTP.

Equivalent for the command line:

```bash
tshark -r /tmp/plaintext.pcap -d tcp.port==8899,http -Y http.request
```

---

## Filters that show the finding

| Filter | What you should see |
|---|---|
| `tcp.port == 8899` | the whole conversation |
| `http.request` | 5 × `POST /v1/chat/completions HTTP/1.1` |
| `http.authorization` | the header, value `Bearer CANARY_PLAINTEXT_9f31c2` |
| `http contains "CANARY_PLAINTEXT"` | every frame carrying the token |
| `tls.handshake` | **zero packets** — this is the proof there is no TLS |
| `tcp.flags.syn == 1` | the connection setup, if you want to show the handshake is plain TCP |

### Reading the credential in the GUI

1. Filter `http.request`.
2. Right-click one packet → **Follow → HTTP Stream**.
3. The top pane is the raw request. `Authorization: Bearer CANARY_PLAINTEXT_9f31c2`
   is there in clear text, alongside the JSON body — no key, no decryption, no
   SSLKEYLOGFILE.

### Headless proof (no GUI)

```bash
# which requests, and who they went to
tshark -r /tmp/plaintext.pcap -d tcp.port==8899,http -Y http.request \
       -T fields -e frame.number -e ip.dst -e http.request.method \
       -e http.request.uri -e http.authorization

# the credential, counted
tshark -r /tmp/plaintext.pcap -d tcp.port==8899,http \
       -Y 'http.authorization contains "Bearer"' \
       -T fields -e http.authorization | sort | uniq -c

# no TLS in the capture at all
tshark -r /tmp/plaintext.pcap -Y tls.handshake | wc -l        # 0

# the full request as text, for pasting into a report
tshark -r /tmp/plaintext.pcap -d tcp.port==8899,http \
       -Y 'http.request' -T fields -e http.request.full_uri -e http.user_agent
```

---

## Save it as evidence

- **GUI:** File → Export Specified Packets… → *All packets* → save as `.pcapng`.
  Or File → Export As → Plain Text for a readable packet list.
- **Screenshot:** the Follow HTTP Stream window with the `Authorization` line
  visible is the clearest single image for a report.
- **Keep the filter applied** when you screenshot, so the reader can reproduce it.

The token in this capture is the **canary** `CANARY_PLAINTEXT_9f31c2`, not a real
credential — that is why the file can be attached to a report. If you change the
config to a real key, redact the `Authorization:` line before sharing.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `tcpdump: eth0: You don't have permission to capture` | not root | `sudo tcpdump …` |
| Capture file is 0 bytes | wrong interface, or the PoC used a different port | pin `--port` and capture on `lo` for `127.0.0.1` |
| Packets present but no HTTP | non-standard port | Decode As → HTTP (see above) |
| Only SYN/ACK and RST | the listener was not running when the tool connected | start `tcpdump` first, then the PoC |
| Traffic to `169.254.x.x` instead of `127.0.0.1` | the script chose the host's outward address | pass `--host 127.0.0.1` |
| Nothing at all in WSL, capturing from Windows | loopback is inside the VM | capture inside WSL (option A) |
| `Follow HTTP Stream` shows compressed bodies | request had `Accept-Encoding` | request bodies here are uncompressed; only responses may differ |
| Windows Wireshark says "no interfaces" | Npcap missing / not installed with admin | install Npcap with "WinPcap API-compatible mode" |

---

## Why this capture is legitimate evidence

- The endpoint is one you control, on your own machine; nothing is intercepted
  from a third party.
- The credential is a canary you generated; no real secret is captured.
- The absence of TLS is demonstrable at packet level (`tls.handshake` → 0), not
  inferred from configuration.
- The request bodies are `--check-llm` probes (`"Hello"`), so the capture shows
  the *transport* defect without embedding scanned source code. For a capture
  that carries real source, seed the tokenizer cache on a host with egress (F-05)
  and run a full scan against the same endpoint — expect the bodies to grow to
  the size of the files being scanned.
