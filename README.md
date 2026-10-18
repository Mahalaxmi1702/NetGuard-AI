# NetGuard AI — Simulator + Live Capture

## Windows setup
1. Install Python 3.12 or 3.13.
2. Install Npcap from https://npcap.com/#download. Use the default options unless your institution's IT policy says otherwise.
3. Extract this folder and open it in VS Code.
4. In the VS Code terminal run:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\python.exe -m pip install --upgrade pip
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe -m streamlit run app.py
   ```
5. Open http://localhost:8501. Choose `Simulated Demo` or `Live Packet Capture` in the sidebar.

## Live capture notes
- Choose the active Wi-Fi/Ethernet interface.
- Capture lasts only 5–20 seconds per click. Generate ordinary traffic during that time, such as loading a webpage.
- On Windows, Scapy generally requires Npcap; depending on the setup, opening the terminal as Administrator may be required.
- Only capture traffic on a device/network you own or are authorized to monitor. This project reads packet metadata and does not intentionally store payloads.
- The app observes only packets visible to that interface. It does not scan other devices or prove an attack.
- The Isolation Forest is trained on synthetic data and must not be presented as validated real-world detection accuracy.
