import time
from datetime import datetime
from collections import Counter
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
from sklearn.ensemble import IsolationForest

st.set_page_config(page_title="NetGuard AI", page_icon="🛡️", layout="wide")

FEATURES = [
    "pps", "bps", "avg_size", "unique_src", "unique_ports",
    "tcp_pct", "udp_pct", "icmp_pct", "conns_per_ip", "burst_delta"
]


def make_baseline(n=500, seed=7):
    rng = np.random.default_rng(seed)
    pps = rng.normal(45, 12, n).clip(5, 100)
    avg_size = rng.normal(650, 130, n).clip(100, 1400)
    unique_src = rng.poisson(2, n).clip(1, 8)
    unique_ports = rng.poisson(4, n).clip(1, 12)
    tcp = rng.normal(0.72, 0.10, n).clip(0.35, 0.95)
    udp = rng.normal(0.23, 0.08, n).clip(0.02, 0.55)
    icmp = (1 - tcp - udp).clip(0.0, 0.25)
    total = tcp + udp + icmp
    tcp, udp, icmp = tcp / total, udp / total, icmp / total
    return pd.DataFrame({
        "pps": pps, "bps": pps * avg_size, "avg_size": avg_size,
        "unique_src": unique_src, "unique_ports": unique_ports,
        "tcp_pct": tcp, "udp_pct": udp, "icmp_pct": icmp,
        "conns_per_ip": (pps / unique_src).clip(1, 150),
        "burst_delta": rng.normal(0, 0.18, n).clip(-0.5, 0.8),
    })[FEATURES]


def create_model():
    model = IsolationForest(n_estimators=150, contamination=0.06, random_state=42)
    model.fit(make_baseline()[FEATURES])
    return model


def sample_window(kind):
    rng = np.random.default_rng()
    pps = float(np.clip(rng.normal(48, 10), 10, 90))
    avg_size = float(np.clip(rng.normal(650, 100), 200, 1200))
    src = int(rng.integers(1, 4))
    ports = int(rng.integers(2, 8))
    tcp, udp, icmp = 0.72, 0.23, 0.05
    burst = float(rng.normal(0.03, 0.08))
    cause = "Traffic within expected range"
    severity = "LOW"
    advice = "Continue monitoring"
    if kind == "Port scan":
        pps, src, ports, burst = float(rng.integers(90, 180)), 1, int(rng.integers(25, 65)), 1.8
        cause, severity, advice = "Many destination ports from one source (simulated)", "MEDIUM", "Review firewall rules and source activity"
    elif kind == "Traffic flood":
        pps, src, ports, avg_size, burst = float(rng.integers(250, 600)), 1, int(rng.integers(1, 5)), float(rng.integers(500, 1100)), 3.2
        cause, severity, advice = "Sudden packet-rate spike (simulated)", "HIGH", "Validate the source and consider rate-limiting under your network policy"
    elif kind == "Data spike":
        pps, avg_size, burst = float(rng.integers(35, 80)), float(rng.integers(1250, 1450)), 1.4
        cause, severity, advice = "Bytes per second increased unusually (simulated)", "MEDIUM", "Check whether a large transfer or backup is expected"
    elif kind == "Protocol shift":
        tcp, udp, icmp = 0.12, 0.13, 0.75
        pps, burst = float(rng.integers(80, 160)), 1.1
        cause, severity, advice = "Unusual ICMP/protocol mix (simulated)", "HIGH", "Inspect the source and validate whether this protocol mix is expected"
    features = {
        "pps": pps, "bps": pps * avg_size, "avg_size": avg_size,
        "unique_src": src, "unique_ports": ports,
        "tcp_pct": tcp, "udp_pct": udp, "icmp_pct": icmp,
        "conns_per_ip": pps / max(src, 1), "burst_delta": burst,
    }
    return features, cause, severity, advice


def capture_live_window(iface, duration_seconds):
    """Passively capture packet metadata only; do not retain or inspect payloads."""
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP

    packets_meta = []
    per_second = Counter()
    started = time.time()

    def on_packet(pkt):
        now = time.time()
        src = dst = None
        proto = "OTHER"
        dport = None
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        if TCP in pkt:
            proto, dport = "TCP", int(pkt[TCP].dport)
        elif UDP in pkt:
            proto, dport = "UDP", int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"
        packets_meta.append({
            "timestamp": now,
            "src": src,
            "dst": dst,
            "proto": proto,
            "dport": dport,
            "size": int(len(pkt)),
        })
        per_second[int(now - started)] += 1

    sniff(iface=iface, timeout=int(duration_seconds), store=False, prn=on_packet)
    elapsed = max(time.time() - started, 1.0)
    if not packets_meta:
        return None, 0

    df = pd.DataFrame(packets_meta)
    total = len(df)
    tcp_n = int((df["proto"] == "TCP").sum())
    udp_n = int((df["proto"] == "UDP").sum())
    icmp_n = int((df["proto"] == "ICMP").sum())
    unique_src = max(int(df["src"].dropna().nunique()), 1)
    unique_ports = int(df.loc[df["dport"].notna(), "dport"].nunique())
    pps = total / elapsed
    avg_size = float(df["size"].mean())
    rates = [per_second.get(i, 0) for i in range(max(1, int(np.ceil(elapsed))))]
    burst_delta = float((max(rates) - np.mean(rates)) / max(np.mean(rates), 1)) if rates else 0.0
    features = {
        "pps": float(pps),
        "bps": float(df["size"].sum() / elapsed),
        "avg_size": avg_size,
        "unique_src": unique_src,
        "unique_ports": unique_ports,
        "tcp_pct": tcp_n / total,
        "udp_pct": udp_n / total,
        "icmp_pct": icmp_n / total,
        "conns_per_ip": float(pps / unique_src),
        "burst_delta": burst_delta,
    }
    return features, total


def diagnose_live(f):
    # Conservative heuristics for a classroom prototype, not proof of an attack.
    if f["unique_ports"] >= 20:
        return "Possible port-scan-like activity: many destination ports observed", "MEDIUM", "Review the source and destination-port pattern; validate against expected applications"
    if f["pps"] >= 200:
        return "High packet rate observed; possible traffic-flood pattern", "HIGH", "Check whether this traffic is expected; inspect router/firewall telemetry"
    if f["icmp_pct"] >= 0.40 and f["pps"] >= 20:
        return "Unusually high ICMP share in this capture window", "MEDIUM", "Check whether diagnostic traffic is expected"
    if f["bps"] >= 150000 and f["avg_size"] >= 1000:
        return "High byte rate with large packets", "LOW", "Check whether a download, stream, or backup explains the traffic"
    return "No configured heuristic triggered in this capture window", "LOW", "This short window alone cannot establish that the network is safe"


if "model" not in st.session_state:
    st.session_state.model = create_model()
if "events" not in st.session_state:
    st.session_state.events = []
if "started" not in st.session_state:
    st.session_state.started = False

st.markdown("""
<style>
.block-container {padding-top: 1.5rem;}
div[data-testid="stMetric"] {background: #111827; border: 1px solid #273449; padding: 14px; border-radius: 12px;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ NetGuard AI")
st.caption("Intelligent Network Traffic Anomaly Detection & Diagnosis · Local prototype")
mode = st.sidebar.radio("Operating mode", ["Simulated Demo", "Live Packet Capture"], help="Live capture passively observes packets visible to an interface on this computer.")

if mode == "Simulated Demo":
    st.info("Demo mode uses locally generated traffic windows. Alerts are hypotheses, not proof of an attack.")
else:
    st.warning("Live capture observes metadata from packets visible to your selected interface. It does not scan other devices or prove an attack. Use only on a device/network you are authorized to monitor.")

with st.sidebar:
    st.header("Control panel")
    if mode == "Simulated Demo":
        st.write("Generate safe, controlled traffic scenarios.")
        if st.button("▶ Start monitoring", use_container_width=True):
            st.session_state.started = True
        if st.button("⏹ Stop monitoring", use_container_width=True):
            st.session_state.started = False
        st.divider()
        st.subheader("Generate event")
        event_kind = st.selectbox("Traffic scenario", ["Normal traffic", "Port scan", "Traffic flood", "Data spike", "Protocol shift"])
        if st.button("＋ Generate traffic window", type="primary", use_container_width=True):
            if not st.session_state.started:
                st.session_state.started = True
            f, cause, severity, advice = sample_window(event_kind)
            score = float(st.session_state.model.decision_function(pd.DataFrame([f])[FEATURES])[0])
            prediction = int(st.session_state.model.predict(pd.DataFrame([f])[FEATURES])[0])
            is_suspicious = prediction == -1 or event_kind != "Normal traffic"
            row = dict(f)
            row.update({
                "time": datetime.now().strftime("%H:%M:%S"), "scenario": f"Simulated: {event_kind}",
                "ml_score": round(score, 3), "ml_result": "Anomaly" if prediction == -1 else "Normal",
                "status": "Anomaly" if is_suspicious else "Normal",
                "severity": severity if is_suspicious else "LOW",
                "cause": cause if is_suspicious else "Traffic within expected range (simulated)",
                "advice": advice if is_suspicious else "Continue monitoring the simulated samples",
            })
            st.session_state.events.append(row)
    else:
        st.write("Passively capture a short window of traffic from this computer.")
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
        except Exception as exc:
            interfaces = []
            st.error("Scapy could not list interfaces. Check installation and Npcap. Details: " + str(exc))
        if interfaces:
            iface = st.selectbox("Network interface", interfaces, help="Choose the interface currently carrying the traffic you want to observe.")
            duration = st.select_slider("Capture duration (seconds)", options=[5, 10, 15, 20], value=10)
            if st.button("▶ Capture live window", type="primary", use_container_width=True):
                try:
                    with st.spinner(f"Capturing packet metadata for {duration} seconds…"):
                        f, packet_count = capture_live_window(iface, duration)
                    if f is None:
                        st.warning("No packets were observed in this window. Try the active interface, generate ordinary activity (e.g. load a page), and capture again.")
                    else:
                        cause, severity, advice = diagnose_live(f)
                        score = float(st.session_state.model.decision_function(pd.DataFrame([f])[FEATURES])[0])
                        prediction = int(st.session_state.model.predict(pd.DataFrame([f])[FEATURES])[0])
                        is_suspicious = severity != "LOW"
                        row = dict(f)
                        row.update({
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "scenario": f"Live capture ({iface}; {packet_count} packets)",
                            "ml_score": round(score, 3),
                            "ml_result": "Anomaly" if prediction == -1 else "Normal",
                            "status": "Anomaly" if is_suspicious else "Normal",
                            "severity": severity, "cause": cause, "advice": advice,
                            "packet_count": packet_count, "interface": iface,
                        })
                        st.session_state.events.append(row)
                        st.success(f"Captured metadata for {packet_count} packets over approximately {duration} seconds.")
                except PermissionError:
                    st.error("Permission denied. On Windows, install Npcap and reopen VS Code as Administrator if required by your setup.")
                except Exception as exc:
                    st.error("Live capture failed. Confirm Npcap is installed, choose the active interface, and check permissions. Details: " + str(exc))
        else:
            st.info("No interfaces were returned by Scapy. Install Scapy and Npcap, then restart the app.")
        st.caption("For best results, select your active Wi-Fi/Ethernet interface and create normal traffic during the capture window. Capture is time-limited and does not intentionally save packet payloads.")

    if st.button("Clear event history", use_container_width=True):
        st.session_state.events = []

events = pd.DataFrame(st.session_state.events)
if events.empty:
    events = pd.DataFrame(columns=FEATURES + ["time", "scenario", "ml_score", "ml_result", "status", "severity", "cause", "advice"])

total = len(events)
anomalies = int((events["status"] == "Anomaly").sum()) if total else 0
latest = events.iloc[-1] if total else None
pps_now = float(events.iloc[-1]["pps"]) if total else 0
bps_now = float(events.iloc[-1]["bps"]) if total else 0

m1, m2, m3, m4 = st.columns(4)
m1.metric("Windows observed", total)
m2.metric("Anomaly alerts", anomalies)
m3.metric("Latest packets/sec", f"{pps_now:,.1f}")
m4.metric("Latest bytes/sec", f"{bps_now:,.0f}")

left, right = st.columns([1.65, 1])
with left:
    st.subheader("Traffic activity")
    if total:
        chart = events[["time", "pps", "bps", "scenario"]].copy()
        fig = px.line(chart, x="time", y="pps", markers=True, hover_data=["scenario"], title="Packets per second by observed window")
        fig.update_layout(height=330, margin=dict(l=10, r=10, t=50, b=10), template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)
        proto = pd.DataFrame({"Protocol": ["TCP", "UDP", "ICMP"], "Share": [float(events.iloc[-1]["tcp_pct"]), float(events.iloc[-1]["udp_pct"]), float(events.iloc[-1]["icmp_pct"])]})
        fig2 = px.pie(proto, names="Protocol", values="Share", hole=0.55, title="Latest window protocol mix")
        fig2.update_layout(height=300, margin=dict(l=10, r=10, t=50, b=10), template="plotly_dark")
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.write("No windows yet. Choose a mode and generate a sample or capture a live window.")

with right:
    st.subheader("Latest diagnosis")
    if latest is not None:
        if latest["status"] == "Anomaly":
            st.error(f'{latest["severity"]} · {latest["cause"]}')
        else:
            st.success(f'LOW · {latest["cause"]}')
        st.write(f'**Window:** {latest["scenario"]}')
        st.write(f'**ML output:** {latest["ml_result"]}')
        st.write(f'**Isolation Forest score:** {latest["ml_score"]} *(lower scores are more anomalous)*')
        st.write(f'**Suggested next step:** {latest["advice"]}')
        st.caption("Machine-learning scores are trained on synthetic baseline data. Rule-based live alerts are simple heuristics; neither proves an attack.")
    else:
        st.write("Your first sample will appear here.")
    st.subheader("Feature snapshot")
    if latest is not None:
        for label, key, fmt in [
            ("Unique destination ports", "unique_ports", "{:.0f}"),
            ("Unique source IPs", "unique_src", "{:.0f}"),
            ("Average packet size", "avg_size", "{:.0f} bytes"),
            ("Burst change", "burst_delta", "{:.2f}"),
        ]:
            st.write(f"**{label}:** " + fmt.format(float(latest[key])))

st.subheader("Event history")
if total:
    wanted = [c for c in ["time", "scenario", "status", "severity", "ml_result", "ml_score", "cause", "advice"] if c in events.columns]
    st.dataframe(events[wanted].iloc[::-1], use_container_width=True, hide_index=True)
    st.download_button("⬇ Download event log (CSV)", data=events.to_csv(index=False).encode("utf-8"), file_name="netguard_event_log.csv", mime="text/csv")
else:
    st.caption("Events appear here after you generate a demo sample or capture a live window.")

with st.expander("About this prototype"):
    st.markdown("""
    - **Simulated mode:** creates synthetic feature windows for a repeatable classroom demonstration.
    - **Live capture mode:** uses Scapy to passively collect packet metadata visible to the selected local interface for a short, fixed window. Packet payloads are not deliberately stored or analyzed.
    - **Feature builder:** packet rate, byte rate, average packet size, unique source IP count, unique destination-port count, protocol ratios, packets per source, and burst change.
    - **ML detector:** Isolation Forest is trained on synthetic normal-like data. Its scores are illustrative and are not validated detection accuracy.
    - **Diagnosis:** simple heuristics suggest patterns worth investigating; they do not prove malicious activity.
    - **Limitations:** interface visibility, operating-system permissions, VPNs, Wi-Fi behavior, and Npcap support can affect capture results.
    """)
