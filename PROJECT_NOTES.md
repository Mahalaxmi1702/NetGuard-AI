# NetGuard AI project notes

This prototype combines repeatable simulated traffic windows with a short, passive Scapy capture mode. It summarizes packet metadata into rate, size, IP-count, port-count, and protocol-ratio features. Isolation Forest scores are illustrative because training data is synthetic. Live diagnosis uses simple heuristics and should be described as a possible pattern, not proof of an attack.

Suggested review explanation: “NetGuard AI captures metadata visible to a selected local network interface, aggregates packets into short windows, extracts traffic features, applies an anomaly-scoring model, and displays possible patterns in a dashboard. Simulation mode provides a reliable fallback.”
