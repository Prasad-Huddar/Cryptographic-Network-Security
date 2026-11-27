"""
Admin Cybersecurity Attack Simulation & Defence Centre — Backend Services Package.

Architecture separation:
- sandbox_keys.py: Isolated ephemeral keypairs & RBAC key-vault isolation (never touches production keys)
- detection_service.py: Cryptographic verification, attack detection & mitigation assessment
- attack_engine.py: Controlled backend attack execution across all 8 security modules
- telemetry_service.py: Persistent audit logging, live SOC KPIs, and Chart.js analytics
"""
