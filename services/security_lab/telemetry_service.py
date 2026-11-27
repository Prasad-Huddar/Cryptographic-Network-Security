"""
Security Event Logging & Live SOC Monitoring Telemetry Service.

All monitoring KPIs, Live Threat Activity, Security Event Logs, and Chart.js analytics
are computed strictly from real persisted `AttackSimulationEvent` records in SQLite.
Every simulation is also cross-recorded into the HMAC-SHA256 protected `SecurityLog` table.
"""
import json
from collections import Counter, defaultdict

from database.database import db
from models.security_lab import AttackSimulationEvent
from services.auth_service import log_security_event
from services.timezone_utils import format_ist_time_bucket, now_ist_formatted


def record_simulation_event(
    *,
    admin_user_id: int | None,
    module_key: str,
    module_name: str,
    attack_key: str,
    attack_type: str,
    attack_category: str,
    description: str,
    payload: dict,
    evidence: dict,
    logs: list[str],
    defence_mechanism: str,
    detected: bool,
    blocked: bool,
    mitigation_action: str,
    final_result: str,
    execution_ms: float,
) -> AttackSimulationEvent:
    """
    Persist an executed attack simulation to both `security_logs` (HMAC-protected)
    and `attack_simulation_events` (HMAC-protected).
    """
    # Map to appropriate SecurityLog event type for full integration with existing audit logs
    if final_result == 'DEFENCE_FAILED':
        sec_event_type = 'DEFENCE_FAILED'
    elif module_key in ('nonce_replay', 'expired_timestamp'):
        sec_event_type = 'REPLAY_ATTEMPT'
    elif module_key == 'rsa_pss':
        sec_event_type = 'INVALID_SIGNATURE'
    elif attack_key == 'unauthorized_key_access':
        sec_event_type = 'ACCESS_DENIED'
    elif module_key in ('aes_gcm', 'rsa_oaep', 'hmac_sha256', 'ciphertext_tampering'):
        sec_event_type = 'TAMPERING_DETECTED'
    else:
        sec_event_type = 'SECURITY_LAB_TEST'

    sec_desc = (
        f"[Security Lab | {module_name}] {attack_type}: "
        f"Result={final_result} | Detected={detected} | Blocked={blocked} | {mitigation_action}"
    )
    sec_log = log_security_event(sec_event_type, sec_desc, user_id=admin_user_id)

    event = AttackSimulationEvent(
        admin_user_id=admin_user_id,
        module_key=module_key,
        module_name=module_name,
        attack_key=attack_key,
        attack_type=attack_type,
        attack_category=attack_category,
        description=description,
        payload_summary=json.dumps(payload, default=str),
        detection_evidence=json.dumps(evidence, default=str),
        execution_logs=json.dumps(logs, default=str),
        defence_mechanism=defence_mechanism,
        detected=bool(detected),
        blocked=bool(blocked),
        mitigation_action=mitigation_action,
        final_result=final_result,
        execution_ms=round(float(execution_ms), 2),
        security_log_id=sec_log.id if sec_log else None,
    )
    event.sign_integrity()

    try:
        db.session.add(event)
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    return event


def get_live_soc_overview(
    module_filter: str | None = None,
    result_filter: str | None = None,
    log_limit: int = 50,
) -> dict:
    """
    Compute live SOC KPI metrics, Live Threat Activity, filtered Security Event Logs,
    and real-time Chart.js analytics strictly from persisted database rows.
    """
    all_events = AttackSimulationEvent.query.order_by(AttackSimulationEvent.executed_at.asc()).all()

    total_simulated = len(all_events)
    detected_count = sum(1 for e in all_events if e.detected)
    blocked_count = sum(1 for e in all_events if e.blocked and e.final_result == 'MITIGATED')
    failed_defence_count = sum(1 for e in all_events if e.final_result == 'DEFENCE_FAILED' or not e.blocked)

    detection_rate = round((detected_count / total_simulated) * 100.0, 1) if total_simulated > 0 else 0.0
    mitigation_rate = round((blocked_count / total_simulated) * 100.0, 1) if total_simulated > 0 else 0.0

    # Category & Module aggregations
    by_category_counter = Counter(e.attack_category for e in all_events)
    by_module_counter = Counter(e.module_name for e in all_events)

    # Per-module detection & mitigation stats
    module_stats_map = defaultdict(lambda: {'total': 0, 'detected': 0, 'blocked': 0, 'failed': 0})
    for e in all_events:
        st = module_stats_map[e.module_name]
        st['total'] += 1
        if e.detected:
            st['detected'] += 1
        if e.blocked and e.final_result == 'MITIGATED':
            st['blocked'] += 1
        else:
            st['failed'] += 1

    module_breakdown = []
    for m_name, st in module_stats_map.items():
        t = st['total']
        module_breakdown.append({
            'module_name': m_name,
            'total': t,
            'detected': st['detected'],
            'blocked': st['blocked'],
            'failed': st['failed'],
            'detection_rate': round((st['detected'] / t) * 100.0, 1) if t else 0.0,
            'mitigation_rate': round((st['blocked'] / t) * 100.0, 1) if t else 0.0,
        })

    # Activity over time (group by IST minute bucket for live local SOC clarity)
    time_buckets: dict[str, dict] = {}
    for e in all_events:
        bucket_label = format_ist_time_bucket(e.executed_at) if e.executed_at else 'Unknown'
        if bucket_label not in time_buckets:
            time_buckets[bucket_label] = {'simulated': 0, 'blocked': 0, 'failed': 0}
        time_buckets[bucket_label]['simulated'] += 1
        if e.blocked and e.final_result == 'MITIGATED':
            time_buckets[bucket_label]['blocked'] += 1
        else:
            time_buckets[bucket_label]['failed'] += 1

    # Keep latest 15 time buckets for clean chart display
    recent_bucket_keys = list(time_buckets.keys())[-15:]
    activity_over_time = {
        'labels': recent_bucket_keys,
        'simulated': [time_buckets[k]['simulated'] for k in recent_bucket_keys],
        'blocked': [time_buckets[k]['blocked'] for k in recent_bucket_keys],
        'failed': [time_buckets[k]['failed'] for k in recent_bucket_keys],
    }

    # Live Threat Activity (latest 12 events)
    recent_desc = list(reversed(all_events))
    live_activity = [e.to_dict(include_details=False) for e in recent_desc[:12]]

    # Filtered Security Event Logs
    filtered_query = AttackSimulationEvent.query
    if module_filter:
        filtered_query = filtered_query.filter_by(module_key=module_filter)
    if result_filter:
        filtered_query = filtered_query.filter_by(final_result=result_filter)
    filtered_events = (
        filtered_query
        .order_by(AttackSimulationEvent.executed_at.desc())
        .limit(max(1, min(int(log_limit), 200)))
        .all()
    )

    return {
        'server_time_ist': now_ist_formatted(),
        'timezone': 'Asia/Kolkata (IST)',
        'metrics': {
            'total_attacks_simulated': total_simulated,
            'attacks_detected': detected_count,
            'attacks_blocked': blocked_count,
            'failed_defence_attempts': failed_defence_count,
            'total_security_tests_executed': total_simulated,
            'detection_rate': detection_rate,
            'mitigation_rate': mitigation_rate,
        },
        'live_threat_activity': live_activity,
        'event_logs': [e.to_dict(include_details=False) for e in filtered_events],
        'analytics': {
            'by_category': {
                'labels': list(by_category_counter.keys()),
                'counts': list(by_category_counter.values()),
            },
            'by_module': {
                'labels': list(by_module_counter.keys()),
                'counts': list(by_module_counter.values()),
            },
            'mitigation_summary': {
                'mitigated': blocked_count,
                'failed_defence': failed_defence_count,
            },
            'activity_over_time': activity_over_time,
            'module_stats': module_breakdown,
        },
    }
