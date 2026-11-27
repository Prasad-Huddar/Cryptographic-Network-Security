"""
Admin Cybersecurity Attack Simulation & Defence Centre — Flask Blueprint & APIs.

Security Enforcement:
- Every page route and JSON API endpoint strictly enforces Administrator-only RBAC on the backend.
- Any unauthenticated or non-admin access returns HTTP 403 and logs ACCESS_DENIED to SecurityLog.
- All state-changing POST endpoints are protected by Flask-WTF CSRFProtect (via X-CSRFToken header).
- All user inputs are validated and sanitized; errors trigger safe DB rollbacks.
"""
from functools import wraps
from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import current_user

from database.database import db
from models.security_lab import AttackSimulationEvent
from services.auth_service import log_security_event
from services.security_lab.attack_engine import (
    MODULE_CATALOGUE,
    execute_attack_simulation,
    execute_module6_tampering,
    execute_module7_replay,
    generate_and_submit_module7_transaction,
    generate_module6_transaction,
)
from services.security_lab.telemetry_service import get_live_soc_overview

security_lab_bp = Blueprint('security_lab', __name__, url_prefix='/admin/security-lab')


def _parse_int_or_hex(val, default: int, min_val: int = 0, max_val: int = 100000) -> int:
    try:
        if isinstance(val, str):
            parsed = int(val.strip(), 0)
        else:
            parsed = int(val)
        return max(min_val, min(parsed, max_val))
    except (TypeError, ValueError):
        return default


def admin_lab_page_required(f):
    """Strict backend RBAC decorator for Admin Security Lab HTML pages (returns HTTP 403)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            log_security_event(
                'ACCESS_DENIED',
                f'Unauthenticated access attempt to Admin Security Lab page: {request.path}',
            )
            abort(403)
        if not current_user.is_admin:
            log_security_event(
                'ACCESS_DENIED',
                f'Non-admin user {current_user.email} denied access to Admin Security Lab page: {request.path}',
                current_user.id,
            )
            abort(403)
        return f(*args, **kwargs)
    return decorated


def admin_lab_api_required(f):
    """Strict backend RBAC decorator for Admin Security Lab JSON APIs (returns JSON HTTP 403)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            log_security_event(
                'ACCESS_DENIED',
                f'Unauthenticated API access attempt to Admin Security Lab: {request.method} {request.path}',
            )
            return jsonify({
                'success': False,
                'error': 'Access denied. Administrator authentication required.',
            }), 403
        if not current_user.is_admin:
            log_security_event(
                'ACCESS_DENIED',
                f'Non-admin user {current_user.email} denied API access: {request.method} {request.path}',
                current_user.id,
            )
            return jsonify({
                'success': False,
                'error': 'Access denied. Administrator privileges required.',
            }), 403
        return f(*args, **kwargs)
    return decorated


@security_lab_bp.route('/', methods=['GET'])
@security_lab_bp.route('', methods=['GET'])
@admin_lab_page_required
def lab_dashboard():
    """Render the Admin-only Cybersecurity Attack Simulation & Defence Centre page."""
    overview = get_live_soc_overview(log_limit=50)
    return render_template(
        'admin_security_lab.html',
        modules=MODULE_CATALOGUE,
        initial_overview=overview,
    )


@security_lab_bp.route('/api/modules', methods=['GET'])
@admin_lab_api_required
def api_modules():
    """Return metadata for all eight cryptographic security modules."""
    return jsonify({
        'success': True,
        'modules': MODULE_CATALOGUE,
    })


@security_lab_bp.route('/api/overview', methods=['GET'])
@admin_lab_api_required
def api_overview():
    """Return live SOC KPI metrics, threat activity, event logs, and Chart.js analytics."""
    module_filter = (request.args.get('module') or '').strip() or None
    result_filter = (request.args.get('result') or '').strip() or None
    limit = _parse_int_or_hex(request.args.get('limit', 50), default=50, min_val=1, max_val=200)

    overview = get_live_soc_overview(
        module_filter=module_filter,
        result_filter=result_filter,
        log_limit=limit,
    )
    return jsonify({
        'success': True,
        **overview,
    })


@security_lab_bp.route('/api/logs', methods=['GET'])
@admin_lab_api_required
def api_logs():
    """Return persisted AttackSimulationEvent logs with optional filtering."""
    module_filter = (request.args.get('module') or '').strip() or None
    result_filter = (request.args.get('result') or '').strip() or None
    limit = _parse_int_or_hex(request.args.get('limit', 50), default=50, min_val=1, max_val=200)

    q = AttackSimulationEvent.query
    if module_filter:
        q = q.filter_by(module_key=module_filter)
    if result_filter:
        q = q.filter_by(final_result=result_filter)

    events = q.order_by(AttackSimulationEvent.executed_at.desc()).limit(limit).all()
    return jsonify({
        'success': True,
        'count': len(events),
        'logs': [e.to_dict(include_details=False) for e in events],
    })


@security_lab_bp.route('/api/events/<string:event_uid>', methods=['GET'])
@admin_lab_api_required
def api_event_detail(event_uid):
    """Return full sanitized execution details for a single persisted simulation event."""
    ev = AttackSimulationEvent.query.filter_by(event_uid=event_uid.strip()).first()
    if not ev:
        return jsonify({'success': False, 'error': 'Simulation event not found.'}), 404
    return jsonify({
        'success': True,
        'event': ev.to_dict(include_details=True),
    })


@security_lab_bp.route('/api/simulate', methods=['POST'])
@admin_lab_api_required
def api_simulate():
    """
    Execute a real backend cryptographic attack simulation and defence verification
    for any of the eight security modules.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'success': False, 'error': 'Invalid JSON request body.'}), 400

    module_key = str(data.get('module_key', '')).strip()
    attack_key = str(data.get('attack_key', '')).strip()
    options = data.get('options') if isinstance(data.get('options'), dict) else {}

    if not module_key or not attack_key:
        return jsonify({'success': False, 'error': 'Both module_key and attack_key are required.'}), 400

    # Sanitize numeric options if provided
    clean_opts = dict(options)
    if 'byte_offset' in clean_opts:
        clean_opts['byte_offset'] = _parse_int_or_hex(clean_opts['byte_offset'], 0, 0, 4096)
    if 'xor_mask' in clean_opts:
        clean_opts['xor_mask'] = _parse_int_or_hex(clean_opts['xor_mask'], 0xFF, 1, 255)
    if 'burst_count' in clean_opts:
        clean_opts['burst_count'] = _parse_int_or_hex(clean_opts['burst_count'], 1, 1, 10)
    if 'offset_seconds' in clean_opts:
        clean_opts['offset_seconds'] = _parse_int_or_hex(clean_opts['offset_seconds'], 900, 1, 864000)

    try:
        result = execute_attack_simulation(
            module_key=module_key,
            attack_key=attack_key,
            admin_user_id=current_user.id,
            options=clean_opts,
        )
        overview = get_live_soc_overview(log_limit=50)
        return jsonify({
            'success': True,
            'simulation': result,
            'overview': overview,
        }), 200
    except ValueError as exc:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(exc)}), 400
    except Exception:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': 'Internal error occurred during controlled security simulation.',
        }), 500


@security_lab_bp.route('/api/module6/generate', methods=['POST'])
@admin_lab_api_required
def api_module6_generate():
    """Module 6 Step 1: Generate and persist an isolated encrypted synthetic transaction."""
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'success': False, 'error': 'Invalid JSON payload.'}), 400

    custom_item = str(data.get('item_name', '')).strip()[:120] or None
    amount_inr = data.get('amount_inr', 2999.00)
    try:
        generated = generate_module6_transaction(
            admin_user_id=current_user.id,
            custom_item=custom_item,
            amount_inr=amount_inr,
        )
        return jsonify({
            'success': True,
            'transaction': generated,
        }), 201
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to generate synthetic encrypted transaction.'}), 500


@security_lab_bp.route('/api/module6/tamper-execute', methods=['POST'])
@admin_lab_api_required
def api_module6_tamper_execute():
    """Module 6 Steps 2–6: Mutate selected ciphertext bytes and execute real AES-GCM verification."""
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'success': False, 'error': 'Invalid JSON payload.'}), 400

    lab_tx_id = str(data.get('lab_tx_id', '')).strip() or None
    byte_offset = _parse_int_or_hex(data.get('byte_offset', 0), default=0, min_val=0, max_val=4096)
    xor_mask = _parse_int_or_hex(data.get('xor_mask', 0xFF), default=0xFF, min_val=1, max_val=255)
    custom_tampered_b64 = data.get('custom_tampered_b64')
    if custom_tampered_b64 is not None:
        custom_tampered_b64 = str(custom_tampered_b64).strip()[:8192] or None

    try:
        result = execute_module6_tampering(
            admin_user_id=current_user.id,
            lab_tx_id=lab_tx_id,
            byte_offset=byte_offset,
            xor_mask=xor_mask,
            custom_tampered_b64=custom_tampered_b64,
        )
        overview = get_live_soc_overview(log_limit=50)
        return jsonify({
            'success': True,
            'simulation': result,
            'overview': overview,
        }), 200
    except ValueError as exc:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(exc)}), 400
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Ciphertext tampering test failed safely.'}), 500


@security_lab_bp.route('/api/module7/generate-and-submit', methods=['POST'])
@admin_lab_api_required
def api_module7_generate_and_submit():
    """Module 7 Steps 1–4: Generate a legitimate transaction with UUID nonce, submit & capture it."""
    try:
        captured = generate_and_submit_module7_transaction(admin_user_id=current_user.id)
        return jsonify({
            'success': True,
            'captured': captured,
        }), 201
    except ValueError as exc:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(exc)}), 400
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to generate and submit test transaction.'}), 500


@security_lab_bp.route('/api/module7/replay', methods=['POST'])
@admin_lab_api_required
def api_module7_replay():
    """Module 7 Steps 5–7: Replay captured request against atomic persistent nonce guard."""
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'success': False, 'error': 'Invalid JSON payload.'}), 400

    lab_tx_id = str(data.get('lab_tx_id', '')).strip() or None
    attack_key = str(data.get('attack_key', 'captured_request_replay')).strip()
    if attack_key not in ('captured_request_replay', 'concurrent_replay_burst'):
        attack_key = 'captured_request_replay'
    burst_count = _parse_int_or_hex(
        data.get('burst_count', 5 if attack_key == 'concurrent_replay_burst' else 1),
        default=1,
        min_val=1,
        max_val=10,
    )

    try:
        result = execute_module7_replay(
            admin_user_id=current_user.id,
            lab_tx_id=lab_tx_id,
            attack_key=attack_key,
            burst_count=burst_count,
        )
        overview = get_live_soc_overview(log_limit=50)
        return jsonify({
            'success': True,
            'simulation': result,
            'overview': overview,
        }), 200
    except ValueError as exc:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(exc)}), 400
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Replay simulation failed safely.'}), 500
