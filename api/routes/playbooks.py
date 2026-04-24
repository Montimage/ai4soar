"""
Playbook-related API routes.
"""

import glob
import json
import logging
import os
import re
from datetime import datetime

import yaml
from flask import request, jsonify

from api.routes import playbooks_bp
from core.config import config
from core.database.alert_service import AlertService
from core.exceptions import PlaybookNotFoundError
from core.orchestration_engine.caldera_service import CalderaService
from core.orchestration_engine.playbook_service import PlaybookService

logger = logging.getLogger(__name__)

playbook_service = PlaybookService()
alert_service = AlertService()
caldera_service = CalderaService()


@playbooks_bp.route('/shuffle/config', methods=['GET'])
def get_shuffle_config():
    """Return browser-facing Shuffle UI config (no secrets)."""
    return jsonify({
        'ui_url': config.shuffle.ui_base_url,
        'default_workflow_id': config.shuffle.default_workflow_id,
        'default_workflow_url': config.shuffle.workflow_url(),
    }), 200


@playbooks_bp.route('/shuffle/results/<execution_id>', methods=['GET'])
def get_shuffle_execution_results(execution_id):
    """Proxy execution results from Shuffle API by execution_id."""
    try:
        results = playbook_service.get_execution_results(execution_id)
        return jsonify(results), 200
    except Exception as e:
        logger.error(f"Error fetching Shuffle execution results: {e}")
        return jsonify({'error': str(e)}), 500


@playbooks_bp.route('/shuffle/results/log', methods=['POST'])
def log_shuffle_execution():
    """Save full Shuffle execution result to output/execution/<playbook>/<execution_id>.log"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    execution_id = data.get('execution_id', 'unknown')
    workflow_name = (data.get('workflow') or {}).get('name', '') or execution_id
    # Sanitise name for use as a directory name
    safe_name = re.sub(r'[^\w\-]', '_', workflow_name).strip('_') or 'workflow'

    log_dir = os.path.join('output', 'execution', safe_name)
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f'{execution_id}.log')

    results = data.get('results') or []
    lines = [
        f"Execution ID : {execution_id}",
        f"Workflow     : {workflow_name}",
        f"Status       : {data.get('status', '')}",
        f"Timestamp    : {datetime.utcnow().isoformat()}Z",
        "",
        "── Actions ──────────────────────────────────────────",
    ]
    for r in results:
        action_name = (r.get('action') or {}).get('label') \
                   or (r.get('action') or {}).get('name') \
                   or (r.get('action') or {}).get('app_name') \
                   or 'unknown'
        lines.append(f"  [{r.get('status', '')}] {action_name}")
        raw = r.get('result', '')
        if raw:
            lines.append(f"    {raw}")
        lines.append("")

    lines += [
        "── Raw JSON ─────────────────────────────────────────",
        json.dumps(data, indent=2),
    ]

    with open(log_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    logger.info(f"Execution log saved: {log_path}")
    return jsonify({'path': log_path}), 200


@playbooks_bp.route('/technique_names', methods=['GET'])
def get_technique_names():
    """Return {T-code: name} mapping from the STIX knowledge base."""
    try:
        from core.intelligent_orchestration.stix_knowledge_base import stix_kb
        stix_kb.load()
        mapping = {
            tid: (info.get('name') or tid)
            for tid, info in stix_kb._techniques.items()
        }
        return jsonify(mapping), 200
    except Exception as e:
        logger.warning(f"Could not load STIX technique names: {e}")
        return jsonify({}), 200


@playbooks_bp.route('/playbooks', methods=['GET'])
def get_playbooks():
    """List all playbooks or get a specific playbook by ID."""
    try:
        playbook_id = request.args.get('playbook_id')
        
        if playbook_id:
            # Get specific playbook
            try:
                playbook = playbook_service.get_playbook_by_id(playbook_id)
                return jsonify(playbook), 200
            except PlaybookNotFoundError:
                return jsonify({"error": f"Playbook with ID {playbook_id} not found"}), 404
        else:
            # Get all playbooks
            playbooks = playbook_service.get_all_playbooks()
            return jsonify(playbooks), 200
            
    except Exception as e:
        logger.error(f"Error getting playbooks: {e}")
        return jsonify({'error': str(e)}), 500


@playbooks_bp.route('/playbooks/<playbook_id>/execute', methods=['POST'])
def execute_playbook(playbook_id):
    """Execute a playbook by ID."""
    try:
        data = request.get_json() or {}
        result = playbook_service.execute_playbook(playbook_id, data)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error executing playbook: {e}")
        return jsonify({'error': str(e)}), 500


@playbooks_bp.route('/playbooks/results', methods=['POST'])
def get_playbook_results():
    """Get playbook execution results."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        results = playbook_service.get_playbook_results(data)
        return jsonify(results), 200
    except Exception as e:
        logger.error(f"Error getting playbook results: {e}")
        return jsonify({'error': str(e)}), 500


@playbooks_bp.route('/playbook/<alert_id>', methods=['GET'])
def get_playbook_for_alert(alert_id):
    """Get playbook associated with an alert."""
    try:
        playbook_id = alert_service.get_playbook_id_for_alert(alert_id)
        
        if playbook_id:
            return jsonify({"playbook_id": playbook_id}), 200
        else:
            return jsonify({"error": f"No playbook found for alert ID {alert_id}"}), 404
            
    except Exception as e:
        logger.error(f"Error getting playbook for alert: {e}")
        return jsonify({'error': str(e)}), 500


@playbooks_bp.route('/playbook_library', methods=['GET'])
def get_playbook_library():
    """
    Return all CACAO YAML templates from the playbook library directory.

    Query params:
        include_cacao   bool  default false — include the full CACAO workflow dict
    """
    include_cacao = request.args.get('include_cacao', 'false').lower() == 'true'
    try:
        lib_path = config.playbook_library.path
        pattern  = os.path.join(lib_path, '*.yaml')
        templates = []
        for fpath in sorted(glob.glob(pattern)):
            with open(fpath, encoding='utf-8') as f:
                pb = yaml.safe_load(f)
            if not isinstance(pb, dict) or 'id' not in pb:
                continue
            # Normalise parameters: dict → list of {name, …} for easy rendering
            raw_params = pb.get('parameters', {}) or {}
            params_list = [
                {
                    'name':        pname,
                    'type':        pdef.get('type', 'string'),
                    'required':    bool(pdef.get('required', False)),
                    'default':     pdef.get('default'),
                    'description': pdef.get('description', ''),
                    'sources':     pdef.get('sources', []),
                }
                for pname, pdef in raw_params.items()
            ]
            entry = {
                'id':          pb.get('id'),
                'name':        pb.get('name'),
                'version':     pb.get('version', '1.0'),
                'description': pb.get('description', ''),
                'techniques':  pb.get('techniques', []),
                'tactics':     pb.get('tactics', []),
                'parameters':  params_list,
                'file':        os.path.basename(fpath),
            }
            if include_cacao:
                entry['cacao'] = pb.get('cacao', {})
            templates.append(entry)

        return jsonify({'count': len(templates), 'playbooks': templates}), 200
    except Exception as e:
        logger.error(f"Error loading playbook library: {e}")
        return jsonify({'error': str(e)}), 500


@playbooks_bp.route('/execute_ability', methods=['POST'])
def execute_ability():
    """Execute Caldera blue agent ability."""
    try:
        ability_id = request.form.get('ability_id')
        target = request.form.get('target')
        
        # If ability_id is empty and target is not empty, consider it as a no-op
        if ability_id == "" and target != "":
            return jsonify({'message': 'No action taken as ability_id is empty and target is provided.'}), 200
        
        # If both ability_id and target are provided, execute the ability
        if ability_id and target:
            response = caldera_service.execute_ability(ability_id, target)
            return jsonify({
                'message': 'Ability execution initiated successfully',
                'response': response.text
            }), 200
        
        # If not valid inputs, return error
        return jsonify({'error': 'Invalid input - both ability_id and target are required'}), 400
        
    except ValueError as e:
        logger.warning(f"Validation error: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error executing ability: {e}")
        return jsonify({'error': str(e)}), 500
