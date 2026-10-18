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


@playbooks_bp.route('/playbooks/shuffle_library', methods=['GET'])
def shuffle_library_status():
    """Per library template: is its Shuffle workflow missing, outdated or current."""
    from core.orchestration_engine import shuffle_library
    try:
        return jsonify({'templates': shuffle_library.status()}), 200
    except Exception as e:
        logger.error(f"Error reading the Shuffle library status: {e}")
        return jsonify({'error': f'Shuffle: {e}'}), 502


@playbooks_bp.route('/playbooks/shuffle_library/sync', methods=['POST'])
def shuffle_library_sync():
    """Create missing / update outdated library workflows in Shuffle.

    Body (optional): {"only": ["t1110"], "force": false}. Credentials entered in Shuffle are kept.
    """
    from core.orchestration_engine import shuffle_library
    data = request.get_json(silent=True) or {}
    try:
        return jsonify({'results': shuffle_library.sync(data.get('only') or None,
                                                        force=bool(data.get('force')))}), 200
    except Exception as e:
        logger.error(f"Error syncing the library to Shuffle: {e}")
        return jsonify({'error': f'Shuffle: {e}'}), 502


@playbooks_bp.route('/playbooks/shuffle_workflow', methods=['POST'])
def deploy_to_shuffle():
    """Create (or reuse) the Shuffle workflow for a recommended playbook.

    Body: {"cacao": <parameterized CACAO 2.0 playbook>, "generated": <true for Path D>}
    Returns {workflow_id, name, url, mode, reused, nodes, warnings}; the workflow is then
    run with POST /playbooks/<workflow_id>/execute.
    """
    from core.orchestration_engine.shuffle_deploy import ConversionError, deploy_playbook
    data = request.get_json(silent=True) or {}
    cacao = data.get('cacao')
    if not isinstance(cacao, dict) or not cacao.get('workflow'):
        return jsonify({'error': 'Body must contain a CACAO playbook under "cacao"'}), 400
    try:
        return jsonify(deploy_playbook(cacao, generated=bool(data.get('generated')))), 200
    except (ValueError, ConversionError) as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error deploying playbook to Shuffle: {e}")
        return jsonify({'error': f'Shuffle: {e}'}), 502


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


@playbooks_bp.route('/soarca/status', methods=['GET'])
def soarca_status():
    """{configured, ok, version, error}: whether the Execute dialog offers a SOARCA dry run."""
    from core.orchestration_engine.soarca import SoarcaError, status
    if not config.soarca.url:
        return jsonify({'configured': False, 'ok': False}), 200
    try:
        return jsonify({'configured': True, 'ok': True, 'version': status().get('version')}), 200
    except SoarcaError as e:
        return jsonify({'configured': True, 'ok': False, 'error': str(e)}), 200


@playbooks_bp.route('/soarca/dry_run', methods=['POST'])
def soarca_dry_run():
    """Dry-run a CACAO playbook on SOARCA. Body: {"cacao": <CACAO 2.0>}.

    Returns {execution_id, warnings, steps}; poll GET /soarca/results/<execution_id>.
    """
    from core.orchestration_engine.soarca import SoarcaError, run_dry
    cacao = (request.get_json(silent=True) or {}).get('cacao')
    if not isinstance(cacao, dict) or not cacao.get('workflow'):
        return jsonify({'error': 'Body must contain a CACAO playbook under "cacao"'}), 400
    try:
        return jsonify(run_dry(cacao)), 200
    except SoarcaError as e:
        return jsonify({'error': str(e)}), 502


@playbooks_bp.route('/soarca/results/<execution_id>', methods=['GET'])
def soarca_results(execution_id):
    from core.orchestration_engine.soarca import SoarcaError, results
    try:
        return jsonify(results(execution_id)), 200
    except SoarcaError as e:
        return jsonify({'error': str(e)}), 502


@playbooks_bp.route('/playbook_library/<template_id>', methods=['PUT'])
def save_playbook_template(template_id):
    """Save a template edited in the Workflow view. Body: {"cacao": <CACAO 2.0 dict>}.

    Rewrites the template's cacao: section and bumps its version; the Playbooks page
    then syncs it to Shuffle.
    """
    from core.playbook_library.editing import TemplateEditError, save_template_cacao
    cacao = (request.get_json(silent=True) or {}).get('cacao')
    try:
        return jsonify(save_template_cacao(template_id, cacao)), 200
    except TemplateEditError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error saving template {template_id}: {e}")
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
            from core.intelligent_orchestration.parameterizer import template_hash
            entry = {
                'id':          pb.get('id'),
                'hash':        template_hash(pb),
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
