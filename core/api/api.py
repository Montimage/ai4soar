from flask import Flask
from core.orchestration_engine.shuffle import get_workflows, execute_workflow, get_workflow_results
from core.constants import PORT

app = Flask(__name__)

# List all workflow's ids
@app.route('/workflows', methods=['GET'])
def get_workflows_route():
    return get_workflows()

# Execute a workflow given its id
@app.route('/workflows/<workflow_id>/execute', methods=['POST'])
def execute_workflow_route(workflow_id):
    return execute_workflow(workflow_id)

# Get workflow execution results
@app.route('/workflows/results', methods=['POST'])
def get_workflow_results_route():
    return get_workflow_results()

if __name__ == '__main__':
    app.run(port=PORT, debug=True)