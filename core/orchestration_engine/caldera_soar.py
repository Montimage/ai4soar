'''
Caldera client for execution of defenses.

This script should be invoked after the recommendation service (AI4ADAPT) returns
an ability_id (defense) to a target (machine).

For UC3 (HES) the attack propagates through 3 machines.
Each machine has **2** identifiers:
- Logical name: the name of the machine related to the attack development
- PAW name: the id of the caldera agent deployed in each file.

Note: PAW identifiers are not stick to the machine, but to the agent deployed in the
machine. They change on every machine restart, etc.
'''

import requests
import json

BASE_URL = 'http://192.168.126.176:8888/'  # TODO replace by env variable
API_URL = BASE_URL + 'api/v2/'
API_KEY_BLUE = 'BLUEADMIN123'  # TODO replace by env variable
DEFAULT_HEADERS = {'Accept': 'application/json', 'KEY': API_KEY_BLUE}
POST_HEADERS = {'Content-Type': 'application/json', 'KEY': API_KEY_BLUE}

# The HUMAN name of the machine/users and caldera client id (the paw_agent)
TARGETS = {'dorothy': None, 'toto': None, 'wizard': None}


def execute_ability(ability_id: str, target: str) -> requests.Response:
    '''
    Execute an action (or ability) into an agent deployed in the
    target name. Example id:'3388-44...' on target: 'dorothy'
    '''
    targets = _current_targets()
    print(targets)
    target_paw = targets[target]
    print(target_paw)
    if not target_paw:
        raise ValueError('There is not currently a paw for that target. Is the machine down?', target, target_paw)
    url = BASE_URL + 'plugin/access/exploit'
    print(url)
    params = {'paw': target_paw, 'ability_id': ability_id, 'obfuscator': 'plain-text'}
    print(params)
    params.update(_get_ability_params(target_paw, ability_id))
    print(params)
    return requests.post(url, headers=POST_HEADERS, json=params)


def get_abilities() -> str:
    '''
    Informative function: list and description of available abilities
    '''
    obj = requests.get(API_URL + 'abilities', headers=DEFAULT_HEADERS).json()
    return json.dumps(obj, indent=2)

def _current_targets() -> dict:
    '''
    Remove obsolete blue agents from Caldera and return {name:paw} dict
    '''
    agents = _update_and_get_agents()
    targets = {TARGETS[r]: None for r in TARGETS.keys()}
    for agent in agents:
        targets[agent['host']] = agent['paw']
    return targets


def _get_ability_params(agent_paw, ability_id, path='response_actions.json'):
    """
    Hardcoded facts for the implemented abilities
    """
    params = {}
    name = ''
    username = ''
    # Get agent name by paw
    agents = _update_and_get_agents()
    for agent in agents:
        if agent['paw'] == agent_paw:
            name = agent['host']
            break
    if not name:
        return params
    if 'wizard' in name:
        username = 'Administrator'
    elif 'toto' in name:
        username = 'totouser1'
    elif 'dorothy' in name:
        username = 'dorothyuser1'

    if ability_id == "ad0b71fe-1b2d-4847-a24a-f4de322ac360":
        # Disable user account
        params = {'facts': [{'trait': 'target.username', 'value': username}]}
    elif ability_id == "4e5c5024-765d-4ff5-ae68-6d1d496c8bef":
        # Force password reset
        params = {'facts': [{'trait': 'target.username', 'value': username}]}
    elif ability_id == "9fd2778f-91a9-469f-8357-0cb50b02a4ae":
        # Force sign out
        params = {'facts': [{'trait': 'target.username', 'value': username}]}
    elif ability_id == "67741162-0d58-4021-bb60-0da5462db181":
        # Add to blocklist
        raise NotImplementedError(
            're-implement this snippet of code by retrieving the IP to be blocked first (the ATTACKER_IP)')
        # params = {'facts': [{'trait': 'target.ipaddr', 'value': ATTACKER_IP}]}
    elif ability_id == "a0a0696f-6da2-4bf0-b482-af230fd3bc68":
        # Terminate process
        # TODO: Hay mas procesos que se podrian matar durante el ataque (e.g., malware.bat del final)
        if 'wizard' in name:
            params = {'facts': [{'trait': 'target.process', 'value': 'uxtheme.exe'}]}
        elif 'toto' in name:
            params = {'facts': [{'trait': 'target.process', 'value': 'uxtheme.exe'}]}
        elif 'dorothy' in name:
            params = {'facts': [{'trait': 'target.process', 'value': 'ChristmasCard.exe'}]}
    elif ability_id == "fed49260-7d04-4d9f-a918-b7dc6c4a98aa":
        # Delete file
        # TODO: Hay mas ficheros que se podrian borrar durante el ataque (OutlookScraper, kill.bat, window.bat, malware.bat)
        if 'wizard' in name:
            params = {'facts': [{'trait': 'target.filepath',
                                 'value': r'C:\Users\Administrator\create_agent.ps1, C:\Users\Administrator\uxtheme.exe'}]}
        elif 'toto' in name:
            params = {'facts': [{'trait': 'target.filepath', 'value': r'C:\Users\totouser1\AppData\uxtheme.exe'}]}
        elif 'dorothy' in name:
            params = {'facts': [{'trait': 'target.filepath',
                                 'value': r'C:\Users\dorothyuser1\Desktop\ChristmasCard.exe'}]}
    elif ability_id == "4a0e90a3-22a0-4ae6-a6e5-c85f6b7cccaa":
        # Stop service (Disabled ATM)
        params = {}
    elif ability_id == "5d81941a-e991-4091-89bd-b26a35d1777f":
        # Delete service (Disabled ATM)
        params = {}
    elif ability_id == "96f40897-739b-4bbd-bef0-4adee91b6ee6":
        # Delete registry entry (ONLY FOR DOROTHY AND WIZARD)
        if 'dorothy' in name:
            params = {'facts': [{'trait': 'target.registrypath', 'value': r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'}, {
                'trait': 'target.registryvalue', 'value': 'blbdigital'}]}
        elif 'wizard' in name:
            params = {'facts': [{'trait': 'target.registrypath', 'value': r'"HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"'}, {
                'trait': 'target.registryvalue', 'value': 'Userinit'}]}
    elif ability_id == "6efbb628-0db1-484e-b1a7-2d5a60bf40c9":
        # Delete scheduled task (Disabled ATM)
        params = {}
    elif ability_id == "0a512e0e-aa82-4419-8d23-3d550a769028":
        # Block C2 communication
        if 'wizard' in name:
            params = {'facts': [{'trait': 'target.programpath', 'value': r'C:\Users\Administrator\uxtheme.exe'}]}
        elif 'toto' in name:
            params = {'facts': [{'trait': 'target.programpath', 'value': r'C:\Users\totouser1\AppData\uxtheme.exe'}]}
        elif 'dorothy' in name:
            params = {'facts': [{'trait': 'target.programpath',
                                 'value': r'C:\Users\dorothyuser1\Desktop\ChristmasCard.exe'}]}
    return params


def get_blue_agents():
    return requests.get(API_URL + 'agents', headers=DEFAULT_HEADERS)


def _delete_agent(agent_paw):
    """
    Delete a given agent from Caldera
    """
    url = API_URL + 'agents/' + agent_paw
    # ARF: same, removed RED from here
    return requests.delete(url, headers={'KEY': API_KEY_BLUE})


def _clear_dead_agents(agent_list):
    """
    Delete agents marked as untrusted
    """
    count = 0
    for agent in agent_list:
        if agent['trusted'] is False:
            _delete_agent(agent['paw'])
            count += 1
    return count


def _update_and_get_agents():
    """
    Delete dead agents and retrieve current BLUE agent list
    """
    # ARF 15-05-2024: remove red-agent since soar should not handle "viruses", only "defenses"
    agent_list = get_blue_agents().json()
    _clear_dead_agents(agent_list)

    # Get alive agents
    agents = []
    for agent in agent_list:
        if agent['trusted'] is False:
            continue
        if 'dorothy' in agent['host']:
            agent['id'] = 1
        elif 'toto' in agent['host']:
            agent['id'] = 2
        else:
            agent['id'] = 3
        agents.append(agent)

    return agents


if __name__ == '__main__':
    print(get_abilities())
    # print(_update_and_get_agents())
    id = "bddd018f-220e-4ce0-9c9a-17751199dd1a" 
    target = "PDC1"
    print(execute_ability(id, target))

