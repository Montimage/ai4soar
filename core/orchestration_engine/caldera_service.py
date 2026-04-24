"""
Caldera service for executing defense abilities.
"""

import logging
import requests
from typing import Dict, Any, Optional
from core.config import config
from core.exceptions import AI4SOARException

logger = logging.getLogger(__name__)


class CalderaService:
    """Service for Caldera operations."""
    
    # Target machine mappings
    TARGETS = {'dorothy': None, 'toto': None, 'wizard': None}
    
    def __init__(self):
        """Initialize Caldera service."""
        self.caldera_config = config.caldera
        self.base_url = self.caldera_config.base_url
        self.api_url = self.caldera_config.api_url
        self.default_headers = self.caldera_config.get_default_headers()
        self.post_headers = self.caldera_config.get_post_headers()
    
    def execute_ability(self, ability_id: str, target: str) -> requests.Response:
        """
        Execute an ability on a target machine.
        
        Args:
            ability_id: Ability identifier
            target: Target machine name
            
        Returns:
            Response from Caldera API
            
        Raises:
            ValueError: If target is invalid or not available
            AI4SOARException: If execution fails
        """
        targets = self._get_current_targets()
        target_paw = targets.get(target)
        
        if not target_paw:
            raise ValueError(f"No active agent for target: {target}")
        
        url = f"{self.base_url}plugin/access/exploit"
        params = {
            'paw': target_paw,
            'ability_id': ability_id,
            'obfuscator': 'plain-text'
        }
        
        # Add ability-specific parameters
        params.update(self._get_ability_params(target_paw, ability_id))
        
        try:
            response = requests.post(url, headers=self.post_headers, json=params)
            response.raise_for_status()
            logger.info(f"Executed ability {ability_id} on target {target}")
            return response
        except requests.RequestException as e:
            logger.error(f"Failed to execute ability {ability_id} on {target}: {e}")
            raise AI4SOARException(f"Failed to execute ability: {e}") from e
    
    def get_abilities(self) -> str:
        """
        Get list of available abilities.
        
        Returns:
            JSON string of abilities
        """
        try:
            response = requests.get(f"{self.api_url}abilities", headers=self.default_headers)
            response.raise_for_status()
            logger.info("Retrieved abilities list")
            return response.text
        except requests.RequestException as e:
            logger.error(f"Failed to retrieve abilities: {e}")
            raise AI4SOARException(f"Failed to retrieve abilities: {e}") from e
    
    def _get_current_targets(self) -> Dict[str, Optional[str]]:
        """
        Get current target mappings with active agents.
        
        Returns:
            Dictionary mapping target names to PAW identifiers
        """
        agents = self._update_and_get_agents()
        targets = {name: None for name in self.TARGETS.keys()}
        
        for agent in agents:
            host = agent.get('host', '')
            for target_name in targets.keys():
                if target_name in host.lower():
                    targets[target_name] = agent['paw']
                    break
        
        logger.debug(f"Current targets: {targets}")
        return targets
    
    def _get_ability_params(self, agent_paw: str, ability_id: str) -> Dict[str, Any]:
        """
        Get ability-specific parameters.
        
        Args:
            agent_paw: Agent PAW identifier
            ability_id: Ability identifier
            
        Returns:
            Dictionary of parameters
        """
        params = {}
        
        # Get agent name by paw
        agents = self._update_and_get_agents()
        name = ''
        for agent in agents:
            if agent['paw'] == agent_paw:
                name = agent['host']
                break
        
        if not name:
            return params
        
        # Determine username based on machine
        username = ''
        if 'wizard' in name.lower():
            username = 'Administrator'
        elif 'toto' in name.lower():
            username = 'totouser1'
        elif 'dorothy' in name.lower():
            username = 'dorothyuser1'
        
        # Ability-specific parameters
        if ability_id == "ad0b71fe-1b2d-4847-a24a-f4de322ac360":
            # Disable user account
            params = {'facts': [{'trait': 'target.username', 'value': username}]}
        elif ability_id == "4e5c5024-765d-4ff5-ae68-6d1d496c8bef":
            # Force password reset
            params = {'facts': [{'trait': 'target.username', 'value': username}]}
        elif ability_id == "9fd2778f-91a9-469f-8357-0cb50b02a4ae":
            # Force sign out
            params = {'facts': [{'trait': 'target.username', 'value': username}]}
        elif ability_id == "a0a0696f-6da2-4bf0-b482-af230fd3bc68":
            # Terminate process
            if 'wizard' in name.lower():
                params = {'facts': [{'trait': 'target.process', 'value': 'uxtheme.exe'}]}
            elif 'toto' in name.lower():
                params = {'facts': [{'trait': 'target.process', 'value': 'uxtheme.exe'}]}
            elif 'dorothy' in name.lower():
                params = {'facts': [{'trait': 'target.process', 'value': 'ChristmasCard.exe'}]}
        elif ability_id == "fed49260-7d04-4d9f-a918-b7dc6c4a98aa":
            # Delete file
            if 'wizard' in name.lower():
                params = {'facts': [{'trait': 'target.filepath',
                                     'value': r'C:\Users\Administrator\create_agent.ps1, C:\Users\Administrator\uxtheme.exe'}]}
            elif 'toto' in name.lower():
                params = {'facts': [{'trait': 'target.filepath', 'value': r'C:\Users\totouser1\AppData\uxtheme.exe'}]}
            elif 'dorothy' in name.lower():
                params = {'facts': [{'trait': 'target.filepath',
                                     'value': r'C:\Users\dorothyuser1\Desktop\ChristmasCard.exe'}]}
        elif ability_id == "96f40897-739b-4bbd-bef0-4adee91b6ee6":
            # Delete registry entry
            if 'dorothy' in name.lower():
                params = {'facts': [
                    {'trait': 'target.registrypath', 'value': r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'},
                    {'trait': 'target.registryvalue', 'value': 'blbdigital'}
                ]}
            elif 'wizard' in name.lower():
                params = {'facts': [
                    {'trait': 'target.registrypath', 'value': r'"HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"'},
                    {'trait': 'target.registryvalue', 'value': 'Userinit'}
                ]}
        elif ability_id == "0a512e0e-aa82-4419-8d23-3d550a769028":
            # Block C2 communication
            if 'wizard' in name.lower():
                params = {'facts': [{'trait': 'target.programpath', 'value': r'C:\Users\Administrator\uxtheme.exe'}]}
            elif 'toto' in name.lower():
                params = {'facts': [{'trait': 'target.programpath', 'value': r'C:\Users\totouser1\AppData\uxtheme.exe'}]}
            elif 'dorothy' in name.lower():
                params = {'facts': [{'trait': 'target.programpath',
                                     'value': r'C:\Users\dorothyuser1\Desktop\ChristmasCard.exe'}]}
        
        return params
    
    def _get_blue_agents(self) -> requests.Response:
        """Get blue team agents."""
        return requests.get(f"{self.api_url}agents", headers=self.default_headers)
    
    def _delete_agent(self, agent_paw: str) -> requests.Response:
        """Delete an agent."""
        url = f"{self.api_url}agents/{agent_paw}"
        return requests.delete(url, headers=self.default_headers)
    
    def _clear_dead_agents(self, agent_list: list) -> int:
        """Clear untrusted agents."""
        count = 0
        for agent in agent_list:
            if agent.get('trusted') is False:
                try:
                    self._delete_agent(agent['paw'])
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to delete agent {agent['paw']}: {e}")
        return count
    
    def _update_and_get_agents(self) -> list:
        """Update and get current blue agents."""
        try:
            response = self._get_blue_agents()
            response.raise_for_status()
            agent_list = response.json()
            
            # Clear dead agents
            self._clear_dead_agents(agent_list)
            
            # Get alive agents
            agents = []
            for agent in agent_list:
                if agent.get('trusted') is False:
                    continue
                
                host = agent.get('host', '').lower()
                if 'dorothy' in host:
                    agent['id'] = 1
                elif 'toto' in host:
                    agent['id'] = 2
                elif 'wizard' in host:
                    agent['id'] = 3
                else:
                    agent['id'] = 0
                
                agents.append(agent)
            
            logger.debug(f"Retrieved {len(agents)} active agents")
            return agents
            
        except Exception as e:
            logger.error(f"Failed to update and get agents: {e}")
            return []
