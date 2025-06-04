# Complete replacement for attack_flow_handler.py
# This is the full file with the modifications for exact matching

import logging
from original.attacktest4 import AttackFlow, AttackFlowParser, load_attack_flow
from typing import Dict, Any, List, Optional
import uuid
import re

# Configure logging
logger = logging.getLogger(__name__)


class AttackFlowHandler:
    def __init__(self, flow_file: str):
        """Initialize the attack flow handler with a flow file"""
        self.attack_flow = None
        self.flow_file = flow_file
        self.initialize_flow()

    def initialize_flow(self) -> bool:
        """Load the attack flow from file"""
        try:
            self.attack_flow = load_attack_flow(self.flow_file)
            if self.attack_flow:
                logger.info(f"Attack flow '{self.attack_flow.name}' loaded successfully")
                logger.info(f"Start nodes: {[node.name for node in self.attack_flow.start_nodes]}")
                return True
            else:
                logger.warning(f"Failed to load attack flow from {self.flow_file}")
                return False
        except Exception as e:
            logger.error(f"Error initializing attack flow: {str(e)}")
            return False

    # Direct fix for AttackFlowHandler.process_alert

    def process_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process an alert through the attack flow detection system.
        Modified to correctly report next expected techniques.

        Args:
            alert_data: The JSON data of the alert

        Returns:
            Dict with information about the attack flow processing
        """
        if not self.attack_flow:
            return {
                "status": "error",
                "message": "Attack flow not initialized"
            }

        # Extract MITRE ATT&CK technique ID from the alert
        technique_id = None
        if 'rule' in alert_data and 'mitre' in alert_data['rule'] and 'id' in alert_data['rule']['mitre']:
            mitre_ids = alert_data['rule']['mitre']['id']
            if mitre_ids and len(mitre_ids) > 0:
                technique_id = mitre_ids[0]

        # If no technique ID found, cannot process through attack flow
        if not technique_id:
            logger.warning("No MITRE ATT&CK technique ID found in alert - cannot process through attack flow")
            return {
                "status": "not_processed",
                "reason": "No MITRE ATT&CK technique ID found in alert"
            }

        # Create a processed alert for the attack flow, including the full alert for pattern matching
        processed_alert = {
            'id': alert_data.get('id', str(uuid.uuid4())),
            'technique_id': technique_id,
            'description': alert_data.get('rule', {}).get('description', 'No description'),
            'original_alert': alert_data  # Include the full alert for complex pattern matching
        }

        # Log the alert being processed
        logger.info(f"Processing alert with technique ID {technique_id} through attack flow")

        # Process through attack flow
        matched_node, sequence_changed = self.attack_flow.process_alert(processed_alert)

        # Find nodes matching this technique, regardless of sequence
        matching_nodes_result = self.find_matching_node_by_technique(technique_id)
        matching_nodes = matching_nodes_result.get("matching_nodes", [])

        # Determine if this is a valid sequence or a technique match outside sequence
        in_sequence = self.attack_flow.in_valid_sequence

        # IMPORTANT: Get the truly next expected techniques AFTER processing
        # This ensures we're getting the next techniques after the current position has been updated
        next_expected_techniques = self.attack_flow.get_expected_next_techniques()

        # Check expected techniques AFTER processing the alert
        expected_check = {
            "matches_expected": False,
            "expected_techniques": next_expected_techniques,
            "matching_expected": None
        }

        # Build result object with more informative properties
        result = {
            "status": "processed",
            "matched_node": matched_node.name if matched_node else None,
            "sequence_valid": in_sequence,
            "sequence_changed": sequence_changed,
            "current_position": self.attack_flow.current_position.name if self.attack_flow.current_position else None,
            "technique_id": technique_id,
            "matching_nodes": matching_nodes_result,
            "has_matching_technique": len(matching_nodes) > 0,
            "matching_technique_nodes": [node["node_name"] for node in matching_nodes],
            "is_expected_next_node": matched_node is not None,
            "is_out_of_sequence_match": len(matching_nodes) > 0 and matched_node is None,
            "expected_check": expected_check
        }

        # Create a user-friendly status message
        if matched_node:
            result[
                "status_message"] = f"Alert matched the expected next step in the attack sequence: {matched_node.name}"
        elif len(matching_nodes) > 0:
            result[
                "status_message"] = f"Alert contains technique {technique_id} which exists in the attack flow but was not expected at this point"
            if next_expected_techniques:
                result["status_message"] += f" (expected: {', '.join(next_expected_techniques)})"
        else:
            result["status_message"] = f"Alert technique {technique_id} does not match any technique in the attack flow"

        # Add attack flow position information with CORRECT next expected techniques
        result["attack_flow_position"] = {
            "current_position": self.attack_flow.current_position.name if self.attack_flow.current_position else None,
            "current_technique": self.attack_flow.current_position.technique_id if self.attack_flow.current_position and hasattr(
                self.attack_flow.current_position, 'technique_id') else None,
            "next_expected_techniques": next_expected_techniques
        }

        # Log the result
        if matched_node:
            logger.info(f"Alert matched node: {matched_node.name} in attack flow")
            logger.info(f"Next expected techniques: {next_expected_techniques}")
        elif result["has_matching_technique"]:
            logger.info(f"Alert matched technique {technique_id} but outside of expected sequence")
        else:
            logger.info(f"Alert did not match any node in attack flow")

        return result

    def find_matching_node_by_technique(self, technique_id: str) -> Dict[str, Any]:
        """
        Find any node that exactly matches the given technique ID.
        Modified to use exact matching only.
        """
        if not self.attack_flow:
            return {"status": "error", "message": "Attack flow not initialized"}

        matching_nodes = []

        # Search all action nodes for the technique ID
        for node_id, node in self.attack_flow.action_nodes.items():
            # Skip the Start State node since it's just a placeholder
            if node.name == "Start State":
                continue

            # Use exact matching only - no parent/child relationships
            if node.technique_id and node.technique_id == technique_id:
                matching_nodes.append({
                    "node_id": node.id,
                    "node_name": node.name,
                    "technique_id": node.technique_id
                })

        return {
            "status": "success",
            "matching_nodes": matching_nodes,
            "count": len(matching_nodes)
        }

    def check_expected_techniques(self, technique_id: str) -> Dict[str, Any]:
        """
        Check if a technique matches the next expected step in the flow.
        Modified to use exact matching only.
        """
        if not self.attack_flow or not self.attack_flow.current_position:
            return {
                "matches_expected": False,
                "reason": "No current position in flow",
                "expected_techniques": []
            }

        # Get expected next techniques
        expected_techniques = self.attack_flow.get_expected_next_techniques()

        # Check if this technique exactly matches any expected technique
        # No parent/child relationships - must be exact match
        matches = technique_id in expected_techniques
        matching_technique = technique_id if matches else None

        return {
            "matches_expected": matches,
            "expected_techniques": expected_techniques,
            "matching_expected": matching_technique
        }

    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the attack flow"""
        if not self.attack_flow:
            return {
                "status": "error",
                "message": "Attack flow not initialized"
            }

        expected_techniques = self.get_expected_next_techniques()

        return {
            "status": "success",
            "flow_name": self.attack_flow.name,
            "sequence_valid": self.attack_flow.in_valid_sequence,
            "current_position": self.attack_flow.current_position.name if self.attack_flow.current_position else None,
            "current_technique": self.attack_flow.current_position.technique_id if self.attack_flow.current_position and hasattr(
                self.attack_flow.current_position, 'technique_id') else None,
            "expected_next": expected_techniques
        }

    def get_history(self) -> Dict[str, Any]:
        """Get the history of the attack flow"""
        if not self.attack_flow:
            return {
                "status": "error",
                "message": "Attack flow not initialized"
            }

        # Format the history for return
        formatted_history = []
        for event in self.attack_flow.history:
            # Copy the event but remove the full alert to reduce response size
            event_copy = event.copy()
            if 'alert' in event_copy:
                event_copy['alert'] = {
                    'id': event_copy['alert'].get('id', 'unknown'),
                    'technique_id': event_copy['alert'].get('technique_id', 'unknown'),
                    'description': event_copy['alert'].get('description', 'No description')
                }
            formatted_history.append(event_copy)

        # Add a summary of the attack path
        attack_path = []
        for event in self.attack_flow.history:
            if 'was_active' in event and event.get('was_active', False):
                technique_id = event.get('technique_id', 'unknown')
                node_name = event.get('node_name', 'unknown')
                attack_path.append(f"{node_name} ({technique_id})")

        return {
            "status": "success",
            "flow_name": self.attack_flow.name,
            "history": formatted_history,
            "attack_path": attack_path if attack_path else [],
            "sequence_valid": self.attack_flow.in_valid_sequence,
            "current_position": self.attack_flow.current_position.name if self.attack_flow.current_position else None
        }

    def get_expected_next_techniques(self) -> List[str]:
        """Get the next expected techniques in the flow"""
        if not self.attack_flow:
            return []

        return self.attack_flow.get_expected_next_techniques()

    def reset(self) -> Dict[str, Any]:
        """Reset the attack flow"""
        if not self.attack_flow:
            return {
                "status": "error",
                "message": "Attack flow not initialized"
            }

        self.attack_flow.reset()

        return {
            "status": "success",
            "message": "Attack flow reset successfully",
            "flow_name": self.attack_flow.name
        }