from __future__ import annotations
from typing import Dict, List, Set, Optional, Any, Tuple
import json
import re
import uuid
from datetime import datetime
import os  # To check if file exists
import logging

# Configure logging
logger = logging.getLogger(__name__)


class Node:
    """Base class for nodes in an attack flow."""

    def __init__(self, node_id: str, name: str, technique_id: str = None, description: str = None):
        self.id = node_id
        self.name = name
        self.description = description
        self.technique_id = technique_id

    def __eq__(self, other):
        if not isinstance(other, Node):
            return False
        return self.id == other.id

    def __hash__(self):
        return hash(self.id)


class ActionNode(Node):
    """A node representing an attack action/technique that has been confirmed."""

    def __init__(self, node_id: str, name: str, technique_id: str = None, description: str = None):
        super().__init__(node_id, name, technique_id, description)
        # The next node can be either another ActionNode or a ConditionNode
        self.next_node = None

    def __str__(self):
        return f"ActionNode({self.name}, {self.technique_id})"


class ConditionNode(Node):
    """A node representing a condition check with a pattern for incoming alerts."""

    def __init__(self, node_id: str, name: str, pattern: str, description: str = None):
        super().__init__(node_id, name, None, description)
        self.pattern = pattern
        self.true_node_refs: List[str] = []  # IDs of nodes to go to if true
        self.false_node_refs: List[str] = []  # IDs of nodes to go to if false
        self.true_nodes: List[Node] = []  # Nodes to go to if true (resolved)
        self.false_nodes: List[Node] = []  # Nodes to go to if false (resolved)

    def check_pattern(self, alert: Dict[str, Any]) -> bool:
        """
        Check if an alert matches this condition with exact technique matching.

        Args:
            alert: Alert data dictionary

        Returns:
            True if condition matches, False otherwise
        """
        # Direct technique match approach
        if self.description and self.description.startswith('T') and 'technique_id' in alert:
            # Extract the technique ID from the description (e.g., "T1078" from "T1078 - Something")
            desc_technique_match = re.match(r'(T\d+(\.\d+)*)', self.description)
            if desc_technique_match:
                condition_technique = desc_technique_match.group(1)
                alert_technique = alert.get('technique_id')

                # Exact match only
                if condition_technique == alert_technique:
                    logger.info(f"Exact technique match: {condition_technique} == {alert_technique}")
                    return True
                else:
                    logger.debug(f"No exact technique match: {condition_technique} != {alert_technique}")
                    return False

        # If we don't have a technique in description or no technique in alert,
        # fall back to pattern matching

        # Early exit if pattern is empty
        if not self.pattern:
            logger.warning(f"Empty pattern in condition {self.name}")
            return False

        # Process complex patterns
        original_alert = alert.get('original_alert', {})

        # Extract fields for matching
        process_name = original_alert.get('data', {}).get('win', {}).get('eventdata', {}).get('image', '')
        cmd_line = original_alert.get('data', {}).get('win', {}).get('eventdata', {}).get('commandLine', '')

        # Normalize process name
        if process_name and '\\' in process_name:
            process_name = process_name.split('\\')[-1].lower()
        else:
            process_name = process_name.lower() if process_name else ''

        # Extract pattern elements
        pattern_elements = []

        # Process name patterns
        process_name_patterns = re.findall(r"process:name\s*=\s*'([^']+)'", self.pattern)
        for p in process_name_patterns:
            pattern_elements.append(('process_name', p))

        # Command line patterns
        cmd_line_patterns = re.findall(r"process:command_line\s+MATCHES\s+'([^']+)'", self.pattern)
        for p in cmd_line_patterns:
            pattern_elements.append(('cmd_line', p))

        # If no pattern elements extracted, check for technique match in the alert
        if not pattern_elements:
            # Try to match technique ID if it's in the condition description
            alert_technique = alert.get('technique_id')
            if alert_technique and self.description and self.description.startswith('T'):
                desc_technique_match = re.match(r'(T\d+(\.\d+)*)', self.description)
                if desc_technique_match:
                    condition_technique = desc_technique_match.group(1)
                    # Exact match only
                    return condition_technique == alert_technique
            return False

        # Evaluate each pattern element
        matches = []
        for element_type, pattern in pattern_elements:
            if element_type == 'process_name':
                pattern = pattern.lower()
                matches.append(pattern in process_name)
            elif element_type == 'cmd_line':
                try:
                    matches.append(bool(re.search(pattern, cmd_line, re.IGNORECASE)))
                except re.error:
                    pattern = pattern.replace('\\\\', '\\').lower()
                    matches.append(pattern.lower() in cmd_line.lower())

        # Apply the pattern logic
        if ' AND ' in self.pattern:
            result = all(matches)
        else:
            result = any(matches)

        return result


class AttackFlow:
    """
    Represents an attack flow with action nodes and condition nodes.
    """

    def __init__(self, flow_id: str, name: str, description: str = None):
        self.id = flow_id
        self.name = name
        self.description = description
        self.nodes: Dict[str, Node] = {}  # All nodes by ID
        self.action_nodes: Dict[str, ActionNode] = {}  # Action nodes by ID
        self.condition_nodes: Dict[str, ConditionNode] = {}  # Condition nodes by ID
        self.start_nodes: List[ActionNode] = []  # Starting nodes

        # Track the current position in the flow
        self.current_position: Optional[Node] = None

        # Track all history with node IDs and timestamps
        self.history: List[Dict[str, Any]] = []

        # Debug mode
        self.debug = True

        # Track which alert activated which nodes
        self.activated_by: Dict[str, str] = {}  # node_id -> alert_id

        # Build a graph of the flow for pathfinding
        self.node_graph: Dict[str, List[str]] = {}  # node_id -> [next_node_ids]

        # Flag to track if we're in a valid sequence
        self.in_valid_sequence = True

    def add_node(self, node: Node) -> Node:
        """Add a node to the flow."""
        self.nodes[node.id] = node
        self.node_graph[node.id] = []

        if isinstance(node, ActionNode):
            self.action_nodes[node.id] = node
        elif isinstance(node, ConditionNode):
            self.condition_nodes[node.id] = node

        return node

    def add_start_node(self, node: Node):
        """Add a starting node to the flow."""
        if node.id not in self.nodes:
            self.add_node(node)

        if isinstance(node, ActionNode):
            self.start_nodes.append(node)
            if self.current_position is None:
                self.current_position = node

    def connect_action_to_next(self, action_id: str, next_id: str):
        """Connect an action node to its next node."""
        action_node = self.action_nodes.get(action_id)
        next_node = self.nodes.get(next_id)

        if action_node and next_node:
            action_node.next_node = next_node
            # Update the graph
            self.node_graph[action_id].append(next_id)

    def resolve_condition_references(self):
        """
        Resolve all condition node references to actual nodes.
        This needs to be called after all nodes are added and before processing alerts.
        """
        for condition_id, condition in self.condition_nodes.items():
            # Resolve true branch references
            condition.true_nodes = []
            for ref_id in condition.true_node_refs:
                if ref_id in self.nodes:
                    condition.true_nodes.append(self.nodes[ref_id])
                    # Update the graph
                    self.node_graph[condition_id].append(ref_id)
                elif self.debug:
                    logger.warning(f"Could not find node {ref_id} for true branch of condition {condition_id}")

            # Resolve false branch references
            condition.false_nodes = []
            for ref_id in condition.false_node_refs:
                if ref_id in self.nodes:
                    condition.false_nodes.append(self.nodes[ref_id])
                    # Update the graph
                    self.node_graph[condition_id].append(ref_id)
                elif self.debug:
                    logger.warning(f"Could not find node {ref_id} for false branch of condition {condition_id}")

    def find_path(self, start_id: str, target_id: str) -> List[str]:
        """Find a path from start_id to target_id in the flow graph."""
        if start_id == target_id:
            return [start_id]

        visited = set()
        queue = [(start_id, [start_id])]

        while queue:
            (node_id, path) = queue.pop(0)
            if node_id not in self.node_graph:
                continue

            for next_id in self.node_graph[node_id]:
                if next_id == target_id:
                    return path + [next_id]
                if next_id not in visited:
                    visited.add(next_id)
                    queue.append((next_id, path + [next_id]))

        return []  # No path found

    def activate_node(self, node: Node, alert_id: str):
        """Set a node as the current position."""
        self.current_position = node
        self.activated_by[node.id] = alert_id

    # Update technique_id_match in AttackFlow class for exact matching only

    def technique_id_match(self, alert_technique_id: str, node_technique_id: str) -> bool:
        """
        Check if an alert's technique ID matches a node's technique ID.
        Modified to only match exact techniques (no parent/child matching).

        Args:
            alert_technique_id: Technique ID from the alert
            node_technique_id: Technique ID from the node

        Returns:
            True if techniques match exactly, False otherwise
        """
        if not alert_technique_id or not node_technique_id:
            return False

        # Exact match only
        exact_match = (alert_technique_id == node_technique_id)

        if exact_match:
            logger.info(f"Exact technique match: {alert_technique_id} == {node_technique_id}")
        else:
            logger.debug(f"No technique match: {alert_technique_id} != {node_technique_id}")

        return exact_match

    def get_valid_accounts_nodes(self) -> List[ActionNode]:
        """Get all action nodes related to Valid Accounts technique."""
        valid_accounts_nodes = []
        for node_id, node in self.action_nodes.items():
            if node.technique_id and (node.technique_id == "T1078" or node.technique_id.startswith("T1078.")):
                valid_accounts_nodes.append(node)
        return valid_accounts_nodes

    def get_preferred_valid_accounts_node(self) -> Optional[ActionNode]:
        """Get the best Valid Accounts node, preferring non-Start State nodes."""
        valid_accounts_nodes = self.get_valid_accounts_nodes()

        # First try to find a dedicated Valid Accounts node (not Start State)
        for node in valid_accounts_nodes:
            if node.name != "Start State" and ("Valid Accounts" in node.name or "Account" in node.name):
                return node

        # If no dedicated node found, take any Valid Accounts node
        for node in valid_accounts_nodes:
            if node.name != "Start State":
                return node

        # If still not found, accept any node including Start State
        return valid_accounts_nodes[0] if valid_accounts_nodes else None

    # Fix get_expected_next_techniques in AttackFlow class

    def get_expected_next_techniques(self) -> List[str]:
        """
        Get the next expected techniques based on current position.
        Fixed to correctly identify the next technique after the current node.

        Returns:
            List of expected technique IDs
        """
        if not self.current_position:
            return []

        expected_techniques = []
        current = self.current_position

        # If current position is the Start State, look at its next condition
        if current.name == "Start State" and isinstance(current, ActionNode) and current.next_node:
            next_condition = current.next_node
            if isinstance(next_condition, ConditionNode):
                # Get technique ID from condition description
                if next_condition.description and next_condition.description.startswith('T'):
                    # Extract the technique ID from the description
                    technique_match = re.match(r'(T\d+(\.\d+)*)', next_condition.description)
                    if technique_match:
                        technique_from_desc = technique_match.group(1)
                        expected_techniques.append(technique_from_desc)
                        logger.info(f"First expected technique from Start State: {technique_from_desc}")
            return expected_techniques

        # If current position is an action node with a next condition
        if isinstance(current, ActionNode) and current.next_node:
            next_condition = current.next_node
            if isinstance(next_condition, ConditionNode):
                # Get technique ID from condition description
                if next_condition.description and next_condition.description.startswith('T'):
                    # Extract the technique ID from the description
                    technique_match = re.match(r'(T\d+(\.\d+)*)', next_condition.description)
                    if technique_match:
                        technique_from_desc = technique_match.group(1)
                        expected_techniques.append(technique_from_desc)
                        logger.info(f"Next expected technique from condition description: {technique_from_desc}")
                        return expected_techniques  # Return immediately with the correct next technique

                # Look at true_nodes if no technique found in description
                if not expected_techniques and next_condition.true_nodes:
                    for node in next_condition.true_nodes:
                        if isinstance(node, ActionNode) and node.technique_id:
                            # Make sure we're not returning the current node's technique
                            if node.technique_id != current.technique_id:
                                expected_techniques.append(node.technique_id)
                                logger.info(f"Next expected technique from true node: {node.technique_id}")
                                break  # Just get the first one

        # If no expected techniques were found and we have a current position,
        # try to follow the graph to find the next node
        if not expected_techniques and self.current_position and isinstance(self.current_position, ActionNode):
            # First get the next condition node
            if self.current_position.next_node and isinstance(self.current_position.next_node, ConditionNode):
                next_condition = self.current_position.next_node

                # Then look at its true branches
                if next_condition.true_nodes:
                    for node in next_condition.true_nodes:
                        if isinstance(node, ActionNode) and node.technique_id:
                            if node.technique_id != self.current_position.technique_id:
                                expected_techniques.append(node.technique_id)
                                logger.info(f"Found next technique through graph traversal: {node.technique_id}")
                                break

        return expected_techniques

    # Complete overhaul of AttackFlow.process_alert for exact technique matching

    def process_alert(self, alert: Dict[str, Any]) -> Tuple[Optional[Node], bool]:
        """
        Process an alert through the attack flow with strict exact matching.
        Completely revised to handle Start State as a pure awaiting state with no technique.

        Args:
            alert: Dictionary with alert details including technique_id

        Returns:
            Tuple of (matched_node, sequence_status_changed)
        """
        technique_id = alert.get('technique_id')
        alert_id = alert.get('id', str(uuid.uuid4()))

        # Log the incoming alert
        logger.info(f"Processing alert with technique: {technique_id}")

        # Track sequence status change
        initial_sequence_status = self.in_valid_sequence

        # If no technique ID, we can't process
        if not technique_id:
            logger.warning("Alert has no technique_id")
            return None, False

        # Make sure all condition references are resolved
        self.resolve_condition_references()

        # Initialize if needed
        if self.current_position is None and self.start_nodes:
            self.current_position = self.start_nodes[0]
            self.in_valid_sequence = True

        if self.current_position is None:
            logger.warning("No current position in flow")
            return None, False

        # Log current state
        current_technique = (self.current_position.technique_id
                             if hasattr(self.current_position, 'technique_id') and self.current_position.technique_id
                             else "None")
        logger.info(f"Current position: {self.current_position.name}, Technique: {current_technique}")

        # EXACT MATCHING APPROACH

        # Special case for Start State
        if self.current_position.name == "Start State":
            logger.info("Currently at Start State, checking for first real node")

            # Find a node with exactly matching technique
            matched_node = None
            for node_id, node in self.action_nodes.items():
                if node.name != "Start State" and node.technique_id == technique_id:
                    matched_node = node
                    logger.info(f"Found matching first node: {node.name}")
                    break

            if matched_node:
                # Record in history
                self.history.append({
                    'timestamp': datetime.now().isoformat(),
                    'node_id': matched_node.id,
                    'node_name': matched_node.name,
                    'technique_id': matched_node.technique_id,
                    'alert': alert,
                    'was_active': True,
                    'event_type': 'first_node',
                    'alert_id': alert_id
                })

                # Move to this node
                self.current_position = matched_node
                self.activated_by[matched_node.id] = alert_id
                return matched_node, True

            # If no match, stay at Start State
            logger.info(f"No match for first node with technique {technique_id}")
            return None, False

        # Case 1: If we're not in a valid sequence, search for exact match to restart
        if not self.in_valid_sequence:
            logger.info("Not in valid sequence, checking for restart point")
            restart_node = None

            # Find node with exactly matching technique, excluding Start State
            for node_id, node in self.action_nodes.items():
                if node.name != "Start State" and node.technique_id == technique_id:
                    restart_node = node
                    logger.info(f"Found restart node: {node.name} with exact technique match {technique_id}")
                    break

            if restart_node:
                # Restart the sequence with this node
                self.current_position = restart_node
                self.in_valid_sequence = True

                # Record in history
                self.history.append({
                    'timestamp': datetime.now().isoformat(),
                    'node_id': restart_node.id,
                    'node_name': restart_node.name,
                    'technique_id': restart_node.technique_id,
                    'alert': alert,
                    'was_active': True,
                    'event_type': 'restart_exact_match',
                    'alert_id': alert_id
                })

                self.activated_by[restart_node.id] = alert_id
                return restart_node, True
            else:
                # No exact match found to restart
                logger.info(f"No exact match found for {technique_id} to restart sequence")
                return None, False

        # Case 2: We're in a valid sequence, evaluate expected next step

        # Get the next node that should match this technique
        if not isinstance(self.current_position, ActionNode):
            logger.warning("Current position is not an action node")
            return None, False

        current_action = self.current_position
        next_node = current_action.next_node

        # If no next node, we're at the end
        if not next_node or not isinstance(next_node, ConditionNode):
            logger.info(f"Current action {current_action.name} has no next condition")
            return None, False

        # Check if this technique matches the expected next technique
        expected_techniques = self.get_expected_next_techniques()
        logger.info(f"Expected next techniques: {expected_techniques}")

        if technique_id not in expected_techniques:
            logger.info(f"Technique {technique_id} is not in expected next techniques {expected_techniques}")
            # Mark sequence as broken
            self.in_valid_sequence = False
            return None, True

        # Evaluate condition
        condition_result = next_node.check_pattern(alert)

        # Record in history
        self.history.append({
            'timestamp': datetime.now().isoformat(),
            'node_id': next_node.id,
            'node_name': next_node.name,
            'pattern': next_node.pattern,
            'result': condition_result,
            'context': alert,
            'alert_id': alert_id
        })

        if condition_result:
            logger.info(f"Alert matches condition {next_node.name}")

            # Find the exact next node with matching technique
            matched_next_node = None

            if next_node.true_nodes:
                for node in next_node.true_nodes:
                    if isinstance(node, ActionNode) and node.technique_id == technique_id:
                        matched_next_node = node
                        logger.info(f"Found exact matching next node: {node.name}")
                        break

            if matched_next_node:
                # Record action
                self.history.append({
                    'timestamp': datetime.now().isoformat(),
                    'node_id': matched_next_node.id,
                    'node_name': matched_next_node.name,
                    'technique_id': matched_next_node.technique_id,
                    'alert': alert,
                    'was_active': True,
                    'alert_id': alert_id
                })

                # Advance to the matched node
                self.current_position = matched_next_node
                self.activated_by[matched_next_node.id] = alert_id
                return matched_next_node, self.in_valid_sequence != initial_sequence_status
            else:
                logger.warning(f"No exact matching node found for technique {technique_id}")

        # If we get here, either condition didn't match or no matching next node
        self.in_valid_sequence = False
        return None, self.in_valid_sequence != initial_sequence_status

    def reset(self):
        """Reset the attack flow to its initial state."""
        if self.start_nodes:
            self.current_position = self.start_nodes[0]
        else:
            self.current_position = None
        self.history = []
        self.activated_by = {}
        self.in_valid_sequence = True
        logger.info("Attack flow reset to initial state")

    def get_next_expected_techniques(self) -> List[str]:
        """
        Helper function to get the correct next expected techniques.
        This function looks ahead in the attack flow to find the next techniques
        after the current position.

        Returns:
            List of technique IDs that are expected next in the flow
        """
        if not self.attack_flow or not self.attack_flow.current_position:
            return []

        current_node = self.attack_flow.current_position

        # If current node is Start State, find any action node that's not Start State
        if current_node.name == "Start State":
            for node_id, node in self.attack_flow.action_nodes.items():
                if node.name != "Start State" and node.technique_id:
                    return [node.technique_id]
            return []

        # If current node is an action node with a next condition
        if hasattr(current_node, 'next_node') and current_node.next_node:
            next_condition = current_node.next_node

            # If next node is a condition, check its description for technique ID
            if isinstance(next_condition, ConditionNode) and next_condition.description:
                technique_match = re.match(r'(T\d+(\.\d+)*)', next_condition.description)
                if technique_match:
                    return [technique_match.group(1)]

            # Check condition's true branches for action nodes
            if isinstance(next_condition, ConditionNode) and hasattr(next_condition, 'true_nodes'):
                for node in next_condition.true_nodes:
                    if hasattr(node,
                               'technique_id') and node.technique_id and node.technique_id != current_node.technique_id:
                        return [node.technique_id]

        # If we got here, try to find any other techniques in the flow
        all_techniques = set()
        for node_id, node in self.attack_flow.action_nodes.items():
            if hasattr(node, 'technique_id') and node.technique_id and node.technique_id != current_node.technique_id:
                all_techniques.add(node.technique_id)

        return list(all_techniques)[:1]

    def print_flow_structure(self):
        """Print the structure of the attack flow for debugging."""
        logger.info(f"\nAttack Flow Structure: {self.name}")
        logger.info("=" * 60)

        # Print all action nodes
        logger.info("Action Nodes:")
        for node_id, node in self.action_nodes.items():
            next_id = node.next_node.id if node.next_node else "None"
            next_name = self.nodes[next_id].name if next_id != "None" else "None"
            logger.info(f"  - {node.name} ({node.technique_id}) → {next_name}")

        # Print all condition nodes
        logger.info("\nCondition Nodes:")
        for node_id, node in self.condition_nodes.items():
            logger.info(f"  - {node.name} ({node.pattern})")
            logger.info(f"    True Refs: {node.true_node_refs}")
            true_nodes = [n.name for n in node.true_nodes] if hasattr(node, 'true_nodes') else []
            logger.info(f"    True Nodes: {true_nodes}")
            logger.info(f"    False Refs: {node.false_node_refs}")
            false_nodes = [n.name for n in node.false_nodes] if hasattr(node, 'false_nodes') else []
            logger.info(f"    False Nodes: {false_nodes}")

        # Print starting nodes
        logger.info("\nStart Nodes:")
        for node in self.start_nodes:
            logger.info(f"  - {node.name} ({node.technique_id})")


class AttackFlowParser:
    # Only showing the modified parts related to Start State

    @staticmethod
    def parse(json_data: Dict) -> AttackFlow:
        """Parse a STIX Attack Flow JSON into our model."""
        # Find the attack-flow object
        attack_flow_obj = None
        for obj in json_data.get('objects', []):
            if obj.get('type') == 'attack-flow':
                attack_flow_obj = obj
                break

        if not attack_flow_obj:
            raise ValueError("No attack-flow object found in the JSON data")

        # Create the AttackFlow
        flow = AttackFlow(
            flow_id=attack_flow_obj.get('id'),
            name=attack_flow_obj.get('name', 'Unnamed Flow'),
            description=attack_flow_obj.get('description')
        )

        # First pass: Create all nodes
        for obj in json_data.get('objects', []):
            obj_type = obj.get('type')

            if obj_type == 'attack-action':
                # Check if this is a Start State node
                is_start_state = obj.get('name') == "Start State"

                # Create the action node
                action_node = ActionNode(
                    node_id=obj['id'],
                    name=obj.get('name', f"Action-{obj['id'][:8]}"),
                    # Don't assign a technique_id to Start State nodes
                    technique_id=None if is_start_state else obj.get('technique_id'),
                    description=obj.get('description')
                )
                flow.add_node(action_node)

            elif obj_type == 'attack-condition':
                condition_node = ConditionNode(
                    node_id=obj['id'],
                    name=obj.get('description', f"Condition-{obj['id'][:8]}"),
                    pattern=obj.get('pattern', ''),
                    description=obj.get('description')
                )

                # Store true/false references
                condition_node.true_node_refs = obj.get('on_true_refs', [])
                condition_node.false_node_refs = obj.get('on_false_refs', [])

                flow.add_node(condition_node)

        # Second pass: Connect nodes
        for obj in json_data.get('objects', []):
            obj_type = obj.get('type')

            if obj_type == 'attack-action' and 'effect_refs' in obj:
                # Connect action to its effect (usually a condition)
                for effect_id in obj['effect_refs']:
                    flow.connect_action_to_next(obj['id'], effect_id)

        # Resolve all condition references to actual nodes
        flow.resolve_condition_references()

        # Set start nodes from the attack flow
        if 'start_refs' in attack_flow_obj and attack_flow_obj['start_refs']:
            for start_ref in attack_flow_obj['start_refs']:
                node = flow.nodes.get(start_ref)
                if node and isinstance(node, ActionNode):
                    # Don't assign a technique ID to Start State nodes
                    if node.name == "Start State":
                        node.technique_id = None
                        logger.info(f"Cleared technique ID for Start State node")

                    flow.add_start_node(node)
                    logger.info(f"Added start node from start_refs: {node.name} with technique {node.technique_id}")
        else:
            # Find nodes with names containing "Start State" if available
            start_node_found = False
            for node_id, node in flow.action_nodes.items():
                if "Start State" in node.name:
                    # Clear any technique ID for Start State
                    node.technique_id = None
                    logger.info(f"Cleared technique ID for Start State node")

                    flow.add_start_node(node)
                    start_node_found = True
                    logger.info(f"Added start node by name 'Start State': {node.name}")
                    break

            # If still no start nodes, use the first action node as a fallback
            if not start_node_found and flow.action_nodes:
                first_node = next(iter(flow.action_nodes.values()))
                flow.add_start_node(first_node)
                logger.info(
                    f"Added first action node as fallback start node: {first_node.name} with technique {first_node.technique_id}")

        # Print confirmation of start nodes
        logger.info("\nStart nodes in the flow:")
        for node in flow.start_nodes:
            logger.info(f"  - {node.name} with technique {node.technique_id}")

        return flow


def load_attack_flow(file_path: str) -> AttackFlow:
    """Load an attack flow from a JSON file."""
    if not os.path.exists(file_path):
        logger.warning(f"Warning: File {file_path} not found.")
        return None

    with open(file_path, 'r') as f:
        data = json.load(f)

    return AttackFlowParser.parse(data)


def simulate_with_alerts(flow: AttackFlow, alerts: List[Dict[str, Any]]):
    """Run a simulation with a sequence of alerts."""
    logger.info(f"\nRunning simulation on flow: {flow.name}")
    logger.info("=" * 60)

    # Print flow structure
    flow.print_flow_structure()

    # Keep track of all alerts, including those that didn't match
    all_alerts_history = []

    # Process each alert
    for i, alert in enumerate(alerts):
        # Ensure alert has an ID
        if 'id' not in alert:
            alert['id'] = f"alert-{i + 1}"

        # Record the current state before processing
        pre_state = {
            'alert': alert,
            'sequence_valid': flow.in_valid_sequence,
            'position': flow.current_position.name if flow.current_position else None,
            'position_technique': flow.current_position.technique_id if flow.current_position and isinstance(
                flow.current_position, ActionNode) else None
        }

        logger.info(f"\nAlert {i + 1}: {alert['technique_id']} - {alert['description']}")
        logger.info("-" * 40)
        logger.info(f"  Sequence state before: {'Valid' if flow.in_valid_sequence else 'Broken'}")
        logger.info(f"  Current position: {flow.current_position.name if flow.current_position else 'None'}")
        if flow.current_position and isinstance(flow.current_position, ActionNode):
            logger.info(f"  Current position technique: {flow.current_position.technique_id}")

        # Process the alert
        matched_node, sequence_status_changed = flow.process_alert(alert)

        # Add to all alerts history
        all_alerts_history.append({
            'timestamp': datetime.now().isoformat(),
            'alert_id': alert['id'],
            'technique_id': alert.get('technique_id'),
            'description': alert.get('description'),
            'matched': matched_node is not None,
            'matched_node': matched_node.name if matched_node else None,
            'position_before': pre_state['position'],
            'position_after': flow.current_position.name if flow.current_position else None,
            'sequence_valid_before': pre_state['sequence_valid'],
            'sequence_valid_after': flow.in_valid_sequence,
            'sequence_changed': sequence_status_changed,
            'is_restart': any(
                event.get('event_type') in ['restart', 'restart_special', 'restart_valid_accounts']
                for event in flow.history[-2:]) if flow.history else False,
            'expected_next': flow.get_expected_next_techniques()
        })

        # Print status after processing
        if matched_node:
            current_pos = flow.current_position
            logger.info(f"  → Matched node: {matched_node.name}")
            logger.info(f"  → Current position: {current_pos.name if current_pos else 'None'}")
            logger.info(f"  → Sequence state after: {'Valid' if flow.in_valid_sequence else 'Broken'}")
            if sequence_status_changed:
                logger.info(f"  → SEQUENCE STATUS CHANGED during this alert processing!")
        else:
            # For non-matching alerts, emphasize that position hasn't changed
            logger.info("  → No nodes matched in sequence")
            logger.info(f"  → Position remained at: {flow.current_position.name if flow.current_position else 'None'}")
            logger.info(f"  → Sequence state after: {'Valid' if flow.in_valid_sequence else 'Broken'}")
            if sequence_status_changed:
                logger.info(f"  → SEQUENCE STATUS CHANGED during this alert processing!")
                logger.info("     (Sequence is now broken, but position remains unchanged until a restart alert)")

            # Check if any node matched out of sequence
            for event in flow.history[-2:]:
                if event.get('event_type') == 'matched_out_of_sequence':
                    logger.info(f"  → Alert matched node {event.get('node_name')} out of sequence")

        # Print expected next techniques
        expected_next = flow.get_expected_next_techniques()
        if expected_next:
            logger.info(f"  → Next expected techniques: {', '.join(expected_next)}")

    # Print the attack path history with better formatting
    logger.info("\nAttack Path History:")
    logger.info("=" * 60)

    # Track which alerts were recorded in the history
    recorded_alert_ids = set()

    # First show the standard history from the flow
    for i, event in enumerate(flow.history):
        if 'alert_id' in event:
            recorded_alert_ids.add(event['alert_id'])

        if 'result' in event:  # Condition node
            result_str = "✓ TRUE" if event['result'] else "✗ FALSE"
            pattern = event.get('pattern', 'No pattern')
            context_technique = event.get('context', {}).get('technique_id', 'unknown')
            alert_id = event.get('alert_id', 'unknown')
            logger.info(
                f"{i + 1}. CONDITION: {event['node_name']} - Pattern: {pattern} - Alert: {context_technique} (ID: {alert_id}) - {result_str}")
        else:  # Action node
            was_active = "Active: True" if event.get('was_active', True) else "Active: False"
            event_type = event.get('event_type', '')
            event_type_str = f" ({event_type.upper()})" if event_type else ""
            alert_id = event.get('alert_id', 'unknown')
            logger.info(
                f"{i + 1}. ACTION: {event['node_name']} ({event['technique_id']}) - {was_active}{event_type_str} - Alert ID: {alert_id}")

    # Now show a complete history including non-matching alerts
    logger.info("\nComplete Alert History (including non-matching alerts):")
    logger.info("=" * 60)

    for i, alert_event in enumerate(all_alerts_history):
        # Get info about this alert
        alert_id = alert_event['alert_id']
        is_in_history = alert_id in recorded_alert_ids

        match_status = "✓ MATCHED" if alert_event['matched'] else "✗ NO MATCH"
        restart = " (RESTART)" if alert_event['is_restart'] else ""
        seq_change = " (SEQ CHANGED)" if alert_event['sequence_changed'] else ""

        # For alerts that broke the sequence, add clear indication
        broke_sequence = " [BROKE SEQUENCE]" if (
                alert_event['sequence_valid_before'] and not alert_event['sequence_valid_after']) else ""

        # For alerts that didn't match, show that position didn't change
        position_info = ""
        if not alert_event['matched']:
            if alert_event['position_before'] == alert_event['position_after']:
                position_info = f" [POSITION UNCHANGED: {alert_event['position_after']}]"
            else:
                position_info = f" [POSITION CHANGED: {alert_event['position_before']} → {alert_event['position_after']}]"

        logger.info(
            f"{i + 1}. ALERT: {alert_event['technique_id']} - {alert_event['description']} - {match_status}{restart}{seq_change}{broke_sequence} - ID: {alert_event['alert_id']}")
        if alert_event['matched']:
            logger.info(f"    → Matched: {alert_event['matched_node']}")
        logger.info(f"    → Sequence: {'Valid' if alert_event['sequence_valid_after'] else 'Broken'}{position_info}")
        if alert_event['expected_next']:
            logger.info(f"    → Next expected: {', '.join(alert_event['expected_next'])}")

    # Print a summary of the entire path traversed
    logger.info("\nAttack Path Summary:")
    logger.info("=" * 60)

    # Extract all action nodes that were activated
    action_history = []
    for event in flow.history:
        if 'was_active' in event and event.get('was_active', True):
            technique_id = event.get('technique_id', 'unknown')
            node_name = event.get('node_name', 'unknown')
            action_history.append(f"{node_name} ({technique_id})")

    # Print the path as a chain
    if action_history:
        logger.info(" → ".join(action_history))
    else:
        logger.info("No actions were activated in this simulation.")


def verify_patterns(flow: AttackFlow):
    """Check all patterns in the flow for potential issues."""
    logger.info("\nVerifying patterns in the flow:")
    logger.info("=" * 60)

    for node_id, node in flow.condition_nodes.items():
        pattern = node.pattern
        match = re.match(r'\[x=([T0-9.]+)\]', pattern)
        if match:
            pattern_id = match.group(1)
            # Check if any action node has this technique ID
            exact_matches = [n for n in flow.action_nodes.values()
                             if n.technique_id and n.technique_id == pattern_id]

            parent_matches = [n for n in flow.action_nodes.values()
                              if n.technique_id and (
                                      n.technique_id.startswith(pattern_id + '.') or
                                      pattern_id.startswith(n.technique_id + '.')
                              )]

            all_matches = exact_matches + [n for n in parent_matches if n not in exact_matches]

            if not all_matches:
                logger.warning(f"Pattern {pattern} in condition {node.name} doesn't match any action node technique ID")
            else:
                logger.info(f"Pattern {pattern} in condition {node.name} matches {len(all_matches)} action nodes")
                # Print the matching action nodes
                for match_node in all_matches:
                    match_type = "exact match" if match_node in exact_matches else "parent/child match"
                    logger.info(f"  - {match_node.name} ({match_node.technique_id}) - {match_type}")
        else:
            logger.warning(f"Pattern '{pattern}' in condition {node.name} doesn't match expected format [x=Txxxx]")


def test_sequence_reset(flow_file: str = 'Resilmesh-RCTI-UberMicroEmulation-19-05-v1.json'):
    """Test the sequence reset functionality with a problematic alert sequence."""
    logger.info("Testing sequence reset functionality")
    logger.info("=" * 50)

    # Load the attack flow
    flow = load_attack_flow(flow_file)

    if not flow:
        logger.error(f"Failed to load attack flow from {flow_file}. Please check the file path.")
        return

    # Define a problematic test sequence:
    # 1. Start with a valid alert (T1078)
    # 2. Continue with a valid alert (T1135)
    # 3. Send an invalid alert that doesn't match any pattern ("WRONG")
    # 4. Send a valid alert that should restart the flow (T1078)
    # 5. Continue with a valid alert in the flow (T1135)
    alerts = [
        {"id": "alert1", "technique_id": "T1078", "description": "Valid Accounts - Initial Access"},
        {"id": "alert2", "technique_id": "T1135", "description": "Network Share Discovery"},
        {"id": "alert3", "technique_id": "WRONG",
         "description": "This alert doesn't match any condition - should break sequence"},
        {"id": "alert4", "technique_id": "T1078", "description": "Valid Accounts again - should restart the sequence"},
        {"id": "alert5", "technique_id": "T1135", "description": "Network Share Discovery - continue after restart"}
    ]

    # Process each alert and print detailed state information
    for i, alert in enumerate(alerts):
        logger.info(f"\n{'=' * 20} Alert {i + 1}: {alert['technique_id']} - {alert['description']} {'=' * 20}")
        logger.info(f"Sequence state before: {'Valid' if flow.in_valid_sequence else 'Broken'}")
        logger.info(f"Current position: {flow.current_position.name if flow.current_position else 'None'}")
        if flow.current_position:
            logger.info(f"Current technique: {flow.current_position.technique_id}")

        # Process the alert
        matched_node, sequence_status_changed = flow.process_alert(alert)

        # Print detailed results
        logger.info(f"\nResults after processing alert {i + 1}:")
        logger.info(f"  Matched node: {matched_node.name if matched_node else 'None'}")
        logger.info(f"  Sequence state: {'Valid' if flow.in_valid_sequence else 'Broken'}")
        logger.info(f"  Sequence status changed: {sequence_status_changed}")
        logger.info(f"  Current position: {flow.current_position.name if flow.current_position else 'None'}")
        if flow.current_position:
            logger.info(f"  Current technique: {flow.current_position.technique_id}")

        # Print expected next techniques
        expected_next = flow.get_expected_next_techniques()
        if expected_next:
            logger.info(f"  Next expected techniques: {', '.join(expected_next)}")

    # Print history for verification
    logger.info("\nFinal Attack Path History:")
    logger.info("=" * 60)
    for i, event in enumerate(flow.history):
        if 'result' in event:  # Condition node
            result_str = "✓ TRUE" if event['result'] else "✗ FALSE"
            pattern = event.get('pattern', 'No pattern')
            context_technique = event.get('context', {}).get('technique_id', 'unknown')
            alert_id = event.get('alert_id', 'unknown')
            logger.info(
                f"{i + 1}. CONDITION: {event['node_name']} - Pattern: {pattern} - Alert: {context_technique} (ID: {alert_id}) - {result_str}")
        else:  # Action node
            was_active = "Active: True" if event.get('was_active', True) else "Active: False"
            event_type = event.get('event_type', '')
            event_type_str = f" ({event_type.upper()})" if event_type else ""
            alert_id = event.get('alert_id', 'unknown')
            logger.info(
                f"{i + 1}. ACTION: {event['node_name']} ({event['technique_id']}) - {was_active}{event_type_str} - Alert ID: {alert_id}")


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info("Attack Flow Sequential Simulator")
    logger.info("=" * 30)

    # Try to load from the JSON file
    flow_file = 'Resilmesh-RCTI-UberMicroEmulation-19-05-v1.json'
    flow = load_attack_flow(flow_file)

    if not flow:
        logger.error(f"Failed to load attack flow from {flow_file}. Please check the file path.")
        return

    # Verify all patterns in the flow
    verify_patterns(flow)

    # Define test alerts - following the complete path in the JSON
    alerts = [
        {"id": "alert1", "technique_id": "T1078", "description": "Default account used"},
        {"id": "alert2", "technique_id": "T1135", "description": "Network shares discovered"},
        {"id": "alert3", "technique_id": "T1046", "description": "Network service scanning"},
        {"id": "alert4", "technique_id": "T1083", "description": "File and Directory Discovery"},
        {"id": "alert5", "technique_id": "T1552.001", "description": "Credential found in file"},
        {"id": "alert6", "technique_id": "T1078", "description": "Valid account used for machine Win4"},
        {"id": "alert7", "technique_id": "T1083", "description": "File enumeration on Win4"},
        {"id": "alert8", "technique_id": "T1005", "description": "Data collected from local system"},
        {"id": "alert9", "technique_id": "T1567.003", "description": "Exfiltration over web service"},

        # Additional test with a break in sequence followed by restart
        {"id": "alert10", "technique_id": "WRONG",
         "description": "This alert doesn't match any condition - should break sequence"},
        {"id": "alert11", "technique_id": "T1078", "description": "Valid Accounts again - should restart the sequence"},
        {"id": "alert12", "technique_id": "T1135", "description": "Network Share Discovery - continue after restart"}
    ]

    # Run the simulation
    simulate_with_alerts(flow, alerts)

    # Test the sequence reset functionality
    logger.info("\n\n=== RUNNING SEQUENCE RESET TEST ===\n")
    test_sequence_reset(flow_file)


if __name__ == "__main__":
    main()