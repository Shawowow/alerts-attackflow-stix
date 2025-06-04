from original.config import *
import json as json_module
from typing import Dict, Any, List, Tuple, Optional
import re
# ===============================
# Correlation Engine Code
# ===============================

class CorrelationEngine:
    def __init__(self, rules_file: str = RULES_FILE):
        """
        Initialize the correlation engine with rules from a file

        Args:
            rules_file: Path to JSON file containing correlation rules
        """
        self.rules_file = rules_file
        self.correlation_rules = {}
        self.load_rules()

    def load_rules(self) -> None:
        """Load correlation rules from JSON file"""
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    self.correlation_rules = json_module.load(f)
                logger.info(f"Loaded {len(self.correlation_rules)} rules from {self.rules_file}")
            else:
                logger.warning(f"Rules file {self.rules_file} not found, starting with empty rules")
                self.correlation_rules = {}
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            self.correlation_rules = {}

    def parse_stix_pattern(self, pattern: str) -> List[Tuple[str, str, str]]:
        """
        Parse simple STIX pattern into components

        Args:
            pattern: STIX pattern string

        Returns:
            List of tuples containing (object_path, operator, value)
        """
        expressions = []
        # Extract expressions between square brackets
        pattern_parts = re.findall(r'\[(.*?)\]', pattern)

        for part in pattern_parts:
            # Split by OR
            or_conditions = part.split(' OR ')
            for condition in or_conditions:
                # Check for AND conditions
                and_conditions = condition.split(' AND ')
                for subcondition in and_conditions:
                    # Parse each condition (object:property OPERATOR 'value')
                    match = re.match(r'([\w:._]+)\s+(MATCHES|=|IN|LIKE|>|<|>=|<=)\s+\'(.*?)\'', subcondition.strip())
                    if match:
                        stix_path, operator, value = match.groups()
                        expressions.append((stix_path, operator, value))

        return expressions

    def parse_stix_pattern_json(self, pattern_obj: Dict) -> List[Tuple[str, str, str]]:
        """
        Parse STIX pattern object (JSON format) into components

        Args:
            pattern_obj: STIX pattern object

        Returns:
            List of tuples containing (object_path, operator, value)
        """
        expressions = []
        
        def process_operand(operand):
            if "field" in operand:
                # This is a leaf condition
                expressions.append((
                    operand["field"], 
                    operand["match_type"], 
                    operand["value"]
                ))
            elif "operator" in operand and "operands" in operand:
                # This is a branch with sub-conditions
                for sub_operand in operand["operands"]:
                    process_operand(sub_operand)
        
        # Start processing from the root
        if "operator" in pattern_obj and "operands" in pattern_obj:
            for operand in pattern_obj["operands"]:
                process_operand(operand)
        
        return expressions

    def map_stix_to_wazuh(self, stix_path: str) -> Optional[str]:
        """
        Map STIX object path to Wazuh alert field

        Args:
            stix_path: STIX object path (e.g., "process:name")

        Returns:
            Corresponding Wazuh field path or None if no mapping exists
        """
        # Mapping between STIX paths and Wazuh alert fields
        mapping = {
            "process:creator_ref.name": "data.win.eventdata.parentImage",
            "process:name": "data.win.eventdata.image",
            "file:name": "data.win.eventdata.targetFilename",
            "process:command_line": "data.win.eventdata.commandLine",
            "user:user_id": "data.win.eventdata.userId",
            "network-traffic:dst_ref.value": "data.srcip",
            "network-traffic:src_ref.value": "data.dstip",
            "network-traffic:dst_port": "data.dstport",
            "network-traffic:src_port": "data.srcport",
            # Add more mappings as needed
        }
        return mapping.get(stix_path)

    def get_nested_value(self, dictionary: Dict, path: str) -> Any:
        """
        Extract a value from a nested dictionary using dot notation

        Args:
            dictionary: Nested dictionary
            path: Path using dot notation (e.g., "data.win.eventdata.image")

        Returns:
            Value at the path or None if not found
        """
        value = dictionary
        for key in path.split('.'):
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value

    def apply_stix_operator(self, operator: str, pattern: str, value: Any) -> bool:
        """
        Apply STIX operator logic to compare values

        Args:
            operator: STIX operator (e.g., "MATCHES", "=")
            pattern: Pattern value
            value: Event value to check

        Returns:
            True if the condition is met, False otherwise
        """
        if value is None:
            return False

        value_str = str(value)

        if operator == "MATCHES":
            return bool(re.search(pattern, value_str, re.IGNORECASE))
        elif operator == "=":
            return value_str == pattern
        elif operator == "IN":
            return value_str in pattern
        elif operator == ">":
            try:
                return float(value_str) > float(pattern)
            except ValueError:
                return False
        elif operator == "<":
            try:
                return float(value_str) < float(pattern)
            except ValueError:
                return False
        elif operator == ">=":
            try:
                return float(value_str) >= float(pattern)
            except ValueError:
                return False
        elif operator == "<=":
            try:
                return float(value_str) <= float(pattern)
            except ValueError:
                return False
        # Add more operators as needed
        return False

    def evaluate_pattern_json(self, wazuh_event: Dict, pattern_obj: Dict) -> bool:
        """
        Evaluate a JSON-based STIX pattern against a Wazuh event

        Args:
            wazuh_event: Wazuh alert data
            pattern_obj: STIX pattern object

        Returns:
            True if the event matches the pattern, False otherwise
        """
        # If this is a leaf condition
        if "field" in pattern_obj:
            field = pattern_obj["field"]
            match_type = pattern_obj["match_type"]
            pattern_value = pattern_obj["value"]
            
            wazuh_field = self.map_stix_to_wazuh(field)
            if not wazuh_field:
                debug_print(f"No mapping found for {field}")
                return False
                
            event_value = self.get_nested_value(wazuh_event, wazuh_field)
            debug_print(f"Event value for {wazuh_field}: {event_value}")
            
            return self.apply_stix_operator(match_type, pattern_value, event_value)
            
        # If this is a branch with sub-conditions
        elif "operator" in pattern_obj and "operands" in pattern_obj:
            operator = pattern_obj["operator"]
            operands = pattern_obj["operands"]
            
            results = [self.evaluate_pattern_json(wazuh_event, operand) for operand in operands]
            
            if operator == "AND":
                return all(results)
            elif operator == "OR":
                return any(results)
            else:
                logger.warning(f"Unknown operator: {operator}")
                return False
                
        return False

    def matches_stix_pattern(self, wazuh_event: Dict, stix_pattern: Any) -> bool:
        """
        Check if a Wazuh event matches a STIX pattern

        Args:
            wazuh_event: Wazuh alert data
            stix_pattern: STIX pattern (string or object)

        Returns:
            True if the event matches the pattern, False otherwise
        """
        try:
            # If stix_pattern is a string, use the old parser
            if isinstance(stix_pattern, str):
                # Parse pattern
                parsed_components = self.parse_stix_pattern(stix_pattern)
                debug_print(f"Parsed STIX components: {parsed_components}")

                # Apply AND logic between different brackets in the pattern
                # and OR logic within brackets
                pattern_parts = re.findall(r'\[(.*?)\]', stix_pattern)
                debug_print(f"Pattern parts: {pattern_parts}")

                results = []

                # For each bracket group
                for i, part in enumerate(pattern_parts):
                    debug_print(f"Processing pattern part: [{part}]")
                    current_part_results = []

                    # Get conditions for this part - simplified approach for debugging
                    part_conditions = []
                    for stix_path, operator, pattern_value in parsed_components:
                        if stix_path in part:
                            part_conditions.append((stix_path, operator, pattern_value))

                    debug_print(f"Conditions for this part: {part_conditions}")

                    # For each condition in this group
                    for stix_path, operator, pattern_value in part_conditions:
                        wazuh_field = self.map_stix_to_wazuh(stix_path)
                        debug_print(f"Mapped {stix_path} to Wazuh field: {wazuh_field}")

                        if not wazuh_field:
                            debug_print(f"No mapping found for {stix_path}")
                            continue

                        # Get value from event
                        event_value = self.get_nested_value(wazuh_event, wazuh_field)
                        debug_print(f"Event value for {wazuh_field}: {event_value}")

                        match_result = self.apply_stix_operator(operator, pattern_value, event_value)
                        debug_print(f"Match result for {operator} '{pattern_value}' with '{event_value}': {match_result}")

                        current_part_results.append(match_result)

                    # OR logic within brackets - any condition can match
                    part_result = any(current_part_results) if current_part_results else False
                    debug_print(f"Result for part {i+1}: {part_result}")
                    results.append(part_result)

                # AND logic between brackets - all bracket groups must match
                final_result = all(results)
                debug_print(f"Final pattern match result: {final_result}")
                return final_result
            
            # If stix_pattern is a dict, use the new JSON parser
            elif isinstance(stix_pattern, dict):
                return self.evaluate_pattern_json(wazuh_event, stix_pattern)
            
            else:
                logger.error(f"Unsupported STIX pattern type: {type(stix_pattern)}")
                return False

        except Exception as e:
            import traceback
            logger.error(f"Error matching STIX pattern: {e}")
            if DEBUG:
                logger.debug(traceback.format_exc())
            return False

    def correlate_event(self, wazuh_event: Dict) -> List[Dict]:
        """
        Check a Wazuh event against all correlation rules

        Args:
            wazuh_event: Wazuh alert data

        Returns:
            List of matching rule information
        """
        matching_rules = []

        # Phase 1: MITRE technique ID matching
        event_techniques = wazuh_event.get("rule", {}).get("mitre", {}).get("id", [])
        if not event_techniques:
            debug_print("No MITRE techniques found in event")
            return matching_rules

        debug_print(f"Event techniques: {event_techniques}")
        debug_print(f"Available rules: {list(self.correlation_rules.keys())}")

        # For each rule, check if techniques match
        for rule_id, rule in self.correlation_rules.items():
            debug_print(f"\nChecking rule {rule_id}: {rule['name']}")
            debug_print(f"Rule techniques: {rule['techniques']}")

            # Check if any technique in the event matches any technique in the rule
            technique_match = False
            for event_tech in event_techniques:
                for rule_tech in rule["techniques"]:
                    # Check for exact match or if event technique is a sub-technique of rule technique
                    if event_tech == rule_tech or (event_tech.startswith(rule_tech + ".")):
                        technique_match = True
                        debug_print(f"Technique match found: {event_tech} matches {rule_tech}")
                        break
                if technique_match:
                    break

            # If any technique matches, proceed to phase 2
            if technique_match:
                debug_print(f"Phase 1 passed for rule {rule_id}")
                debug_print(f"Checking STIX pattern: {rule['stix_pattern']}")

                # Phase 2: Field-specific matching with STIX pattern
                if self.matches_stix_pattern(wazuh_event, rule["stix_pattern"]):
                    debug_print(f"Phase 2 passed for rule {rule_id}")
                    matching_rules.append({
                        "rule_id": rule_id,
                        "rule_name": rule["name"],
                        "techniques": rule["techniques"]
                    })
                else:
                    debug_print(f"Phase 2 failed for rule {rule_id}")
            else:
                debug_print(f"No technique match for rule {rule_id}")

        return matching_rules

    # Add to correlate.py - Explicit implementation of checkTechniqueMatch_req

    # Updated check_technique_match method for correlate.py

    def check_technique_match(self, technique_id: str) -> Dict[str, Any]:
        """
        Check if a technique ID is valid, regardless of whether it matches rules.
        This implements the 'checkTechniqueMatch_req' function from the sequence chart.

        Args:
            technique_id: The MITRE ATT&CK technique ID to check

        Returns:
            Dictionary with the result of the technique check
        """
        if not technique_id:
            return {
                "status": "error",
                "message": "No technique ID provided",
                "is_valid_technique": False
            }

        # Just verify if this is a valid technique ID format
        # We're not checking against rules here, just validating the format
        pattern = r'^T\d+(\.\d+)*$'  # T followed by digits, optionally followed by .digits
        is_valid = bool(re.match(pattern, technique_id))

        # For logging purposes, also find which rules (if any) match this technique
        matching_rules = []
        for rule_id, rule in self.correlation_rules.items():
            for rule_tech in rule.get("techniques", []):
                if technique_id == rule_tech or (technique_id.startswith(rule_tech + ".")):
                    matching_rules.append({
                        "rule_id": rule_id,
                        "rule_name": rule.get("name", "Unnamed Rule"),
                        "technique": rule_tech
                    })
                    break

        return {
            "status": "success",
            "technique_id": technique_id,
            "is_valid_technique": is_valid,
            "matches_any_rules": len(matching_rules) > 0,
            "matching_rules": matching_rules,
            "rule_count": len(matching_rules)
        }