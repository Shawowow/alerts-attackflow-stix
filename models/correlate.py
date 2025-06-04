from stix2patterns.validator import run_validator

# pattern = "[file-object:hashes.md5 = '79054025255fb1a26e4bc422aef54eb4']"
# errors = run_validator(pattern)
# print(errors)

async def find_attackflows(attackflows, technique_id):
    """
    Find first attack action within attackflows that matches the given technique_id.
    """
    matched_attackflows = []
    for attackflow in attackflows:
        for object in attackflow["objects"]:
            if object["type"] == "attack-action" and technique_id in object["technique_id"]: 
                matched_attackflows.append(attackflow)
                break
    return matched_attackflows