from stix2 import CustomObject, properties
from stix2 import ExtensionDefinition, Identity

"""
  This module defines required STIX contents 
  And custom STIX objects based on the schema definitions described in https://github.com/opencybersecurityalliance/oca-iob/tree/main/apl_reference_implementation_bundle/revision_3/schemas
"""

identity = Identity(
    name = "Resilmesh Project",
)

"""Custom SDOs"""

@CustomObject('x-oca-behavior', [
    ('name', properties.StringProperty(required=True)),
    ('description', properties.StringProperty()),
    ('behavior_class', properties.StringProperty(required=True)),
    ('tatic', properties.StringProperty()),
    ('technique', properties.StringProperty()),
    ('first_seen', properties.TimestampProperty(precision='millisecond')),
    ('platforms', properties.ListProperty(properties.StringProperty())),
    ]
)
class Behavior(object):
    """
    Custom SDO for OCA Behavior
    """
    pass

@CustomObject('x-oca-detection', [
    ('name', properties.StringProperty(required=True)),
    ('data_sources', properties.ListProperty(properties.DictionaryProperty(), required=True)),
    ('analytic', properties.DictionaryProperty(
        ('rule', properties.StringProperty(required=True)),
        ('type', properties.StringProperty(required=True)),
    )),
    ]
)
class Detection(object):
    """
    Custom SDO for OCA Detection
    """
    pass

@CustomObject('x-oca-detector', [
    ('name', properties.StringProperty(required=True)),
    ('description', properties.StringProperty()),
    ('cpe', properties.StringProperty()),
    ('valid_until', properties.TimestampProperty(precision='millisecond')),
    ('vendor', properties.StringProperty()),
    ('vendor_url', properties.StringProperty()),
    ('product', properties.StringProperty()),
    ('product_url', properties.StringProperty()),
    ('detection_types', properties.ListProperty(properties.StringProperty())),
    ('detector_data_categories', properties.ListProperty(properties.StringProperty())),
    ('detector_data_sources', properties.ListProperty(properties.StringProperty())),
    ]
)
class Detector(object):
    """
    Custom SDO for OCA Detector
    """
    pass

@CustomObject('x-oca-asset', [
    ('name', properties.StringProperty(required=True)),
])
class Asset(object):
    """
    Custom SDO for OCA Asset
    """
    pass

"""Custom Extension Definitions"""

behavior_extension = ExtensionDefinition (
    created_by_ref = identity.id,
    name = "x-oca-behavior Extension Definition",
    description = "This schema creates a new object type called x-oca-behavior. x-oca-behavior objects describe higher-level functionality than can be described using SCOs.",
    schema = "https://raw.githubusercontent.com/opencybersecurityalliance/stix-extensions/main/2.x/schemas/x-oca-behavior.json",
    version = "1.0.0",
    extension_types= [
        "new-sdo"
    ]
)

detector_extension = ExtensionDefinition (
    created_by_ref = identity.id,
    name= "x-oca-detector Extension Definition",
    description = "This schema creates a new object type called detector, which describes software that is capable of performing detections.",
    schema = "https://raw.githubusercontent.com/opencybersecurityalliance/stix-extensions/main/2.x/schemas/x-oca-detector.json",
    version = "1.0.0",
    extension_types = [
        "new-sdo"
    ]
)

detection_extension = ExtensionDefinition (
    created_by_ref = identity.id,
    name= "x-oca-detection Extension Definition",
    description = "This schema creates a new object type called detection, which contain queries or other actionable information that can identify an event or behavior.",
    schema = "https://raw.githubusercontent.com/opencybersecurityalliance/stix-extensions/main/2.x/schemas/x-oca-detection.json",
    version = "1.0.0",
    extension_types = [
        "new-sdo"
    ]
)

asset_extension = ExtensionDefinition (
    created_by_ref = identity.id,
    name= "x-oca-asset Extension Definition",
    description = "This schema creates a new object type called x-oca-asset.",
    schema = "TBD",
    version = "1.0.0",
    extension_types = [
        "new-sdo"
    ]
)
