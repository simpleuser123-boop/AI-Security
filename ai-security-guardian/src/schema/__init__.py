"""特征 schema 契约与 model_manifest 校验（R3 / P0）。"""

from .feature_schemas import (
    SCHEMA_IDS,
    attach_network_flow_v1_block,
    validate_payload_against_schema,
)
from .manifest import (
    ManifestLoadError,
    ModelManifest,
    load_manifest_for_model_path,
    validate_manifest_dict,
)
from .nsl_kdd_adapter import NSLKDDAdapter, NSL_KDD_FEATURE_COLUMNS
from .persist import write_model_manifest

__all__ = [
    "SCHEMA_IDS",
    "ModelManifest",
    "ManifestLoadError",
    "load_manifest_for_model_path",
    "validate_manifest_dict",
    "validate_payload_against_schema",
    "attach_network_flow_v1_block",
    "NSLKDDAdapter",
    "NSL_KDD_FEATURE_COLUMNS",
    "write_model_manifest",
]
