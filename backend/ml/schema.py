"""Canonical column definitions for the headerless NSL-KDD dataset."""

FEATURE_SCHEMA_VERSION = "1.0.0"

FEATURE_NAMES = (
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
)

CATEGORICAL_FEATURES = ("protocol_type", "service", "flag")
NUMERIC_FEATURES = tuple(
    name for name in FEATURE_NAMES if name not in CATEGORICAL_FEATURES
)
ORIGINAL_ATTACK_LABEL_COLUMN = "attack_label"
DIFFICULTY_COLUMN = "difficulty"
COLUMN_NAMES = FEATURE_NAMES + (
    ORIGINAL_ATTACK_LABEL_COLUMN,
    DIFFICULTY_COLUMN,
)

CATEGORICAL_FEATURE_INDICES = tuple(
    FEATURE_NAMES.index(name) for name in CATEGORICAL_FEATURES
)
NUMERIC_FEATURE_INDICES = tuple(
    index for index, name in enumerate(FEATURE_NAMES) if name in NUMERIC_FEATURES
)
