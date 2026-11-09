"""Training-fitted categorical preprocessing for NSL-KDD features."""

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder

from ml.dataset import NSLKDDDataset
from ml.schema import CATEGORICAL_FEATURE_INDICES, NUMERIC_FEATURE_INDICES


def create_preprocessor() -> ColumnTransformer:
    """Create an unfitted transformer for the 41 feature columns only."""
    return ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore"),
                list(CATEGORICAL_FEATURE_INDICES),
            ),
            ("numeric", "passthrough", list(NUMERIC_FEATURE_INDICES)),
        ],
        remainder="drop",
    )


def fit_preprocessor(training_data: NSLKDDDataset) -> ColumnTransformer:
    """Fit preprocessing exclusively from the supplied training features."""
    return create_preprocessor().fit(training_data.features)
