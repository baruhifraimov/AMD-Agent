"""Tests for model continuation."""

import numpy as np
import pytest
from src.ml.classifier import continue_training, _fit_lightgbm
from unittest.mock import MagicMock, patch

@patch("src.ml.classifier._fit_lightgbm")
@patch("src.ml.classifier._save_bundle_dict")
@patch("src.ml.classifier.load_bundle")
def test_continue_training(mock_load, mock_save, mock_fit):
    X_train = np.random.normal(size=(100, 10))
    y_train = np.array([0]*50 + [1]*50)
    X_val = np.random.normal(size=(20, 10))
    y_val = np.array([0]*10 + [1]*10)
    
    mock_booster = MagicMock()
    mock_booster.num_trees.return_value = 150
    
    old_model = MagicMock()
    old_model.booster_ = mock_booster
    old_model.get_params.return_value = {"n_estimators": 150, "learning_rate": 0.05}
    
    old_bundle = {
        "model": old_model,
        "selected_feature_indices": list(range(10)),
        "selected_feature_names": [f"f{i}" for i in range(10)],
        "threshold": 0.5,
    }
    
    # Return something dummy from load_bundle to signal success
    mock_load.return_value = old_bundle
    
    with patch("src.config.CONTINUATION_TREES", 50), \
         patch("src.config.MAX_TOTAL_TREES", 500):
         
        bundle = continue_training(X_train, y_train, X_val, y_val, old_bundle=old_bundle)
        
    assert mock_fit.called
    kwargs = mock_fit.call_args.kwargs
    assert kwargs["init_model"] == old_model
    
    new_model = mock_fit.call_args.args[0]
    assert new_model.n_estimators == 200  # 150 + 50
    
    assert mock_save.called
