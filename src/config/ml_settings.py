"""ML training, drift, MADAR, evaluation, and feature version constants."""

# --- Training sample counts and fetch limits ---

REPLAY_BUDGET = 3000
MIN_TRAIN_MALWARE = 25
MIN_TRAIN_BENIGN = 25
PE_FETCH_LIMIT = 25
THRESHOLD_RETRAIN_MIN_NEW_SAMPLES = 50  # retrain when N untrained featured samples accumulate

# --- Classifier hyperparameters (Optuna / feature selection) ---

FEATURE_SELECTION_K = 384
OPTUNA_TRIALS = 25
OPTUNA_TIMEOUT = 300
REPLAY_FRACTION = 0.3  # DEPRECATED

# --- Concept drift (ADWIN + multivariate shift) ---

ADWIN_DELTA = 0.002
DRIFT_WINDOW_DAYS = 0  # 0 = disable time pruning
DRIFT_MIN_WINDOW_SAMPLES = 20
DRIFT_MEAN_SHIFT_THRESHOLD = 1.5
DRIFT_CORR_SHIFT_THRESHOLD = 0.35

# --- MADAR replay and LightGBM continuation ---

MADAR_CONTAMINATION = 0.1
MADAR_ANOMALOUS_RATIO = 0.5
MADAR_CLASS_RATIO = 0.5
MADAR_BUDGET_STRATEGY = "ratio"
CONTINUATION_TREES = 50
MAX_TOTAL_TREES = 500
MODEL_ARCHIVE_DEPTH = 5

# --- Static feature vector schema version ---

FEATURE_SET_VERSION = "ember_static_v1"
FEATURE_DIM = 2304

# --- Evaluation (TESSERACT cadence) ---

EVAL_EVERY_RUNS = 10
EVAL_SKIP_BOOTSTRAP = True
TESSERACT_MIXED_UNTIL_HEALTHY = True

# --- FPR tier input (see src/ml/thresholds.py for targets) ---

MIN_BENIGN_FOR_FPR = MIN_TRAIN_BENIGN
