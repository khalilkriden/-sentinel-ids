"""
SENTINEL IDS — Flask Application
Network Intrusion Detection System powered by XGBoost (UNSW-NB15)
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import numpy as np
import pandas as pd
import joblib
import os
import logging
import json
import time

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'sentinel-dev-key-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sentinel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('logs/sentinel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ── Database model ────────────────────────────────────────────────────────────
class ScanRecord(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)
    prediction  = db.Column(db.String(50))
    severity    = db.Column(db.String(20))
    confidence  = db.Column(db.Float)
    proto       = db.Column(db.String(10))
    service     = db.Column(db.String(20))
    state       = db.Column(db.String(10))
    sbytes      = db.Column(db.Integer)
    dbytes      = db.Column(db.Integer)
    rate        = db.Column(db.Float)
    input_json  = db.Column(db.Text)
    inference_ms= db.Column(db.Float)

    def to_dict(self):
        return {
            'id':           self.id,
            'timestamp':    self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'prediction':   self.prediction,
            'severity':     self.severity,
            'confidence':   round(self.confidence, 1),
            'proto':        self.proto,
            'service':      self.service,
            'state':        self.state,
            'sbytes':       self.sbytes,
            'dbytes':       self.dbytes,
            'rate':         self.rate,
            'inference_ms': round(self.inference_ms, 2),
        }

# ── Attack metadata ───────────────────────────────────────────────────────────
ATTACK_META = {
    'Normal':         {'severity': 'none',     'color': '#10b981', 'icon': 'shield-check',    'risk': 0},
    'Generic':        {'severity': 'medium',   'color': '#f59e0b', 'icon': 'alert-triangle',  'risk': 40},
    'Exploits':       {'severity': 'high',     'color': '#ef4444', 'icon': 'zap',             'risk': 75},
    'Fuzzers':        {'severity': 'medium',   'color': '#f97316', 'icon': 'shuffle',         'risk': 45},
    'DoS':            {'severity': 'high',     'color': '#dc2626', 'icon': 'wifi-off',        'risk': 80},
    'Reconnaissance': {'severity': 'low',      'color': '#eab308', 'icon': 'search',          'risk': 25},
    'Analysis':       {'severity': 'low',      'color': '#84cc16', 'icon': 'activity',        'risk': 20},
    'Backdoor':       {'severity': 'critical', 'color': '#8b5cf6', 'icon': 'unlock',          'risk': 95},
    'Shellcode':      {'severity': 'high',     'color': '#f43f5e', 'icon': 'terminal',        'risk': 85},
    'Worms':          {'severity': 'critical', 'color': '#7c3aed', 'icon': 'git-branch',      'risk': 92},
}

SEVERITY_ORDER = ['none', 'low', 'medium', 'high', 'critical']

# ── ML Model ──────────────────────────────────────────────────────────────────
class ModelManager:
    def __init__(self):
        self.model    = None
        self.pipeline = None
        self.loaded   = False
        self.mode     = 'demo'
        self._try_load()

    def _try_load(self):
        model_path    = 'models/best_model.pkl'
        pipeline_path = 'data/processed/preprocessing_pipeline.pkl'
        if os.path.exists(model_path) and os.path.exists(pipeline_path):
            try:
                self.model    = joblib.load(model_path)
                self.pipeline = joblib.load(pipeline_path)
                self.loaded   = True
                self.mode     = 'live'
                logger.info('✅ Model loaded successfully — LIVE mode')
            except Exception as e:
                logger.error(f'❌ Failed to load model: {e}')
        else:
            logger.warning('⚠️  Model files not found — DEMO mode active')

    def preprocess(self, data: dict) -> pd.DataFrame:
        SCALER_COLS = self.pipeline['scaler'].feature_names_in_.tolist()
        FINAL_COLS  = self.pipeline['feature_cols_final']

        row = {c: 0 for c in SCALER_COLS}
        row.update(data)
        df = pd.DataFrame([row])

        for col in ['proto', 'service', 'state']:
            df[col] = df[col].astype(str)
            if col in self.pipeline['label_encoders']:
                le  = self.pipeline['label_encoders'][col]
                val = df[col].iloc[0]
                df[col] = le.transform([val])[0] if val in le.classes_ else 0
            else:
                df[col] = 0

        for col, (lo, hi) in self.pipeline.get('cap_limits', {}).items():
            if col in df.columns:
                df[col] = df[col].clip(lower=lo, upper=hi)

        df['bytes_ratio']   = df['sbytes'] / (df['dbytes'] + 1)
        df['total_bytes']   = df['sbytes'] + df['dbytes']
        df['total_pkts']    = df['spkts'] + df['dpkts']
        df['pkts_ratio']    = df['spkts'] / (df['dpkts'] + 1)
        df['bytes_per_pkt'] = df['total_bytes'] / (df['total_pkts'] + 1)
        df['loss_ratio']    = df['sloss'] / (df['spkts'] + 1)
        df['ttl_diff']      = abs(df['sttl'] - df['dttl'])
        df['load_ratio']    = df['sload'] / (df['dload'] + 1)
        df['jit_diff']      = abs(df['sjit'] - df['djit'])
        for col in ['sbytes', 'dbytes', 'rate', 'sload', 'dload']:
            df[f'{col}_log'] = np.log1p(df[col].clip(lower=0))

        df[SCALER_COLS] = self.pipeline['scaler'].transform(df[SCALER_COLS])
        return df[FINAL_COLS]

    def predict(self, data: dict) -> dict:
        t0 = time.perf_counter()

        if self.loaded:
            df    = self.preprocess(data)
            pred  = self.model.predict(df)[0]
            label = self.pipeline['le_target'].inverse_transform([pred])[0]
            probs = {}
            if hasattr(self.model, 'predict_proba'):
                proba   = self.model.predict_proba(df)[0]
                classes = self.pipeline['le_target'].classes_
                probs   = {c: round(float(p) * 100, 1) for c, p in zip(classes, proba)}
            else:
                probs = {label: 100.0}
        else:
            # Heuristic demo
            label, probs = self._demo_predict(data)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        meta       = ATTACK_META.get(label, ATTACK_META['Generic'])
        confidence = probs.get(label, 100.0)
        top_probs  = dict(sorted(probs.items(), key=lambda x: -x[1])[:6])

        return {
            'prediction':   label,
            'severity':     meta['severity'],
            'color':        meta['color'],
            'icon':         meta['icon'],
            'risk_score':   meta['risk'],
            'confidence':   confidence,
            'probabilities':top_probs,
            'inference_ms': elapsed_ms,
            'mode':         self.mode,
        }

    def _demo_predict(self, data):
        sloss  = data.get('sloss', 0)
        rate   = data.get('rate', 0)
        sbytes = data.get('sbytes', 0)
        dpkts  = data.get('dpkts', 0)
        dur    = data.get('dur', 0)

        classes = list(ATTACK_META.keys())
        base    = {c: 1.0 for c in classes}

        if sloss > 50:
            label = 'DoS';            base['DoS'] = 90
        elif rate > 800:
            label = 'Fuzzers';        base['Fuzzers'] = 85
        elif sbytes < 80 and dpkts > 15:
            label = 'Reconnaissance'; base['Reconnaissance'] = 80
        elif dur > 60 and rate < 10:
            label = 'Backdoor';       base['Backdoor'] = 78
        elif sbytes > 20000 and dpkts < 10:
            label = 'Exploits';       base['Exploits'] = 82
        else:
            label = 'Normal';         base['Normal'] = 92

        total = sum(base.values())
        probs = {k: round(v / total * 100, 1) for k, v in base.items()}
        return label, probs


ml = ModelManager()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    stats = _get_stats()
    return render_template('index.html', stats=stats, mode=ml.mode)


@app.route('/history')
def history():
    page    = request.args.get('page', 1, type=int)
    filter_ = request.args.get('severity', 'all')
    q = ScanRecord.query.order_by(ScanRecord.timestamp.desc())
    if filter_ != 'all':
        q = q.filter_by(severity=filter_)
    records = q.paginate(page=page, per_page=20)
    return render_template('history.html', records=records, filter=filter_)


@app.route('/api/predict', methods=['POST'])
def predict():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No JSON body'}), 400

    try:
        result = ml.predict(data)

        # Persist to DB
        meta = ATTACK_META.get(result['prediction'], {})
        rec  = ScanRecord(
            prediction   = result['prediction'],
            severity     = result['severity'],
            confidence   = result['confidence'],
            proto        = data.get('proto', '?'),
            service      = data.get('service', '?'),
            state        = data.get('state', '?'),
            sbytes       = int(data.get('sbytes', 0)),
            dbytes       = int(data.get('dbytes', 0)),
            rate         = float(data.get('rate', 0)),
            input_json   = json.dumps(data),
            inference_ms = result['inference_ms'],
        )
        db.session.add(rec)
        db.session.commit()
        result['scan_id'] = rec.id
        logger.info(f'[SCAN #{rec.id}] {result["prediction"]} ({result["severity"]}) — {result["inference_ms"]:.1f}ms')
        return jsonify(result)

    except Exception as e:
        logger.error(f'Prediction error: {e}')
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
def api_stats():
    return jsonify(_get_stats())


@app.route('/api/history')
def api_history():
    limit   = request.args.get('limit', 50, type=int)
    records = ScanRecord.query.order_by(ScanRecord.timestamp.desc()).limit(limit).all()
    return jsonify([r.to_dict() for r in records])


@app.route('/api/health')
def health():
    return jsonify({
        'status':       'ok',
        'model_loaded': ml.loaded,
        'mode':         ml.mode,
        'total_scans':  ScanRecord.query.count(),
    })


@app.route('/api/clear', methods=['POST'])
def clear_history():
    ScanRecord.query.delete()
    db.session.commit()
    return jsonify({'status': 'cleared'})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_stats():
    total    = ScanRecord.query.count()
    threats  = ScanRecord.query.filter(ScanRecord.severity != 'none').count()
    critical = ScanRecord.query.filter(ScanRecord.severity == 'critical').count()

    # Distribution by class
    dist = {}
    for label in ATTACK_META:
        dist[label] = ScanRecord.query.filter_by(prediction=label).count()

    # Avg inference time
    from sqlalchemy import func
    avg_ms = db.session.query(func.avg(ScanRecord.inference_ms)).scalar() or 0

    # Recent 7 records
    recent = [r.to_dict() for r in
              ScanRecord.query.order_by(ScanRecord.timestamp.desc()).limit(7).all()]

    return {
        'total':    total,
        'threats':  threats,
        'critical': critical,
        'safe':     total - threats,
        'avg_ms':   round(avg_ms, 1),
        'dist':     dist,
        'recent':   recent,
        'attack_meta': ATTACK_META,
    }


# ── Init ──────────────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
