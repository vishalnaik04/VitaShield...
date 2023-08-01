from flask import Flask, request, jsonify
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
import pickle

warnings.filterwarnings('ignore')
from feature import FeatureExtraction

file = open("model.pkl", "rb")
gbc = pickle.load(file)
file.close()

app = Flask(__name__)

@app.route("/", methods=["POST"])
def detect_phishing():
    if request.is_json:
        data = request.get_json()
        url = data.get('url')
        if url is not None:
            obj = FeatureExtraction(url)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)

            y_pred = int(gbc.predict(x)[0])  # Convert the prediction to a standard Python integer
            y_pro_phishing = float(gbc.predict_proba(x)[0, 0])  # Convert the probability to a standard Python float
            y_pro_non_phishing = float(gbc.predict_proba(x)[0, 1])  # Convert the probability to a standard Python float

            result = {
                'url': url,
                'prediction': y_pred,
                'safe_probability': y_pro_phishing,
                'unsafe_probability': y_pro_non_phishing
            }
            return jsonify(result)
        else:
            return jsonify({'error': 'URL not provided in the request body'}), 400
    else:
        return jsonify({'error': 'Invalid Content-Type. Expected application/json'}), 415

if __name__ == "__main__":
    app.run(debug=True, port=2002)