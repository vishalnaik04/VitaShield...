# Import the necessary libraries
from flask import Flask, request, jsonify
import numpy as np
import warnings
import pickle
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

# Load the model from the pickle file
file = open("mlmodel.pkl", "rb")
gbc = pickle.load(file)
file.close()

# Create the Flask app
app = Flask(__name__)

@app.route("/", methods=["POST"])
def detect_phishing():
    if request.is_json:
        try:
            data = request.get_json()
            url = data.get('url')
            if url is not None:
                obj = FeatureExtraction(url)
                x = np.array(obj.getFeaturesList()).reshape(1, 30)

                # Check if gbc is a GradientBoostingClassifier
                if hasattr(gbc, 'predict') and hasattr(gbc, 'predict_proba'):
                    y_pred = int(gbc.predict(x)[0])  # Convert the prediction to a standard Python integer
                    y_pro_phishing = float(gbc.predict_proba(x)[0, 0])  # Convert the probability to a float
                    y_pro_non_phishing = float(gbc.predict_proba(x)[0, 1])  # Convert the probability to a float

                    result = {
                        'url': url,
                        'prediction': y_pred,
                        'safe_probability': y_pro_phishing,
                        'unsafe_probability': y_pro_non_phishing
                    }
                    return jsonify(result)
                else:
                    return jsonify({'error': 'Invalid model. Expected a GradientBoostingClassifier model'}), 500
            else:
                return jsonify({'error': 'URL not provided in the request body'}), 400
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Invalid Content-Type. Expected application/json'}), 415

if __name__ == "__main__":
    # Run the app, listening on all available network interfaces (0.0.0.0) on port 2002
    app.run(debug=True, host='0.0.0.0', port=2002)
