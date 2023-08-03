from flask import Flask, request, jsonify
import pickle
from feature import FeatureExtraction
import numpy as np

app = Flask(__name__)

# Load the pre-trained model
with open("mlmodel.pkl", "rb") as file:
    model = pickle.load(file)

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url")

    if url is not None:
        obj = FeatureExtraction(url)
        x = np.array([obj.getFeaturesList()])

        # Make predictions using the pre-trained model
        prediction = model.predict(x)[0]
        probabilities = model.predict_proba(x)[0]
        safe_probability = probabilities[0]
        unsafe_probability = probabilities[1]

        result = {
            "url": url,
            "prediction": int(prediction),
            "safe_probability": float(safe_probability),
            "unsafe_probability": float(unsafe_probability)
        }

        return jsonify(result)
    else:
        return jsonify({"error": "URL not provided in the request body"}), 400

if __name__ == "__main__":
    app.run(debug=True)
