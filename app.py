from flask import Flask, render_template, request
import pandas as pd
import pickle
from feature_extraction import extract_features

app = Flask(__name__)

with open("model_phishing_webpage_classifer.pkl", "rb") as file:
    model = pickle.load(file)

@app.route('/', methods=['GET', 'POST'])
def index():
    result_text = None  
    if request.method == 'POST':
        
        url = request.form.get('url')

        features = extract_features(url)
        feature_names = feature_names = [
            'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_qm', 'nb_eq', 'nb_slash',
            'nb_www', 'ratio_digits_url', 'ratio_digits_host', 'tld_in_subdomain',
            'prefix_suffix', 'shortest_word_host', 'longest_words_raw', 'longest_word_path',
            'phish_hints', 'nb_hyperlinks', 'ratio_intHyperlinks', 'empty_title',
            'domain_in_title', 'domain_age', 'google_index', 'page_rank'
        ]

        data = pd.DataFrame([features], columns=feature_names)

        prediction = model.predict(data)[0]

        if prediction == 1:
            result_text = "Not Safe"
        else:
            result_text = "Safe"

    return render_template('index.html', result=result_text)

if __name__ == '__main__':
    app.run(debug=True)
