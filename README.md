# Phishing URL Detector

This is a web application for detecting phishing URLs. It allows users to enter a URL, and it uses a machine learning model(I've used Random Forest classifier) to determine whether the URL is safe or potentially a phishing site.

## Features

- URL input form for users to enter URLs for analysis.
- Machine learning model for URL classification.
- Real-time result display with color-coded notifications.

![1](https://github.com/Mohd-Daniyal/Phishing-sites-detector/assets/96229438/78c86b11-80a2-4688-b769-5d1f91d2d84b)

![2](https://github.com/Mohd-Daniyal/Phishing-sites-detector/assets/96229438/5124f59a-000c-4228-b525-ad5bc89a2c2c)


## Prerequisites

Before you begin, ensure you have met the following requirements:

- Python 3.11
- Flask web framework
- scikit-learn for machine learning
- Other required Python libraries (specified in requirements.txt)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/phishing-url-detector.git
   ```

2. Install the required Python packages:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:

   ```bash
   python app.py
   ```

2. Open your web browser and navigate to `http://localhost:5000` to access the application.

3. Enter a URL in the input field and click "Detect."

## Configuration

- The machine learning model can be configured and trained with your dataset.
- You can customize the CSS, JavaScript, and HTML templates to match your design preferences.

## Contributing

1. Fork the project.
2. Create your feature branch: `git checkout -b feature/your-feature-name`.
3. Commit your changes: `git commit -m 'Add some feature'`.
4. Push to the branch: `git push origin feature/your-feature-name`.
5. Submit a pull request.
