from flask import Flask, render_template, request, Response
import joblib
import requests
import threading
import openai
import json

# Load trained model and vectorizer
model = joblib.load('sqli_model_rf.pkl')
vectorizer = joblib.load('vectorizer.pkl')

# Initialize Flask app
app = Flask(__name__)

# Load OpenAI API Key from a file
def load_openai_key():
    with open('../..openai_secret', 'r') as f:
        return f.read().strip()

# Set OpenAI API Key
openai.api_key = load_openai_key()

# Load payloads from a text file
def load_payloads(file_path='payloads.txt'):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

# Function to check if the site is vulnerable
def check_vulnerability(url, payloads, results, progress_callback):
    headers = {"User-Agent": "SQLi Scanner"}
    for idx, payload in enumerate(payloads):
        test_url = f"{url}?payload={requests.utils.quote(payload)}"
        try:
            response = requests.get(test_url, headers=headers, timeout=5)
            # Preprocess and predict using the model
            processed_payload = vectorizer.transform([payload])
            prediction = model.predict(processed_payload)[0]
            result = {
                'payload': payload,
                'status': 'Vulnerable' if prediction == 1 else 'Not Vulnerable',
                'confidence': model.predict_proba(processed_payload)[0][prediction]
            }
            results.append(result)
        except requests.RequestException as e:
            print(f"Error testing {test_url}: {e}")
        
        # Update the progress via callback
        progress_callback(idx + 1, len(payloads))

# Function to generate a vulnerability report from OpenAI
def generate_report(scan_results):
    try:
        prompt = "Generate a detailed SQL injection vulnerability report based on the following findings:\n\n"
        for result in scan_results:
            prompt += f"Payload: {result['payload']}\nStatus: {result['status']}\nConfidence: {result['confidence']:.2f}\n\n"
        
        # Call OpenAI API to generate a report
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=1500,
            temperature=0.7
        )
        return response.choices[0].text.strip()
    except Exception as e:
        return f"Error generating report: {str(e)}"

# SSE endpoint for progress updates
@app.route('/progress')
def progress():
    def generate():
        # Send an initial message to the frontend
        yield f"data: {json.dumps({'progress': 0})}\n\n"

        def progress_callback(current, total):
            progress = (current / total) * 100
            yield f"data: {json.dumps({'progress': progress})}\n\n"
        
        # Simulate a URL scan with payloads (you can replace with your own logic)
        url = "http://example.com"
        payloads = load_payloads()  # Load payloads from file
        results = []
        check_vulnerability(url, payloads, results, progress_callback)

        # After scanning, return the full scan result
        yield f"data: {json.dumps({'progress': 100, 'scan_complete': True})}\n\n"
        
    return Response(generate(), content_type='text/event-stream')

# Route to handle the scanning process
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        payloads = load_payloads()  # Load payloads from file
        results = []
        total_payloads = len(payloads)

        # Define progress_callback here
        def progress_callback(current, total):
            progress = (current / total) * 100
            print(f"Progress: {progress:.2f}%")

        def scan():
            check_vulnerability(url, payloads, results, progress_callback)

            # Once scanning is complete, generate a report using OpenAI
            report = generate_report(results)

            # Return the results and the generated report to the frontend
            return render_template("index.html", vulnerabilities=results, payload_count=total_payloads, report=report)

        # Start scanning in background
        thread = threading.Thread(target=scan)
        thread.start()
        
        # Show progress (optional) while the scan is running
        thread.join()  # Ensure the thread finishes before rendering the result
        return render_template("index.html", vulnerabilities=results, payload_count=total_payloads, report="")

    return render_template("index.html", payload_count=0)

if __name__ == "__main__":
    app.run(debug=True)
