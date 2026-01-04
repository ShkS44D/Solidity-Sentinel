from flask import Flask, render_template, request, redirect, url_for
import os
import time
from werkzeug.utils import secure_filename
from scanner.slither_scan import run_slither
from scanner.parser import parse_report, analyze_threats

app = Flask(__name__)

# 1. SECURITY CONFIGURATION
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'sol'}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
# 2. Limit max upload size to 2MB to prevent DoS attacks
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 3. Helper to validate file extension
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_score(summary):
    score = 100
    # STRICT PROFESSIONAL SCORING
    score -= (summary["critical"] * 30)
    score -= (summary["high"] * 15)
    score -= (summary["medium"] * 10)
    score -= (summary["low"] * 5)
    score -= (summary["info"] * 2)
    score -= (summary["gas"] * 1)
    
    return max(0, score)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        start_time = time.time()
        
        # Check if the post request has the file part
        if 'contract' not in request.files:
            return redirect(request.url)
            
        file = request.files["contract"]
        
        # If user does not select file, browser submits an empty part without filename
        if file.filename == '':
            return redirect(request.url)

        # 4. Validate & Sanitize
        if file and allowed_file(file.filename):
            # Sanitize the filename to prevent directory traversal
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # --- SCANNING LOGIC ---
            
            # 1. Run Slither
            report_path = run_slither(file_path)
            slither_findings = parse_report(report_path)
            
            # 2. Analyze Threats & Get Extra Findings
            threats, line_count, threat_findings = analyze_threats(file_path)
            
            # 3. COMBINE ALL FINDINGS (Slither + Threats)
            all_findings = slither_findings + threat_findings
            
            end_time = time.time()
            duration = round(end_time - start_time, 2)

            # 4. Summary Stats
            summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "gas": 0}
            
            for f in all_findings:
                sev = f["severity"]
                if sev in summary: summary[sev] += 1
                else: summary["info"] += 1

            total_issues = sum(summary.values())
            score = calculate_score(summary)

            return render_template(
                "report.html",
                findings=all_findings,
                summary=summary,
                filename=filename, # Passes the clean, secure filename
                score=score,
                threats=threats,
                duration=duration,
                lines=line_count,
                total_issues=total_issues
            )
        else:
            # If file is not allowed (e.g. .txt or .exe), just reload the page safely
            return redirect(request.url)

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)