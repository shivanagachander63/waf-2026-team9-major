/**
 * SmartGuard Global Logic
 * Handles form submissions and global UI state
 */

document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('.demo-form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const actionType = this.getAttribute('data-action');
            let payload = "";
            
            // Extract meaningful payload based on scenario
            if (actionType === 'Login') {
                const u = this.querySelector('#login-user').value;
                const p = this.querySelector('#login-pass').value;
                payload = u + " " + p; 
            } else if (actionType === 'Search') {
                payload = this.querySelector('#search-query').value;
            } else if (actionType === 'Comment') {
                payload = this.querySelector('#comment-text').value;
            }
            
            if (!payload.trim()) return;

            // Trigger Loading UI (Live Demo version or Fallback)
            if (window.updateAnalysisUI_Loading) {
                window.updateAnalysisUI_Loading();
            } else {
                updateStandardLoadingUI();
            }

            // Send to Backend
            fetch('/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payload: payload, action_type: actionType })
            })
            .then(async response => {
                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.error || 'Analysis failed.');
                }
                return data;
            })
            .then(data => {
                // Update Result UI (Live Demo version or Fallback)
                if (window.updateAnalysisUI_Result) {
                    window.updateAnalysisUI_Result(data, actionType);
                } else {
                    updateStandardResultUI(data, actionType);
                }
                
                // Final Browser Feedback
                updateBrowserFeedback(data, actionType);
            })
            .catch(err => {
                console.error("SmartGuard Error:", err);
                if (window.resetSimulator) window.resetSimulator();
                alert(err.message || "Error connecting to SmartGuard backend.");
            });
        });
    });
});

// --- Standard UI Fallbacks (Used if not on the Try Now page) ---

function updateStandardLoadingUI() {
    const status = document.getElementById('panel-status');
    const decision = document.getElementById('decision-text');
    if(status) {
        status.innerText = "ANALYZING...";
        status.className = "badge bg-warning animate-pulse";
    }
    if(decision) {
        decision.innerText = "...";
    }
}

function updateStandardResultUI(data, action) {
    const status = document.getElementById('panel-status');
    if(status) {
        status.innerText = "COMPLETE";
        status.className = "badge bg-success";
    }

    const decision = document.getElementById('decision-text');
    const reason = document.getElementById('decision-reason');
    
    if(decision) {
        decision.innerText = data.decision;
        decision.className = data.decision === 'ACCEPTED' ? "text-success" : "text-danger";
    }
    if(reason) {
        reason.innerText = data.decision === 'ACCEPTED' ? "Request Safe." : "Threat Blocked.";
    }

    // Update basic metric fields if they exist
    const fields = {
        'res-action': action,
        'res-type': data.detected_type,
        'res-conf': data.confidence,
        'harm-text': data.harm_text
    };

    for (let id in fields) {
        const el = document.getElementById(id);
        if(el) el.innerText = fields[id];
    }
}

function updateBrowserFeedback(data, action) {
    const fb = document.getElementById('browser-feedback');
    if (!fb) return;
    
    fb.classList.remove('d-none');
    if (data.decision === 'ACCEPTED') {
        fb.className = "mt-4 text-center text-success fw-bold fade-in p-3 bg-success bg-opacity-10 rounded border border-success";
        fb.innerHTML = "<i class='fas fa-check-circle me-2'></i>Validation Passed. Request Safe.";
    } else {
        fb.className = "mt-4 text-center text-danger fw-bold fade-in p-3 bg-danger bg-opacity-10 rounded border border-danger";
        fb.innerHTML = "<i class='fas fa-shield-virus me-2'></i>REQUEST BLOCKED: Threat Signature Detected.";
    }
}

// Helper to set payloads from "Quick Scenarios" buttons
function setPayload(mainInputId, mainText, secText = null) {
    const mainEl = document.getElementById(mainInputId);
    if (mainEl) mainEl.value = mainText;
    if (secText) {
        const passEl = document.getElementById('login-pass');
        if (passEl) passEl.value = secText;
    }
}

// Utility: CSV Export for Dashboard
function exportTableToCSV(filename) {
    const csv = [];
    const rows = document.querySelectorAll("table tr");
    for (let i = 0; i < rows.length; i++) {
        const row = [], cols = rows[i].querySelectorAll("td, th");
        for (let j = 0; j < cols.length; j++) 
            row.push('"' + cols[j].innerText.replace(/"/g, '""') + '"');
        csv.push(row.join(","));
    }
    const csvFile = new Blob([csv.join("\n")], { type: "text/csv" });
    const downloadLink = document.createElement("a");
    downloadLink.download = filename;
    downloadLink.href = window.URL.createObjectURL(csvFile);
    downloadLink.style.display = "none";
    document.body.appendChild(downloadLink);
    downloadLink.click();
}

// Expose functions to window for HTML onclick handlers
window.setPayload = setPayload;
