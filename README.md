# 🎣 Intelligent PhishMail Analyzer

> **AI-Powered Email Phishing Detection & Threat Analyzer**  
> Scan email headers, body, and metadata — detect phishing threats using ML pattern matching and AI reasoning.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-medo.dev-00ff88?style=for-the-badge&logo=vercel&logoColor=black)](https://medo.dev)
[![Powered by Claude](https://img.shields.io/badge/Powered%20by-Claude%20AI-orange?style=for-the-badge)](https://anthropic.com)
[![ML Powered](https://img.shields.io/badge/ML-Threat%20Patterns-red?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)]()

---

## 🔗 Live Preview

**[→ Open Intelligent PhishMail Analyzer](#)** ← *(replace with your Medo link)*

---

## 📖 What is Intelligent PhishMail Analyzer?

Intelligent PhishMail Analyzer is an intelligent email phishing detection tool that analyzes raw email content — headers, body, links, and metadata — to identify phishing attempts, social engineering tactics, and malicious patterns.

Paste any email into the analyzer and the AI cross-references it against known phishing signatures, ML-trained threat patterns from historical vulnerabilities, and live heuristic checks to give you a full threat assessment in seconds.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📧 **Header Analysis** | Parses SPF, DKIM, DMARC, Reply-To mismatches, and forged sender fields |
| 🧠 **AI Threat Reasoning** | Claude analyzes language, urgency tactics, and social engineering signals |
| 🗄️ **ML Pattern Matching** | Cross-references against a database of known phishing vulnerability patterns |
| 🔗 **Link Scanner** | Detects suspicious URLs, redirect chains, lookalike domains, and homograph attacks |
| 📊 **Threat Score** | Outputs a 0–100 risk score with severity classification |
| 🚨 **Threat Breakdown** | Lists every detected indicator with category, severity, and explanation |
| 📋 **Full Report** | Generates a structured analysis report for every scanned email |
| ⚡ **Instant Results** | No upload, no login — paste and scan |

---

## 🔍 What Gets Analyzed

### Email Header Checks
```
✓ From / Reply-To mismatch detection
✓ SPF record validation (pass / fail / softfail)
✓ DKIM signature verification
✓ DMARC policy alignment
✓ Received-from chain anomalies
✓ X-Originating-IP geolocation flags
✓ Message-ID format irregularities
✓ Unusual mail server hops
```

### Body & Content Analysis
```
✓ Urgency and fear-based language detection
✓ Impersonation of trusted brands (banks, Microsoft, PayPal, etc.)
✓ Suspicious call-to-action phrases
✓ Credential harvesting patterns
✓ Lookalike domain detection in links
✓ Hidden redirects and URL shorteners
✓ Attachment threat indicators
✓ Homograph / punycode domain attacks
```

### ML Threat Pattern Database
```
✓ Historical phishing campaign signatures
✓ Known malicious sender patterns
✓ Previously flagged subject line templates
✓ Exploit payload indicators
✓ Zero-day phishing technique patterns
```

---

## 🧠 How It Works

```
Step 1 → User pastes raw email (headers + body)
Step 2 → Parser extracts headers, links, sender info, and metadata
Step 3 → ML engine matches against historical phishing pattern database
Step 4 → Claude AI performs deep semantic analysis of content and intent
Step 5 → Threat score calculated (0–100) with confidence level
Step 6 → Full breakdown report generated with per-indicator explanations
```

---

## 📊 Threat Score Scale

| Score | Level | Meaning |
|---|---|---|
| 0 – 20 | 🟢 Safe | No significant threats detected |
| 21 – 40 | 🟡 Low Risk | Minor suspicious signals, likely safe |
| 41 – 60 | 🟠 Medium Risk | Multiple indicators — review carefully |
| 61 – 80 | 🔴 High Risk | Strong phishing signals — do not click links |
| 81 – 100 | ⛔ Critical | Confirmed phishing attempt — delete immediately |

---

## 🖥️ UI Overview

- **Input panel** — paste raw email content (headers + body)
- **Scan button** — triggers full AI + ML analysis pipeline
- **Threat score card** — large visual score with severity color coding
- **Indicator breakdown table** — each threat listed with category, severity, and description
- **Header analysis panel** — SPF / DKIM / DMARC results displayed clearly
- **Link scanner results** — all URLs extracted and rated
- **Full report panel** — complete AI-generated analysis ready to copy or export

---

## 🚀 Getting Started

### Run Locally

```bash
# Clone the repo
git clone https://github.com/your-username/intelligent-phishmail-analyzer.git
cd intelligent-phishmail-analyzer

# Install dependencies
npm install

# Start the dev server
npm run dev
```

### Requirements

- Node.js 18+
- Anthropic API access (Claude Sonnet)
- Modern browser

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React (JSX) |
| AI Engine | Claude Sonnet (`claude-sonnet-4-20250514`) |
| ML Patterns | Historical phishing vulnerability dataset |
| Header Parsing | Custom email header parser |
| API | Anthropic `/v1/messages` |
| Deployment | [Medo.dev](https://medo.dev) |

---

## 📧 Example — What a Phishing Email Looks Like to Intelligent PhishMail Analyzer

```
From: security@paypa1.com          ← lookalike domain (1 instead of l)
Reply-To: harvester@evil.ru        ← Reply-To mismatch
Subject: URGENT: Your account has been suspended!

Dear Customer,
Your PayPal account has been limited. Click below IMMEDIATELY
to verify your identity or your account will be closed in 24 hours.

[Verify Now] → http://bit.ly/3xR9q2k (redirect to credential harvester)
```

**Intelligent PhishMail Analyzer detects:**
- Lookalike domain `paypa1.com` → CRITICAL
- Reply-To mismatch (`.ru` domain) → HIGH
- Urgency language ("URGENT", "IMMEDIATELY", "24 hours") → HIGH
- URL shortener hiding destination → HIGH
- Impersonation of PayPal brand → HIGH
- **Threat Score: 94 / 100 — ⛔ Critical**

---

## 🔒 Privacy

- Emails are **never stored** — analysis happens in-session only
- No email content is logged or retained after the scan
- All processing happens via secure API calls
- No login or account required

---

## 🤝 Contributing

Pull requests are welcome. To contribute:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 📄 License

MIT — free to use, modify, and distribute with attribution.

---

<p align="center">
  🎣 Intelligent PhishMail Analyzer &nbsp;·&nbsp; Stay safe. Scan first. &nbsp;·&nbsp; Powered by Claude

</p>
