"""Generate security awareness training quizzes.

Creates multiple-choice questions on phishing, password security,
physical security, and general awareness with answers and explanations.
"""

import asyncio
import hashlib
import random
import re
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

QUIZ_BANK = {
    "phishing": {
        "beginner": [
            {"q": "What is the most common delivery method for phishing attacks?", "choices": ["Email", "Phone call", "Text message", "Social media"], "answer": 0, "explanation": "Email remains the most common phishing vector, accounting for over 90% of phishing attacks. Attackers can easily spoof sender addresses and craft convincing messages at scale."},
            {"q": "Which of the following is a red flag in a suspicious email?", "choices": ["Company logo in the signature", "Urgent request to click a link immediately", "Email sent during business hours", "A greeting using your name"], "answer": 1, "explanation": "Urgency is a key social engineering tactic. Legitimate organizations rarely demand immediate action via email. Always pause and verify through official channels."},
            {"q": "What should you do if you receive an unexpected email asking for your password?", "choices": ["Reply with your password", "Click the link and enter credentials", "Report it to IT security and delete it", "Forward it to colleagues for their opinion"], "answer": 2, "explanation": "Never provide credentials via email. Legitimate services will never ask for your password by email. Report suspicious messages to your security team."},
            {"q": "What is 'spear phishing'?", "choices": ["Phishing that targets a specific individual", "Phishing sent to millions of users", "A phishing attack using phone calls", "Malware hidden in fishing-related websites"], "answer": 0, "explanation": "Spear phishing is a targeted attack directed at a specific person or organization, using personalized information to appear more credible than mass phishing."},
            {"q": "Which URL is most likely a phishing attempt?", "choices": ["https://www.google.com/login", "https://google.com.login-secure.xyz/auth", "https://accounts.google.com/signin", "https://support.google.com/account"], "answer": 1, "explanation": "The domain 'login-secure.xyz' is the actual domain, not google.com. Phishing URLs often embed trusted brand names as subdomains of attacker-controlled domains."},
        ],
        "intermediate": [
            {"q": "What technique involves registering domains similar to legitimate ones (e.g., g00gle.com)?", "choices": ["DNS poisoning", "Typosquatting", "Man-in-the-middle", "SQL injection"], "answer": 1, "explanation": "Typosquatting uses domains with slight misspellings or character substitutions to trick users. Always verify the exact domain before entering credentials."},
            {"q": "Which email header field is most easily spoofed?", "choices": ["Received", "X-Originating-IP", "From", "DKIM-Signature"], "answer": 2, "explanation": "The 'From' header is trivially spoofed. SPF, DKIM, and DMARC help detect spoofing, but many domains lack proper configuration. Always check the actual sending domain."},
            {"q": "What is a 'watering hole' attack?", "choices": ["Flooding a network with traffic", "Compromising a website frequently visited by the target group", "Sending phishing emails with water-themed content", "A DDoS attack on water utility systems"], "answer": 1, "explanation": "Watering hole attacks compromise websites commonly visited by the target group. When targets visit the site, malware is delivered, bypassing email-based defenses."},
            {"q": "How does DMARC help prevent phishing?", "choices": ["It encrypts all emails", "It blocks all external emails", "It validates that emails come from authorized senders for a domain", "It scans attachments for malware"], "answer": 2, "explanation": "DMARC (Domain-based Message Authentication) uses SPF and DKIM to verify that emails claiming to be from a domain are actually authorized, reducing spoofing success."},
            {"q": "What is a Business Email Compromise (BEC) attack?", "choices": ["An attack encrypting business email servers", "Impersonation of executives to authorize fraudulent transactions", "A brute force attack on email passwords", "Installing keyloggers on business computers"], "answer": 1, "explanation": "BEC attacks impersonate trusted executives or business partners to trick employees into transferring funds or sharing sensitive information. They caused over $2.7B in losses in 2022."},
        ],
        "advanced": [
            {"q": "Which technique can bypass MFA in a phishing attack?", "choices": ["Real-time phishing proxy (e.g., Evilginx2)", "Adding extra CSS to the page", "Using a VPN", "Encoding the URL in base64"], "answer": 0, "explanation": "Real-time phishing proxies intercept credentials AND session tokens as the victim authenticates through a transparent proxy to the real site, capturing the authenticated session cookie."},
            {"q": "What is 'consent phishing' in the context of OAuth?", "choices": ["Asking users to accept cookie policies", "Tricking users into granting malicious apps access to their accounts", "Phishing emails that ask for explicit consent", "Social engineering to obtain written authorization"], "answer": 1, "explanation": "Consent phishing tricks users into granting OAuth permissions to malicious applications, giving attackers persistent access to email, files, and other resources without needing passwords."},
            {"q": "How can an attacker use IDN homograph attacks in phishing?", "choices": ["By registering domains with Unicode characters visually identical to ASCII", "By hiding phishing links in image files", "By modifying DNS cache entries", "By exploiting browser vulnerabilities"], "answer": 0, "explanation": "IDN homograph attacks use Unicode characters that look identical to ASCII (e.g., Cyrillic 'a' vs Latin 'a') to create visually indistinguishable but technically different domain names."},
            {"q": "What is AiTM (Adversary-in-the-Middle) phishing?", "choices": ["AI-generated phishing emails", "Intercepting and relaying authentication in real-time to steal session tokens", "Using AI to detect phishing attempts", "A phishing attack targeting AI systems"], "answer": 1, "explanation": "AiTM phishing proxies the authentication flow in real-time, capturing session cookies after successful MFA. This bypasses traditional MFA by stealing the post-authentication session."},
            {"q": "Which defense is MOST effective against AiTM phishing attacks?", "choices": ["Email filtering", "SMS-based MFA", "FIDO2/WebAuthn hardware keys", "Security awareness training alone"], "answer": 2, "explanation": "FIDO2/WebAuthn keys are bound to the legitimate domain origin, so they refuse to authenticate on proxy domains. This is the strongest defense against real-time phishing proxies."},
        ],
    },
    "password": {
        "beginner": [
            {"q": "What is the minimum recommended password length for strong security?", "choices": ["6 characters", "8 characters", "12 characters", "16 characters"], "answer": 2, "explanation": "NIST recommends at least 12 characters. Longer passwords exponentially increase brute-force difficulty. A 12-character password with mixed characters can take centuries to crack."},
            {"q": "Which of these is the STRONGEST password?", "choices": ["Password123!", "p@$$w0rd", "correct-horse-battery-staple", "Admin2024"], "answer": 2, "explanation": "A passphrase of random words is both strong and memorable. 'correct-horse-battery-staple' has high entropy due to length. Short passwords with substitutions (p@$$w0rd) are easily cracked."},
            {"q": "Why should you not reuse passwords across different sites?", "choices": ["It makes passwords easier to remember", "If one site is breached, attackers can access all your accounts", "It violates most terms of service", "Reusing passwords is actually fine"], "answer": 1, "explanation": "Credential stuffing attacks use leaked passwords from breached sites to attempt login on other services. Password reuse means one breach compromises all your accounts."},
            {"q": "What is a password manager?", "choices": ["A person who manages your passwords", "Software that generates and securely stores unique passwords", "A browser feature that saves login pages", "An IT policy document about passwords"], "answer": 1, "explanation": "Password managers generate strong unique passwords for every account and store them in an encrypted vault. You only need to remember one master password."},
        ],
        "intermediate": [
            {"q": "What is credential stuffing?", "choices": ["Creating very long passwords", "Using leaked credential pairs to attempt logins on other services", "Storing passwords in plain text", "A password complexity requirement"], "answer": 1, "explanation": "Credential stuffing uses username/password pairs from data breaches to automatically test login on other services. It exploits password reuse and is extremely common."},
            {"q": "Which hashing algorithm should NOT be used for password storage?", "choices": ["bcrypt", "Argon2", "MD5", "scrypt"], "answer": 2, "explanation": "MD5 is fast and lacks salt by default, making it trivial to crack with rainbow tables or GPU-based attacks. Modern password hashing (bcrypt, Argon2, scrypt) is intentionally slow."},
            {"q": "What is 'password spraying'?", "choices": ["Trying many passwords against one account", "Trying one common password against many accounts", "Storing passwords in multiple locations", "Encrypting passwords before transmission"], "answer": 1, "explanation": "Password spraying tries a few common passwords (e.g., 'Summer2024!') against many accounts to avoid lockout thresholds. It is effective because users often pick predictable passwords."},
            {"q": "What is the primary advantage of passkeys over traditional passwords?", "choices": ["They are shorter and easier to type", "They use public-key cryptography and are phishing-resistant", "They can be shared across teams easily", "They don't require any device"], "answer": 1, "explanation": "Passkeys use asymmetric cryptography bound to the legitimate domain. The private key never leaves the device, making them immune to phishing, credential stuffing, and server-side breaches."},
        ],
        "advanced": [
            {"q": "What is the time complexity advantage of Argon2id over bcrypt for password hashing?", "choices": ["Argon2id is faster", "Argon2id is memory-hard, resisting GPU/ASIC attacks", "bcrypt is more secure", "They are identical"], "answer": 1, "explanation": "Argon2id is memory-hard, requiring significant RAM per hash computation. This neutralizes GPU/ASIC parallelism advantages that make bcrypt more vulnerable to modern hardware attacks."},
            {"q": "In a Kerberoasting attack, what is extracted for offline cracking?", "choices": ["User password hashes from NTDS.dit", "TGS service tickets encrypted with service account password hashes", "Kerberos TGT tickets", "LDAP bind credentials"], "answer": 1, "explanation": "Kerberoasting requests TGS tickets for SPNs, which are encrypted with the service account's password hash. These can be extracted by any domain user and cracked offline."},
            {"q": "What makes PBKDF2 with 600,000 iterations less secure than Argon2id in practice?", "choices": ["PBKDF2 uses weaker encryption", "PBKDF2 lacks memory-hardness, allowing efficient GPU parallelization", "PBKDF2 cannot use salt", "PBKDF2 has a maximum password length"], "answer": 1, "explanation": "PBKDF2's computation is purely CPU-bound with no memory requirement. GPUs can compute millions of PBKDF2 hashes in parallel. Argon2id's memory requirement limits parallelization."},
        ],
    },
    "physical": {
        "beginner": [
            {"q": "What is 'tailgating' in physical security?", "choices": ["Following someone through a secured door without authentication", "Driving too close to another vehicle", "Monitoring someone's online activity", "Copying someone's access card"], "answer": 0, "explanation": "Tailgating (piggybacking) is following an authorized person through a secured entry point. It bypasses physical access controls and is one of the most common physical security breaches."},
            {"q": "What should you do if a stranger asks you to hold the door to a secure area?", "choices": ["Hold the door open politely", "Ask them to use their own badge or contact reception", "Ignore them completely", "Call the police immediately"], "answer": 1, "explanation": "Politely redirect them to use their own credentials or contact the front desk. Social pressure to be polite is how tailgating succeeds - security awareness means knowing when to say no."},
            {"q": "What is a 'clean desk policy'?", "choices": ["Keeping your desk physically clean", "Ensuring no sensitive information is visible on desks when unattended", "A policy about desk placement in the office", "Cleaning computer screens regularly"], "answer": 1, "explanation": "Clean desk policies require employees to secure all sensitive documents, notes, and screens when away. Visible information can be photographed or read by unauthorized visitors."},
            {"q": "Why should you lock your computer screen when leaving your desk?", "choices": ["To save electricity", "To prevent unauthorized access to your session", "It's required by law everywhere", "To prevent screen burn-in"], "answer": 1, "explanation": "An unlocked workstation gives anyone passing by full access to your accounts, emails, and files. Use Win+L (Windows) or Ctrl+Cmd+Q (Mac) to lock instantly."},
        ],
        "intermediate": [
            {"q": "What is 'shoulder surfing'?", "choices": ["A water sport activity", "Observing someone's screen or keystrokes by looking over their shoulder", "A network scanning technique", "A social media stalking method"], "answer": 1, "explanation": "Shoulder surfing captures passwords, PINs, and sensitive data by direct observation. Use privacy screens, be aware of surroundings, and shield keypads when entering PINs."},
            {"q": "What physical security risk do USB drops exploit?", "choices": ["Electrical damage to ports", "Human curiosity - people plug in found devices", "Wi-Fi signal interference", "Overloading power supplies"], "answer": 1, "explanation": "USB drop attacks rely on people plugging in found USB devices. These can contain malware that executes on insertion, keystroke loggers, or scripts that exfiltrate data."},
            {"q": "What is 'dumpster diving' in a security context?", "choices": ["Recycling old computer equipment", "Searching through discarded materials for sensitive information", "Cleaning up digital storage", "A network packet capture technique"], "answer": 1, "explanation": "Dumpster diving retrieves sensitive documents, hardware, and media from trash. Organizations should shred documents, degauss drives, and physically destroy sensitive media."},
        ],
        "advanced": [
            {"q": "What is a 'rogue access point' in physical security?", "choices": ["An unauthorized wireless access point planted in the facility", "A broken door lock", "An unauthorized parking area", "A fake fire exit"], "answer": 0, "explanation": "Rogue APs are unauthorized wireless devices planted to capture traffic or provide network access. Physical security sweeps should include wireless spectrum analysis."},
            {"q": "How can an attacker exploit an HID proximity card system?", "choices": ["By guessing the card number", "By cloning the card using a proxmark device at close range", "By hacking the card manufacturer", "Proximity cards cannot be cloned"], "answer": 1, "explanation": "Legacy HID proximity cards transmit their ID unencrypted and can be cloned with a Proxmark or similar device within reading range (a few inches). Upgrade to iCLASS SE or SEOS."},
        ],
    },
    "all": {},
}


class SocialAwarenessQuizModule(AtsModule):
    """Generate security awareness training quizzes with questions, answers, and explanations."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="social_awareness_quiz",
            category=ModuleCategory.ADVANCED,
            description="Generate security awareness quizzes on phishing, passwords, physical security, and more",
            version="1.0.0",
            parameters=[
                Parameter(name="topic", type=ParameterType.CHOICE,
                          description="Quiz topic area",
                          choices=["phishing", "password", "physical", "all"], default="all"),
                Parameter(name="difficulty", type=ParameterType.CHOICE,
                          description="Quiz difficulty level",
                          choices=["beginner", "intermediate", "advanced"], default="beginner"),
                Parameter(name="count", type=ParameterType.INTEGER,
                          description="Number of questions to generate",
                          default=10, min_value=1, max_value=50),
            ],
            outputs=[
                OutputField(name="questions", type="list", description="Quiz questions with choices and answers"),
                OutputField(name="answer_key", type="list", description="Correct answers with explanations"),
                OutputField(name="quiz_metadata", type="dict", description="Quiz topic, difficulty, and stats"),
            ],
            tags=["advanced", "social", "awareness", "training", "quiz"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        count = config.get("count", 10)
        if not isinstance(count, int) or count < 1:
            return False, "Question count must be a positive integer"
        return True, ""

    def _gather_questions(self, topic: str, difficulty: str) -> list[dict[str, Any]]:
        """Collect questions matching the topic and difficulty criteria."""
        pool = []
        topics_to_search = [topic] if topic != "all" else ["phishing", "password", "physical"]
        for t in topics_to_search:
            topic_bank = QUIZ_BANK.get(t, {})
            if difficulty in topic_bank:
                for q in topic_bank[difficulty]:
                    pool.append({**q, "topic": t, "difficulty": difficulty})
            if difficulty == "advanced":
                for diff in ["intermediate", "advanced"]:
                    if diff in topic_bank:
                        for q in topic_bank[diff]:
                            entry = {**q, "topic": t, "difficulty": diff}
                            if entry not in pool:
                                pool.append(entry)
            elif difficulty == "intermediate":
                for diff in ["beginner", "intermediate"]:
                    if diff in topic_bank:
                        for q in topic_bank[diff]:
                            entry = {**q, "topic": t, "difficulty": diff}
                            if entry not in pool:
                                pool.append(entry)
        return pool

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        topic = config.get("topic", "all")
        difficulty = config.get("difficulty", "beginner")
        count = config.get("count", 10)

        pool = self._gather_questions(topic, difficulty)
        random.shuffle(pool)
        selected = pool[:count]

        questions = []
        answer_key = []

        for idx, item in enumerate(selected, 1):
            question_id = hashlib.md5(item["q"].encode()).hexdigest()[:8]
            questions.append({
                "number": idx,
                "id": question_id,
                "topic": item["topic"],
                "difficulty": item["difficulty"],
                "question": item["q"],
                "choices": {chr(65 + i): choice for i, choice in enumerate(item["choices"])},
            })
            correct_letter = chr(65 + item["answer"])
            answer_key.append({
                "number": idx,
                "id": question_id,
                "correct_answer": correct_letter,
                "correct_text": item["choices"][item["answer"]],
                "explanation": item["explanation"],
            })

        topics_covered = list({q["topic"] for q in selected})
        difficulties_covered = list({q["difficulty"] for q in selected})

        return {
            "questions": questions,
            "answer_key": answer_key,
            "quiz_metadata": {
                "requested_topic": topic,
                "requested_difficulty": difficulty,
                "questions_delivered": len(selected),
                "questions_requested": count,
                "topics_covered": topics_covered,
                "difficulties_covered": difficulties_covered,
                "total_pool_size": len(pool),
            },
        }
