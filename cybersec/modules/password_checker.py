import re
import math
import string


# A small inline list of the most common weak passwords
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "passw0rd", "shadow", "123123",
    "654321", "superman", "qazwsx", "michael", "football", "password1",
    "password123", "admin", "welcome", "login", "passw0rd1",
}


def _entropy(password: str) -> float:
    """Calculate Shannon entropy of the password."""
    if not password:
        return 0.0
    freq = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(password)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _charset_size(password: str) -> int:
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += 32
    return pool or 1


def analyze_password(password: str) -> dict:
    """
    Evaluate password strength and return a detailed report.
    """
    length      = len(password)
    has_lower   = bool(re.search(r'[a-z]', password))
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    is_common   = password.lower() in COMMON_PASSWORDS

    # ── Score (0–100) ─────────────────────────────────────────────────────────
    score = 0

    # Length scoring
    if length >= 8:   score += 10
    if length >= 12:  score += 15
    if length >= 16:  score += 20

    # Character variety
    if has_lower:   score += 10
    if has_upper:   score += 10
    if has_digit:   score += 10
    if has_special: score += 15

    # Entropy bonus
    ent = _entropy(password)
    if ent >= 3.0:  score += 5
    if ent >= 3.5:  score += 5

    # Penalties
    if is_common:              score = max(0, score - 50)
    if re.search(r'(.)\1{2,}', password):  score = max(0, score - 10)  # repeated chars
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
        score = max(0, score - 10)  # sequential patterns

    score = min(score, 100)

    # ── Strength Label ────────────────────────────────────────────────────────
    if score < 20:
        strength = "Very Weak"
    elif score < 40:
        strength = "Weak"
    elif score < 60:
        strength = "Fair"
    elif score < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    # ── Crack Time Estimate ───────────────────────────────────────────────────
    charset = _charset_size(password)
    combinations = charset ** length
    # Assume 10 billion guesses/sec (GPU cluster)
    guesses_per_sec = 10_000_000_000
    seconds = combinations / guesses_per_sec

    if seconds < 60:
        crack_time = f"{int(seconds)} seconds"
    elif seconds < 3600:
        crack_time = f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        crack_time = f"{int(seconds / 3600)} hours"
    elif seconds < 31536000:
        crack_time = f"{int(seconds / 86400)} days"
    elif seconds < 3.156e9:
        crack_time = f"{int(seconds / 31536000)} years"
    else:
        crack_time = "centuries"

    # ── Suggestions ───────────────────────────────────────────────────────────
    suggestions = []
    if length < 12:
        suggestions.append("Use at least 12 characters.")
    if not has_upper:
        suggestions.append("Add uppercase letters.")
    if not has_digit:
        suggestions.append("Include numbers.")
    if not has_special:
        suggestions.append("Use special characters (!@#$%^&*).")
    if is_common:
        suggestions.append("This is a commonly used password — choose something unique.")

    return {
        "password_length": length,
        "score":           score,
        "strength":        strength,
        "crack_time":      crack_time,
        "entropy":         round(ent, 2),
        "checks": {
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digit":     has_digit,
            "has_special":   has_special,
            "length_ok":     length >= 12,
            "not_common":    not is_common,
        },
        "suggestions": suggestions,
    }
