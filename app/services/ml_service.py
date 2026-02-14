def predict_risk(url):
    # Dummy ML logic (baad me real ML se replace karna hai)
    if "login" in url:
        return 80, "Suspicious"
    return 20, "Safe"
