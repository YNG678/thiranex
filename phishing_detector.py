import pandas as pd
import re
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

data = {
    "email": [
        "Your account has been suspended click here to verify",
        "Win a free iPhone now click this link",
        "Meeting scheduled for tomorrow",
        "Project report attached please review",
        "Update your bank password immediately",
        "Claim your lottery prize now",
        "Team lunch at 1 PM",
        "Invoice attached for payment",
        "Urgent verify your PayPal account",
        "Congratulations you won cash reward"
    ],

    "label": [
        "Phishing",
        "Phishing",
        "Safe",
        "Safe",
        "Phishing",
        "Phishing",
        "Safe",
        "Safe",
        "Phishing",
        "Phishing"
    ]
}

df = pd.DataFrame(data)

def extract_features(text):

    text = text.lower()

    url_count = len(re.findall(r'http[s]?://', text))

    suspicious_words = [
        "verify",
        "password",
        "bank",
        "urgent",
        "click",
        "win",
        "free",
        "prize",
        "cash"
    ]

    suspicious_count = sum(word in text for word in suspicious_words)

    return f"{text} urlcount_{url_count} suspicious_{suspicious_count}"

df["processed"] = df["email"].apply(extract_features)

vectorizer = TfidfVectorizer()

X = vectorizer.fit_transform(df["processed"])

y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.3,
    random_state=42
)

model = LogisticRegression()

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:\n")

print(accuracy)

print("\nClassification Report:\n")

print(classification_report(y_test, y_pred))

cm = confusion_matrix(y_test, y_pred)

print("\nConfusion Matrix:\n")

print(cm)

plt.figure(figsize=(5,4))

sns.heatmap(
    cm,
    annot=True,
    fmt='d',
    xticklabels=["Phishing", "Safe"],
    yticklabels=["Phishing", "Safe"]
)

plt.xlabel("Predicted")

plt.ylabel("Actual")

plt.title("Confusion Matrix")

plt.show()

while True:

    email = input("\nEnter Email Text (or type exit):\n")

    if email.lower() == "exit":
        break

    processed = extract_features(email)

    transformed = vectorizer.transform([processed])

    prediction = model.predict(transformed)[0]

    print(f"\nPrediction: {prediction}")