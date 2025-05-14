import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score

# Load dataset
df = pd.read_csv("emails.csv")
df['label'] = df['label'].map({'ham': 0, 'phishing': 1})  # Convert labels to numeric

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(df['text'], df['label'], test_size=0.2, random_state=42)

# Vectorize text
vectorizer = CountVectorizer()
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# Train the model
model = MultinomialNB()
model.fit(X_train_vec, y_train)

# Evaluate the model
y_pred = model.predict(X_test_vec)
print("Model accuracy:", accuracy_score(y_test, y_pred))

# Function to classify custom email
def classify_email(text):
    vec = vectorizer.transform([text])
    prediction = model.predict(vec)
    return "Phishing Email" if prediction[0] == 1 else "Legitimate Email"

# Test with user input
while True:
    email_text = input("\nPaste email content (or type 'exit' to quit):\n")
    if email_text.lower() == "exit":
        break
    print("Result:", classify_email(email_text))
