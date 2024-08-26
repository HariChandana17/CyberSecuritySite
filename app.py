import streamlit as st
import json
import re
import os
from ibm_watsonx_ai.foundation_models import Model
import hashlib
import requests
from urllib.parse import urlparse
import time
import string
import random
import pandas as pd
from datetime import datetime
 
# Set up the model
model_id = "ibm/granite-13b-chat-v2"
parameters = {
    "decoding_method": "greedy",
    "max_new_tokens": 900,
    "repetition_penalty": 1.05
}
 
project_id = os.getenv("PROJECT_ID")
space_id = os.getenv("SPACE_ID")
 
 
def get_credentials():
    return {
        "url": "https://us-south.ml.cloud.ibm.com",
        "apikey": "d38ImtKqLpIRMGcIHnbELRc9r4niWjXKHPMDqKbNYrC5"
    }
 
model = Model(
    model_id=model_id,
    params=parameters,
    credentials=get_credentials(),
    project_id="bcf9d59d-48aa-4aa0-a251-dc010d26afb5",
    space_id=space_id
)
 
# Define the prompt input
prompt_input = """<|system|>
You are Granite Chat, an AI language model developed by IBM. You are a cautious assistant and your role is Cyber Security Crime Detector. You carefully follow instructions. You are helpful and harmless and you follow ethical guidelines and promote positive behavior. You always respond to greetings (for example, hi, hello, g'day, morning, afternoon, evening, night, what's up, nice to meet you, sup, etc) with "Hello! I am Granite Chat, created by IBM. How can I help you today?".  
 
You are a Cyber Security Crime Detector AI assistant designed to help civilians identify potential social engineering attacks in messages or emails. Your task is to analyze the provided text and determine if it's likely to be a scam or a legitimate message.
 
For each message provided, you must:
1. Carefully analyze the content for signs of social engineering tactics.
2. Determine if the message is likely to be a scam or legitimate.
3. Provide your assessment in JSON format with the following structure:
 
{
  "is_scam": [true/false],
  "category": ["SCAM"/"NOT_SCAM"],
  "social_engineering_attack": [true/false],
  "explanation": "[Brief explanation of your assessment]"
}
 
Guidelines:
1. The "is_scam" field should be a boolean (true or false).
2. The "category" field must be either "SCAM" or "NOT_SCAM". Never use both or include "OR".
3. The "social_engineering_attack" field should be a boolean (true or false).
4. Provide a concise explanation for your assessment in the "explanation" field.
 
Analyze each message carefully for signs of phishing, urgency, unsolicited requests for personal information, suspicious links, or other red flags associated with social engineering attacks.
 
Respond only with the JSON output. Do not include any additional text or explanations outside the JSON structure.
Guidelines for analysis:
- Look for urgency, threats, or pressure to act quickly
- Check for unusual requests for personal information
- Be wary of unexpected attachments or links
- Consider the sender's email address and any inconsistencies
- Analyze the language for poor grammar, spelling, or unusual phrasing
- Be cautious of offers that seem too good to be true
 
Respond only with the JSON output. Do not include any other text in your response.
<|user|>
"""
 
def extract_value(text, key):
    pattern = f'"{key}":\s*(true|false|"[^"]*")'
    match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
    if match:
        value = match.group(1)
        if value.lower() == 'true':
            return True
        elif value.lower() == 'false':
            return False
        else:
            return value.strip('"')
    return None
 
def generate_email_draft(user_details, original_message):
    email_prompt = f"""Draft a concise email to the Cyber Security Team reporting a potential phishing incident behalf of the user. Include the following details:
    - The user clicked on a suspicious link
    - User-provided details: {user_details}
    
    Main Issue Details: {original_message}
    The email should be professional, clear, indicating the seriousness of the issue and seeking help from Cyber Security Team.
    """
    email_draft = model.generate_text(prompt=email_prompt, guardrails=False)
    return email_draft
 
def analyze_message(question):
    formattedQuestion = f"""<|user|>
    {question}
    <|assistant|>
    """
    prompt = f"{prompt_input}{formattedQuestion}"
    generated_response = model.generate_text(prompt=prompt, guardrails=False)
   
    # Clean up the generated response
    generated_response = generated_response.strip()
   
    # Remove any text before the first '{' and after the last '}'
    start = generated_response.find('{')
    end = generated_response.rfind('}')
    if start != -1 and end != -1:
        generated_response = generated_response[start:end+1]
   
    try:
        response_data = json.loads(generated_response)
    except json.JSONDecodeError:
        # If JSON parsing fails, use regex to extract values
        response_data = {}
        response_data['is_scam'] = extract_value(generated_response, 'is_scam')
        response_data['category'] = extract_value(generated_response, 'category')
        response_data['social_engineering_attack'] = extract_value(generated_response, 'social_engineering_attack')
        response_data['explanation'] = extract_value(generated_response, 'explanation')
       
        # If extraction fails, provide default values
        if response_data['is_scam'] is None:
            response_data['is_scam'] = False
        if response_data['category'] is None:
            response_data['category'] = "UNKNOWN"
        if response_data['social_engineering_attack'] is None:
            response_data['social_engineering_attack'] = False
        if response_data['explanation'] is None:
            response_data['explanation'] = "Unable to parse the AI's response. Please review the generated text carefully."
   
    return response_data, generated_response
 
def check_url_safety(url):
    # List of known safe domains
    safe_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com']
   
    try:
        # Parse the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        # Check if the domain (without www.) is in the list of safe domains
        base_domain = domain.replace('www.', '')
        if any(base_domain.endswith(safe_domain) for safe_domain in safe_domains):
            return True
        # For demonstration purposes, we'll consider HTTPS URLs safer
        if parsed_url.scheme == 'https':
            return True
        # In a real-world scenario, you would make an API call to a URL reputation service here
        # For now, we'll return False for any URL not matching the above criteria
        return False
    except:
        # If there's any error in parsing or checking the URL, err on the side of caution
        return False
 
def generate_security_quiz():
    questions = [
        {
            "question": "What is phishing?",
            "options": [
                "A type of fish",
                "A cybercrime where targets are contacted by email, phone or text by someone posing as a legitimate institution",
                "A method of cooking fish",
                "A type of internet connection"
            ],
            "correct": 1
        },
        {
            "question": "What should you do if you receive an unexpected email asking for personal information?",
            "options": [
                "Reply immediately with the information",
                "Click on any links in the email",
                "Ignore the email and delete it",
                "Contact the supposed sender through official channels to verify"
            ],
            "correct": 3
        },
        {
            "question": "Which of the following is a strong password?",
            "options": [
                "password123",
                "qwerty",
                "P@ssw0rd!",
                "MyNameIsJohn"
            ],
            "correct": 2
        },
        {
            "question": "What is two-factor authentication?",
            "options": [
                "Using two different passwords",
                "Logging in from two different devices",
                "A security process where users provide two different authentication factors to verify their identity",
                "Changing your password twice a year"
            ],
            "correct": 2
        },
        {
            "question": "What is a common sign of a phishing email?",
            "options": [
                "It's from someone you know",
                "It has a sense of urgency or threat",
                "It's written in perfect grammar",
                "It doesn't ask for any personal information"
            ],
            "correct": 1
        }
    ]
    return questions
 
def generate_chatbot_response(user_input):
    chatbot_prompt = f"""<|system|>
You are Granite Chat, an AI language model developed by IBM. Your role is a Cyber Security Expert. You provide helpful and accurate information about cybercrime, cyber security, and best practices for online safety. Always be respectful and professional in your responses. Respond only to the user's input without asking follow-up questions or continuing the conversation on your own.
 
<|user|>
{user_input}
 
<|assistant|>
"""
    response = model.generate_text(prompt=chatbot_prompt, guardrails=True)
    # Remove any content after detecting a user prompt
    response = response.split("<|user|>")[0].strip()
    return response
 
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def display_useful_links():
    st.subheader("🔗 Useful Links")
    
    links = [
        {"name": "NCPCR", "url": "https://ncpcr.gov.in/", "logo": "https://ncpcr.gov.in/images/ncpcr-logo.png"},
        {"name": "SVP National Police Academy", "url": "https://elibrary.svpnpa.gov.in/user#/home", "logo": "https://elibrary.svpnpa.gov.in/static-content/org_0808a681-686f-49a4-b5a8-4e90d90c9f27/org_0808a681-686f-49a4-b5a8-4e90d90c9f27_logo.png?_t=1724654451494"},
        {"name": "Cyber Dost", "url": "https://x.com/CyberDost", "logo": "https://pbs.twimg.com/profile_images/1675803883669700608/AsGfEGG__400x400.jpg"},
        {"name": "ISEA", "url": "https://isea.gov.in/", "logo": "https://www.jmjdelhi.in/assets/images/isea-logo.png"},
        {"name": "CERT-In", "url": "https://www.cert-in.org.in/", "logo": "https://upload.wikimedia.org/wikipedia/commons/d/db/CERT-In_2023.png"},
        {"name": "India.gov.in", "url": "https://www.india.gov.in/", "logo": "https://www.india.gov.in/sites/upload_files/npi/files/logo_1.png"},
        {"name": "CyTrain", "url": "https://cytrain.ncrb.gov.in/", "logo": "https://cybercrime.gov.in/images/cytrain_log.png"},
        {"name": "NIELIT", "url": "https://nielitcyberforensics.in/", "logo": "https://pcitacademy.in/new/product/category/1559628954831.png"},  
    ]
    
    # Create columns for each link
    num_links = len(links)
    cols = st.columns(num_links)
    
    for i, link in enumerate(links):
        with cols[i]:
            # Display the logo image
            st.image(link["logo"], width=150)
            # Display the link text
            st.markdown(f"[{link['name']}]({link['url']})")
 
def check_password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    return score
def save_user_data(name, location):
    df = pd.DataFrame({'Name': [name], 'Location': [location], 'Login Time': [datetime.now()]})
    if os.path.exists('users_data.xlsx'):
        existing_df = pd.read_excel('users_data.xlsx')
        updated_df = pd.concat([existing_df, df], ignore_index=True)
    else:
        updated_df = df
    updated_df.to_excel('users_data.xlsx', index=False)
 
def login_page():
    st.title("🔐 Login to Cyber Security Crime Detector")
    name = st.text_input("Enter your name:")
    location = st.text_input("Enter your location:")
    if st.button("Login"):
        if name and location:
            save_user_data(name, location)
            st.session_state.logged_in = True
            st.session_state.user_name = name
            st.success(f"Welcome, {name}! You have successfully logged in.")
            st.rerun()
        else:
            st.error("Please enter both name and location.")
 
 
def main_content():
    st.title(f"🛡️ Welcome to Cyber Security Crime Detector, {st.session_state.user_name}!")
    st.markdown("---")

    # Sidebar content
    st.sidebar.title("About Our Features")
    st.sidebar.info("""
    🔍 Threat Analyzer: AI-powered scam detection\n
    🔗 URL Checker: Verify link safety \n
    🧠 Security Quiz: Test your cyber security knowledge\n
    💬 Cyber Security Buddy: Get answers to your security questions\n
    🔑 Password Tools: Generate and check password strength\n
    📊 Security Dashboard: Monitor your system's security status\n
    📰 Top News: Stay updated on recent cyber security threats
    """)
 
    # Initialize session state variables
    if 'question' not in st.session_state:
        st.session_state.question = ""
    if 'analysis_done' not in st.session_state:
        st.session_state.analysis_done = False
    if 'is_scam' not in st.session_state:
        st.session_state.is_scam = None
    if 'response_data' not in st.session_state:
        st.session_state.response_data = None
    if 'generated_response' not in st.session_state:
        st.session_state.generated_response = None
    if 'quiz_score' not in st.session_state:
        st.session_state.quiz_score = 0
    if 'last_scan_time' not in st.session_state:
        st.session_state.last_scan_time = None
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
 
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["Threat Analyzer", "Cyber Security Buddy", "URL Checker", "Security Dashboard", "Password Tools", "Security Quiz", "Useful Links"])

    with tab1:
        col1, col2 = st.columns([2, 1])
       
        with col1:
            st.subheader("📧 Enter Suspicious Message")
            st.session_state.question = st.text_area("Paste the suspicious message or email here:", value=st.session_state.question, height=200)
           
            if st.button("🔍 Analyze Message"):
                if st.session_state.question:
                    with st.spinner("Analyzing the message..."):
                        st.session_state.response_data, st.session_state.generated_response = analyze_message(st.session_state.question)
                    st.session_state.analysis_done = True
                    st.session_state.is_scam = st.session_state.response_data.get('is_scam')
           
            if st.session_state.analysis_done:
                st.subheader("🤖 AI Analysis:")
                st.json(st.session_state.generated_response)
               
                if st.session_state.is_scam is not None:
                    if st.session_state.is_scam:
                        st.error("⚠️ Warning: This message has been identified as a potential scam.")
                        clicked = st.radio("Have you already clicked on any links in this message?", ('No', 'Yes'))
                       
                        if clicked == 'Yes':
                            st.warning("🚨 Caution: You may have been exposed to a phishing attempt.")
                            user_details = st.text_area("Please provide details about what happened and what information you may have entered:")
                           
                            if st.button("📧 Generate Email Draft"):
                                with st.spinner("Generating email draft..."):
                                    email_draft = generate_email_draft(user_details, st.session_state.question)
                                st.subheader("📤 Draft Email to Cyber Security Team:")
                                st.text_area("Email Draft:", value=email_draft, height=300)
                                st.info("Please review this draft, make any necessary changes, and send it to your Cyber Security Team.")
                                st.warning("🚨 Contact your IT security team or bank immediately for further assistance.")
                        else:
                            st.success("✅ Good news: You haven't clicked any links. Here are some tips to protect yourself from phishing:")
                            st.markdown("""
                            1. Always verify the sender's email address
                            2. Be cautious of urgent or threatening language
                            3. Don't click on suspicious links or download attachments
                            4. If unsure, contact the supposed sender through official channels
                            """)
                    else:
                        st.success("✅ This message appears to be legitimate. However, always exercise caution when dealing with sensitive information.")
                else:
                    st.error("❌ Error: Unable to determine if the message is a scam. Please review the AI's response carefully.")
       
        with col2:
            st.subheader("ℹ️ About")
            st.info("""
            This Cyber Security Crime Detector uses AI to analyze messages and emails for potential phishing attempts and other cyber security threats.
           
            Simply paste the suspicious message into the text area and click "Analyze Message" to get an assessment.
           
            Remember: Always be cautious with suspicious messages and never share sensitive information unless you're absolutely sure it's safe.
            """)
           
            st.subheader("🔒 Security Tips")
            st.markdown("""
            - Always verify the sender's email address
            - Be wary of urgent or threatening language
            - Don't click on suspicious links or download attachments
            - Use strong, unique passwords for each account
            - Enable two-factor authentication when possible
            - Keep your software and systems updated
            - Report suspicious activity to your IT department
            """)
   
    with tab3:
        st.subheader("🔗 URL Safety Checker")
        url_to_check = st.text_input("Enter a URL to check:")
        if st.button("Check URL"):
            if url_to_check:
                with st.spinner("Checking URL safety..."):
                    is_safe = check_url_safety(url_to_check)
                if is_safe:
                    st.success(f"✅ The URL {url_to_check} appears to be safe.")
                else:
                    st.warning(f"⚠️ Exercise caution with {url_to_check}. It's not recognized as a known safe site.")
            else:
                st.warning("Please enter a URL to check.")
   
    with tab6:
        st.subheader("🧠 Cyber Security Quiz")
        questions = generate_security_quiz()
        for i, q in enumerate(questions):
            st.write(f"**Question {i+1}:** {q['question']}")
            user_answer = st.radio(f"Select an answer for question {i+1}:", options=q['options'], key=f"q{i}")
            if st.button(f"Submit Answer {i+1}"):
                if q['options'].index(user_answer) == q['correct']:
                    st.success("Correct!")
                    st.session_state.quiz_score += 1
                else:
                    st.error(f"Incorrect. The correct answer was: {q['options'][q['correct']]}")
       
        st.write(f"Your current score: {st.session_state.quiz_score}/{len(questions)}")
   
    with tab2:
        st.subheader("💬 Cyber Security Buddy")
        st.write("Ask questions about cyber crime, cyber security, or online safety.")
       
        # Display chat history
        for message in st.session_state.chat_history:
            with st.chat_message(message["role"]):
                st.write(message["content"])
       
        # User input
        user_input = st.chat_input("Type your question here...")
       
        if user_input:
            # Display user message
            with st.chat_message("user"):
                st.write(user_input)
           
            # Add user message to chat history
            st.session_state.chat_history.append({"role": "user", "content": user_input})
           
            # Generate and display assistant response
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    response = generate_chatbot_response(user_input)
                st.write(response)
           
            # Add assistant response to chat history
            st.session_state.chat_history.append({"role": "assistant", "content": response})
   
    with tab5:
        st.subheader("🔑 Password Tools")
       
        col1, col2 = st.columns(2)
       
        with col1:
            st.write("Generate a Strong Password")
            password_length = st.slider("Password Length", min_value=8, max_value=32, value=12)
            if st.button("Generate Password"):
                generated_password = generate_password(password_length)
                st.code(generated_password)
                st.info("Copy this password and store it securely!")
       
        with col2:
            st.write("Check Password Strength")
            password_to_check = st.text_input("Enter a password:", type="password")
            if st.button("Check Strength"):
                strength = check_password_strength(password_to_check)
                st.progress(strength / 5)
                if strength <= 2:
                    st.error("Weak password. Please improve it.")
                elif strength <= 4:
                    st.warning("Moderate password. Consider making it stronger.")
                else:
                    st.success("Strong password!")
   
    with tab4:
        st.subheader("🖥️ Security Dashboard")
       
        col1, col2 = st.columns(2)
       
        with col1:
            st.write("System Security Status")
            st.info("Firewall: Active")
            st.info("Antivirus: Up-to-date")
            st.info("Last System Update: 2 days ago")
           
            if st.button("Run Quick Scan"):
                with st.spinner("Scanning system..."):
                    time.sleep(3)  # Simulating scan
                st.session_state.last_scan_time = time.time()
                st.success("Scan completed. No threats detected.")
       
        with col2:
            st.write("Recent Activity")
            if st.session_state.last_scan_time:
                st.info(f"Last Quick Scan: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.session_state.last_scan_time))}")
            else:
                st.info("No recent scans")
           
            st.warning("2 unsuccessful login attempts detected")
            st.info("5 websites blocked due to potential threats")
       
        st.write("Security Recommendations")
        st.markdown("""
        1. Enable two-factor authentication on all accounts
        2. Update your software regularly
        3. Use a password manager for generating and storing strong passwords
        4. Be cautious when opening email attachments or clicking on links
        5. Regularly backup your important data
        """)
 
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.experimental_rerun()

    with tab7:
        display_useful_links()
 
def main():
    st.set_page_config(page_title="Enhanced Cyber Security Crime Detector", page_icon="🛡️", layout="wide")
   
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
 
    if not st.session_state.logged_in:
        login_page()
    else:
        main_content()
 
if __name__ == "__main__":
    main()