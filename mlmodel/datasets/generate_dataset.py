import csv
import random
import os

names = ["Rahul", "Priya", "Amit", "Neha", "Vikram", "Sneha", "Karthik", "Ananya", "Rohan", "Divya", "Manish", "Aisha"]
roles = ["Software Engineer", "Data Scientist", "Frontend Developer", "Marketing Intern", "HR Executive", "Business Analyst", "Content Writer", "Graphic Designer", "ML Intern", "Cybersecurity Trainee"]
companies = ["TechNova", "NexaByte", "CloudSync", "GlobalTech", "InfoEdge", "MediaPulse", "DesignHub", "CodeCraft", "AppForge", "BuzzBee Digital", "Razorpay", "Flipkart", "Zomato"]
fake_companies = ["MegaSoft", "DigiCorp", "CyberNex Labs", "Top MNC", "Fortune 500 Startup", "FlexiWork", "DreamJobs2026", "EarnBig Agency"]
amounts = ["999", "1499", "1999", "2500", "2999", "3499", "4999", "5000", "7999", "12999"]
stipends = ["10000", "15000", "20000", "25000", "30000", "40000", "50000", "60000", "1 Lakh"]
fee_types = ["registration fee", "security deposit", "processing fee", "kit charges", "onboarding fee", "training fee", "certification cost", "background check fee"]

fake_templates = [
    "Congratulations {name}! You are selected for {role} at {fake_company}. Stipend: Rs {stipend}/month. To lock your spot, pay a {fee_type} of Rs {amount} via GPay to 9876543210 within {hours} hours.",
    "URGENT: Your application for {role} is approved. Salary: Rs {stipend}. No interview needed! Pay Rs {amount} {fee_type} immediately to confirm. Reply YES to get payment link.",
    "Dear {name}, we are offering a work from home {role} internship. Earn Rs {stipend} monthly. Registration cost is just Rs {amount}. Pay via UPI: fake@paytm. Act fast, only 2 seats left!",
    "Hi! Earn Rs {stipend} per month as a {role}. Zero experience required. We provide full training. Just pay Rs {amount} for the learning material and start earning tomorrow. WhatsApp us for details.",
    "ALERT: Your offer for {role} at {fake_company} will expire in {hours} hours. Please transfer Rs {amount} refundable {fee_type} to our bank account. Send receipt here to get your offer letter.",
    "Greetings {name}. You've been shortlisted for {role} internship. Guaranteed PPO! To proceed to the final round, pay the assessment fee of Rs {amount} here: http://bit.ly/fake-payment.",
    "Job Offer: {role}. Salary: Rs {stipend}. Work from home. Share this message with 5 friends and pay Rs {amount} joining fee. 100% placement guarantee. DM on Insta or WhatsApp for info.",
    "Dear Student, Exclusive internship drive for {role}. Top companies hiring! Pay Rs {amount} to enroll in our placement program. Money back guarantee if not placed. Call +91-9988776655.",
    "You're hired! Role: {role}. Stipend: Rs {stipend}. Please verify your identity by sending your Aadhaar card, PAN card, and Rs {amount} background check fee. Contact only via WhatsApp.",
    "Hi {name}, your profile was selected for a premium {role} internship. Benefits include free MacBook and Rs {stipend} stipend. Pay the Rs {amount} courier charges for the laptop delivery today.",
    "Glad to inform you that, we have selected you for a {hours} month internship by details provided by the placement dept. To ensure you will complete the project, you need to deposit {amount}. Make sure you do it with 24hrs."
]

legit_templates = [
    "Dear {name}, we are pleased to offer you the {role} Internship at {company}. Your stipend will be Rs {stipend}/month. Please confirm your acceptance by replying to this email/message.",
    "Hi {name}, congratulations! You have cleared all rounds for the {role} position at {company}. Your joining date is next Monday. The HR team will send the official offer letter to your email.",
    "Hello {name}, following your interview, {company} is excited to extend a {role} internship offer. Duration is 3 months with a stipend of Rs {stipend}. Please check your email for the DocuSign link.",
    "Dear Candidate, your application for {role} at {company} is successful. We are offering Rs {stipend} per month. There are no fees associated with this offer. Let us know if you accept.",
    "Hi {name}, this is HR from {company}. You are selected for the {role} intern role. Work mode is remote. Stipend: Rs {stipend}. Please reply YES to confirm your interest.",
    "Congratulations {name}! We loved your assignment and want you to join {company} as a {role} Intern. We offer Rs {stipend}/month. Official onboarding details will follow on your university email.",
    "Dear {name}, {company} Campus Recruitment team is happy to offer you a summer internship for the {role} profile. Please upload your academic transcripts to the HR portal within {hours} hours.",
    "Hello {name}, based on your performance in the hackathon, {company} is offering you a {role} internship. Stipend: Rs {stipend}. Background verification will be initiated shortly by our vendor.",
    "Hi {name}, great news! You're hired as a {role} at {company}. We do not charge any registration fees. Please complete your profile on our careers portal to generate the offer letter.",
    "Dear {name}, welcome to {company}! We are thrilled to offer you the {role} Internship. Your monthly stipend is Rs {stipend}. A detailed email has been sent. Please revert within {hours} hours.",
    "Hi {name}, thanks for applying to {company}. You are selected for the {role} position. Start date: 1st of next month. Remote work. Please confirm acceptance to proceed with onboarding.",
    "Good evening {name}, your final interview for {role} at {company} was positive. We are offering you a 6-month internship at Rs {stipend}/month. Accept via the HR portal."
]

def generate_message(is_legit):
    templates = legit_templates if is_legit else fake_templates
    template = random.choice(templates)
    return template.format(
        name=random.choice(names),
        role=random.choice(roles),
        company=random.choice(companies),
        fake_company=random.choice(fake_companies),
        amount=random.choice(amounts),
        stipend=random.choice(stipends),
        fee_type=random.choice(fee_types),
        hours=random.choice(["2", "6", "12", "24", "48"])
    )

output_file = os.path.join(os.path.dirname(__file__), 'offer_messages_generated.csv')

with open(output_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['message', 'label'])
    # Generate 50 fake
    for _ in range(50):
        writer.writerow([generate_message(is_legit=False), 0])
    # Generate 50 legit
    for _ in range(50):
        writer.writerow([generate_message(is_legit=True), 1])

print(f"Generated 100 messages in {output_file}")
