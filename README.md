import sqlite3
import smtplib
from tkinter import *
from tkinter import ttk, messagebox
from datetime import datetime
from cryptography.fernet import Fernet
from matplotlib import pyplot as plt
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import bcrypt

# Encryption Key
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

# Database Setup
conn = sqlite3.connect("mental_health_scribe.db")
cursor = conn.cursor()

# Create Tables
cursor.execute("""
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id TEXT UNIQUE,
    name TEXT,
    age INTEGER,
    diagnosis TEXT,
    medications TEXT,
    session_notes TEXT,
    symptoms TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id TEXT,
    date TEXT,
    time TEXT,
    description TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
)
""")
conn.commit()

# Utility Functions
def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(data):
    return cipher.decrypt(data.encode()).decode()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def add_appointment(patient_id, date, time, description):
    try:
        cursor.execute("""
        INSERT INTO appointments (patient_id, date, time, description)
        VALUES (?, ?, ?, ?)""", (patient_id, date, time, description))
        conn.commit()
        messagebox.showinfo("Success", "Appointment added successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Could not add appointment: {e}")

def plot_symptom_trends(patient_id):
    cursor.execute("SELECT symptoms FROM patients WHERE patient_id=?", (patient_id,))
    result = cursor.fetchone()
    if result:
        symptoms_data = decrypt_data(result[0])
        if symptoms_data:
            dates = []
            severities = []
            for entry in symptoms_data.split("\n"):
                if entry.strip():
                    date, severity = entry.split(": ")
                    dates.append(datetime.strptime(date.strip("[]"), "%Y-%m-%d"))
                    severities.append(int(severity))
            plt.plot(dates, severities, marker="o", linestyle="-")
            plt.title(f"Symptom Trends for Patient {patient_id}")
            plt.xlabel("Date")
            plt.ylabel("Severity")
            plt.grid(True)
            plt.show()
        else:
            messagebox.showinfo("Info", "No symptom data to display.")
    else:
        messagebox.showerror("Error", "Patient not found!")

def send_email(receiver_email, subject, body, attachment=None):
    try:
        sender_email = "your_email@example.com"
        sender_password = "your_password"
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = receiver_email
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        if attachment:
            with open(attachment, "rb") as file:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(file.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={attachment}")
                msg.attach(part)

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            messagebox.showinfo("Success", "Email sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Could not send email: {e}")

# GUI
def main_gui():
    root = Tk()
    root.title("Psychiatric Mental Health Scribe")
    root.geometry("800x600")

    tabs = ttk.Notebook(root)
    tabs.pack(expand=1, fill="both")

    # Add Patient Tab
    add_patient_tab = Frame(tabs)
    tabs.add(add_patient_tab, text="Add Patient")
    Label(add_patient_tab, text="Patient ID").pack()
    patient_id_var = StringVar()
    Entry(add_patient_tab, textvariable=patient_id_var).pack()
    Label(add_patient_tab, text="Name").pack()
    name_var = StringVar()
    Entry(add_patient_tab, textvariable=name_var).pack()
    Label(add_patient_tab, text="Age").pack()
    age_var = IntVar()
    Entry(add_patient_tab, textvariable=age_var).pack()
    Label(add_patient_tab, text="Diagnosis").pack()
    diagnosis_var = StringVar()
    Entry(add_patient_tab, textvariable=diagnosis_var).pack()
    Button(add_patient_tab, text="Add Patient", command=lambda: add_patient(patient_id_var.get(), name_var.get(), age_var.get(), diagnosis_var.get())).pack()

    # Symptom Trends Tab
    symptoms_tab = Frame(tabs)
    tabs.add(symptoms_tab, text="Symptom Trends")
    Label(symptoms_tab, text="Patient ID").pack()
    trend_patient_id_var = StringVar()
    Entry(symptoms_tab, textvariable=trend_patient_id_var).pack()
    Button(symptoms_tab, text="Show Trends", command=lambda: plot_symptom_trends(trend_patient_id_var.get())).pack()

    # Email Reports Tab
    email_tab = Frame(tabs)
    tabs.add(email_tab, text="Email Report")
    Label(email_tab, text="Receiver Email").pack()
    email_var = StringVar()
    Entry(email_tab, textvariable=email_var).pack()
    Label(email_tab, text="Subject").pack()
    subject_var = StringVar()
    Entry(email_tab, textvariable=subject_var).pack()
    Label(email_tab, text="Body").pack()
    body_var = StringVar()
    Entry(email_tab, textvariable=body_var).pack()
    Label(email_tab, text="Attachment Path").pack()
    attachment_var = StringVar()
    Entry(email_tab, textvariable=attachment_var).pack()
    Button(email_tab, text="Send Email", command=lambda: send_email(email_var.get(), subject_var.get(), body_var.get(), attachment_var.get())).pack()

    root.mainloop()

if __name__ == "__main__":
    main_gui()
