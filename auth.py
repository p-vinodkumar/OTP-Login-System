from utils import generate_otp

USERS = ["vinod", "admin", "user123"]

def login_flow():
    username = input("Enter username: ")
    
    if username not in USERS:
        print("User not found!")
        return
    
    otp = generate_otp()
    print(f"OTP: {otp}")
    
    entered_otp = input("Enter OTP: ")
    
    if entered_otp == otp:
        print("Login Successful!")
    else:
        print("Wrong OTP!")