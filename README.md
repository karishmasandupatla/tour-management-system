# Tour Management System

A web-based application to simplify tour planning, management, and booking. This system enables users to explore available tours, book them, leave reviews, and manage their travel experience—all through a clean and user-friendly interface.

---

## Objective

- To develop a complete **Tour Management System** that allows:
  - Customers to view, search, and book tours
  - Admins to manage tours, payments, and reviews
  - Seamless interaction between frontend and backend using Flask and MongoDB

---

## Challenges Faced

- Connecting multiple modules (booking, review, admin, user) into a unified system  
- Structuring MongoDB collections for bookings, users, and tours  
- Implementing role-based login (admin vs. user)  
- Handling form validations and edge cases (duplicate bookings, empty forms, etc.)  
- Deploying to a cloud platform (Firebase Studio)  

---

##  Outcome

- Fully functional Tour Management web app with:
  - Secure login system and session handling  
  - API integrations for booking, payments, and review features  
  - Structured, modular code for scalability and maintenance  
  - Successfully connected MongoDB Atlas for cloud-based data storage  
  - Project uploaded and version-controlled using GitHub  

---

## 🛠️ Tech Stack

| Component        | Technology            |
|------------------|------------------------|
| Backend API       | Python Flask           |
| Frontend UI       | HTML, CSS, Bootstrap   |
| Database          | MongoDB Atlas          |
| Hosting (optional)| Firebase Studio        |
| Tools Used        | Git, GitHub, Postman   |

---
## Author:Karishma Sandupatla
🌐 GitHub:https://github.com/karishmasandupatla
📧 Email:ksbyte22@gmail.com 

--

##  How to Run

```bash
git clone https://github.com/karishmasandupatla/tour-management-system.git
cd tour-management-system

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # (for Windows)

# Install dependencies
pip install -r requirements.txt

# Run the app
python user_web/user_app.py

