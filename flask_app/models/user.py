from flask_app.config.mysqlconnection import connectToMySQL

from flask_app import app

from flask import flash


import re	# the regex module
# create a regular expression object that we'll use later   
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

from flask_bcrypt import Bcrypt 
bcrypt = Bcrypt(app) 


class User:
    db = "login_reg_schema"
    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @staticmethod
    def validate_user(user):
        is_valid = True
        query = 'SELECT users.email FROM users WHERE email = %(email)s;'
        results = connectToMySQL('login_reg_schema').query_db(query,user)
        if len(results) >= 1:
            is_valid = False
            flash("That email is already in our database.", "register")
        if not EMAIL_REGEX.match(user['email']):
            is_valid = False
            flash("Invalid email format")
        if len(user['first_name']) < 2:
            flash("First Name is a required field.", "register")
            is_valid = False
        if len(user['last_name']) < 2: 
            flash("Last Name is a required field.", "register")
            is_valid = False
        if len(user['email']) < 1:
            flash("Email address required.", "register")
            is_valid = False
        if len(user['password']) < 8 :
            flash("Password must be at least  8 characters long.", "register")
            is_valid = False  
        elif not re.search("[A-Z]", user['password']):
            flash("Password must contain at least one uppercase letter.", "register")
            is_valid = False  
        elif not re.search("[0-9]", user['password']):
            flash("Password must contain at least one number.", "register")
            is_valid = False  
        if user['password'] != user['confirm']:
            is_valid = False
            flash('Passwords do not match.', "register")
        return is_valid 
    
  
    @classmethod
    def get_all(cls):
        query = "SELECT * FROM users;"
        results =  connectToMySQL(cls.db).query_db(query)
        users =[]
        for row in results:
            users.append(cls(row))
        return users


    @classmethod
    def get_one(cls,data):
        query = "SELECT * FROM users WHERE users.id = %(id)s;"
        user_from_db = connectToMySQL(cls.db).query_db(query,data)
        return cls(user_from_db[0])
    
    @classmethod
    def get_by_email(cls,data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL(cls.db).query_db(query,data)
        # Didn't find a matching user
        if len(result) < 1:
            return False
        return cls(result[0])

    @classmethod
    def save(cls,data):
        query = "INSERT INTO users (first_name, last_name, email, password, created_at,updated_at) VALUES (%(first_name)s,%(last_name)s, %(email)s, %(password)s, NOW(), NOW());"
        return connectToMySQL(cls.db).query_db(query,data)

    @classmethod
    def update(cls,data):
        query = "UPDATE users SET first_name=%(first_name)s, last_name=%(last_name)s, email=%(email)s, password=%(password)s, updated_at = NOW() WHERE id = %(id)s;"
        return connectToMySQL(cls.db).query_db(query,data)

    

    @classmethod
    def destroy(cls,data):
        query = "DELETE FROM users WHERE id = %(id)s;"
        return connectToMySQL(cls.db).query_db(query,data)
        
    
    


    

    
    
