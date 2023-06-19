from flask_app.config.mysqlconnection import connectToMySQL
import re
from flask import flash
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class User:
    DB = 'login_and_register_schema'

    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']

    @staticmethod
    def validate_user(new_user):
        is_valid = True
        if len(new_user['first_name']) < 3:
            flash('First name must be at least 3 characters')
            is_valid = False
        if len(new_user['last_name']) < 3:
            flash('Last name must be at least 3 characters')
            is_valid = False
        if not EMAIL_REGEX.match(new_user['email']):
            flash('Invalid email!!!')
            is_valid = False
        if len(new_user['password']) < 8:
            flash('Password must be at least 8 characters')
            is_valid = False
        if new_user['password'] != new_user['confirm_password']:
            flash('Passwords did not match')
            is_valid = False

        return is_valid

    @classmethod
    def createUser(cls, data):
        query = """
        INSERT INTO users (first_name, last_name, email, password)
        VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);
        """
        result = connectToMySQL(cls.DB).query_db(query, data)
        return result

    @classmethod
    def getUserById(cls, data):
        query = """
        SELECT * FROM users
        WHERE id = %(user_id)s;
        """

        result = connectToMySQL(cls.DB).query_db(query, data)
        return cls(result[0])

    @classmethod
    def getUserByEmail(cls, data):
        query = """
        SELECT * FROM users
        WHERE email = %(email)s;
        """

        result = connectToMySQL(cls.DB).query_db(query, data)
        if len(result) < 1:
            return False
        return cls(result[0])
