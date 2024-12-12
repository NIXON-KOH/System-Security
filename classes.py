import mysql.connector
import datetime
class User:
    def __init__(self, idno:str, name:str, email:str, power:int, imagepth=str):
        self.id = idno
        self.name = name
        self.email = email
        self.power = power
        self.ipth = imagepth
    
    def get_id(self):
        return self.id
    
    def get_name(self):
        return self.name
    
    def get_email(self):
        return self.email
    
    def get_power(self):
        return self.power

    def get_imgpth(self):
        return self.ipth
    
class UserDatabase:
    def __init__(self, password):
        self.db = mysql.connector.connect(
            host="localhost",
            user="root",
            password=password,
            database="pythonlogin"
        )
        self.cursor = self.db.cursor(buffered=True)

    def insert_query(self,sql,val):
        self.cursor.execute(sql, val)
        self.db.commit()

    def select_1(self,select):
        self.cursor.execute(select)
        res = self.cursor.fetchone()
        return res
    
    def update(self, update):
        self.cursor.execute(update)
        self.db.commit()
        return 
    
    def select_all(self,select):
        self.cursor.execute(select)
        res = self.cursor.fetchall()
        return res
    
    def log(self, user,msg):
        self.cursor.execute("INSERT INTO logs VALUES (NULL,%s,%s,%s)",(datetime.datetime.now(), user, msg))
        self.db.commit() 