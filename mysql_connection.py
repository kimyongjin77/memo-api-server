import mysql.connector

def get_connection():
    connection = mysql.connector.connect(
        host = 'yh-db.ckdh7nnfozjl.ap-northeast-2.rds.amazonaws.com',
        database='memo2_db',
        user='memo2_user',
        password='1234'
    )
    
    return connection
    