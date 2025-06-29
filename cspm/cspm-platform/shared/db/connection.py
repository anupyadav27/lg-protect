import psycopg2

def get_db_connection():
    connection = psycopg2.connect(
        dbname="cspm",
        user="admin",
        password="password",
        host="localhost",
        port=5432
    )
    return connection