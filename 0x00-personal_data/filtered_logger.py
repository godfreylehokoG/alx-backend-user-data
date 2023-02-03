#!/usr/bin/env python3
""" Encrypting passwords """
import bcrypt


def hash_password(password: str) -> bytes:
    """ expects one string argument name password and returns a salted,
    hashed password, which is a byte string. """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def is_valid(hashed_password: bytes, password: str) -> bool:
    """ expects 2 arguments and returns a boolean. """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def filter_datum(fields: List[str],
                 redaction: str,
                 message: str,
                 separator: str) -> str:
    """ returns the log message obfuscated """
    for item in fields:
        message = re.sub(fr'{item}=.+?{separator}',
                         f'{item}={redaction}{separator}', message)
    return message


def get_logger() -> logging.Logger:
    """ returns a logging.Logger object """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ returns a connector to the database """
    return mysql.connector.connect(
                    host=os.environ.get('PERSONAL_DATA_DB_HOST', 'localhost'),
                    database=os.environ.get('PERSONAL_DATA_DB_NAME', 'root'),
                    user=os.environ.get('PERSONAL_DATA_DB_USERNAME'),
                    password=os.environ.get('PERSONAL_DATA_DB_PASSWORD', ''))


def main():
    """ obtain a database connection using get_db and retrieve all rows in the
        users table and display each row under a filtered format """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    result = cursor.fetchall()
    for row in result:
        message = f"name={row[0]}; " + \
                  f"email={row[1]}; " + \
                  f"phone={row[2]}; " + \
                  f"ssn={row[3]}; " + \
                  f"password={row[4]};"
        print(message)
        log_record = logging.LogRecord("my_logger", logging.INFO,
                                       None, None, message, None, None)
        formatter = RedactingFormatter(PII_FIELDS)
        formatter.format(log_record)
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
