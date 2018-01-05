import os
import uuid
import random
import hashlib
import sqlite3
import binascii

import rsa
from Crypto.Cipher import AES


def encrypt_with_aes(msg, key) -> str:
    key_32 = key.rjust(32, '*') if len(key) <= 32 else key[:32]
    cipher = AES.new(key_32, AES.MODE_CFB, 'This is an IV456')
    return binascii.hexlify(cipher.encrypt(msg)).decode('utf8')


def decrypt_with_aes(encrypted_msg, key) -> str:
    key_32 = key.rjust(32, '*') if len(key) <= 32 else key[:32]
    cipher = AES.new(key_32, AES.MODE_CFB, 'This is an IV456')
    return cipher.decrypt(binascii.unhexlify(encrypted_msg)).decode('utf8')


def get_db_connect(app) -> sqlite3.connect:
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv


def get_handled_password(password, salt) -> str:
    salted_pass = salt + password
    return hashlib.md5(salted_pass.encode('utf8')).hexdigest()


def encrypt_salt_with_rsa(salt, users_uuid, app) -> str:
    if not os.path.isdir(os.path.join(app.root_path, "pem")):
        os.mkdir(os.path.join(app.root_path, "pem"))
    public, private = rsa.newkeys(512)
    # save private key as uuid.pem file
    with open(os.path.join(app.root_path, "pem", "{}.pem".format(users_uuid)), "wb") as f:
        f.write(private.save_pkcs1())
    # encrypt salt with public key
    crypto = rsa.encrypt(salt.encode('utf8'), public)
    return binascii.hexlify(crypto).decode('utf8')


def decrypt_salt(uuid, crypted_salt, app) -> str:
    with open(os.path.join(app.root_path, "pem", "{}.pem".format(uuid)), "rb") as f:
        keydata = f.read()
    private_key = rsa.PrivateKey.load_pkcs1(keydata)
    decrypro = rsa.decrypt(binascii.unhexlify(crypted_salt.encode('utf8')), private_key)
    return decrypro.decode('utf8')


def is_password_valid(username, password, db_connection, app) -> bool:
    db_resp = db_connection.execute("SELECT uuid, password, salt FROM users WHERE username is ?",
                                    [username])
    resp = db_resp.fetchall()[0]
    salt = decrypt_salt(uuid=resp['uuid'], crypted_salt=resp['salt'], app=app)
    original = resp['password']
    getted = get_handled_password(password=password, salt=salt)
    return original == getted


def get_uuid() -> str:
    return str(uuid.uuid1()).replace('-', '')


def get_users_props(username, password, db_connection) -> dict:
    db_resp = db_connection.execute("SELECT * FROM users WHERE username is ?", [username])
    creds = dict(db_resp.fetchall()[0])
    for key in ('age', 'email'):
        creds[key] = decrypt_with_aes(creds[key],password)
    return creds


def is_user(username, db_connections) -> bool:
    db_resp = db_connections.execute("SELECT username from users WHERE username is ?",
                                     [username])
    users = db_resp.fetchall()
    return bool(users)


def handle_signup_request(form_content, db_connection, app) -> None:
    salt = ''.join(chr(random.randint(33, 126)) for i in range(10))
    users_uuid = get_uuid()
    sql_req = "INSERT INTO users (uuid, username, password, age, email, salt) " \
              "values (:uuid, :username, :password, :age, :email, :salt)"
    kwargs = {"uuid": users_uuid,
              "username": form_content['username'],
              "password": get_handled_password(password=form_content['password'], salt=salt),
              "age": encrypt_with_aes(msg=form_content['age'], key=form_content['password']),
              "email": encrypt_with_aes(msg=form_content['email'], key=form_content['password']),
              "salt": encrypt_salt_with_rsa(salt=salt, users_uuid=users_uuid, app=app)}
    db_connection.execute(sql_req, kwargs)
    db_connection.commit()
