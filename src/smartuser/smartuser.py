import base64
import json
import os
import sqlite3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes



class sql:
    '''
    Manages SQL operations.

    PARAMETERS:
        [str] File NAME or PATH - 'data.db'

    '''
    FILE_PATH_NAME = 'data.db'

    def __init__(self, file:str = FILE_PATH_NAME): 


        assert isinstance(file, str), 'Invalid DB file path/name, it must be str type.'
        
        file = file.replace('\\', '/')

        self.__file = file

        try:
            con = sqlite3.connect(file)
            self.__connection = con
        except:
            print('''Error trying to connect to the db.
                     Your file needs to had .db suffix.
                     Leave it blank and i'll be the value on FILE_PATH_NAME ''')




    @property
    def file(self):
        return self.__file

    @property
    def connection(self):
        return self.__connection


    def connect(self):
        '''Opens again a connection with his database file.'''

        try:
            con = sqlite3.connect(self.__file)
            self.__connection = con
        except:
            con = None
            print('Error trying to connect to the db.')

        assert not isinstance(con, type(None))

        


    def close(self):
        '''Close the connection with the database.'''

        self.__connection.close()



    def execute(self, sentence:str, extra_argument = None):
        '''
        Execute a SQL statement.

        PARAMETERS:
            [str] sentence
             [any:optional] argument to the sentence - False
        '''
        
        assert isinstance(sentence, str), 'Invalid sentence to execute, it must be str type.'
        

        try:
            #   if the sentence needs additional arguments.
            _ = self.connection.cursor().execute(sentence) if isinstance(extra_argument, type(None)) else self.__connection.cursor().execute(sentence, extra_argument)
            
            return _ 
        except Exception as r:
            raise ValueError(f'Error trying to execute the sentence: {r}')

    def migrate(self, users:list = []):
        '''
        Migrate users to the bound database. 
        
        PARAMETERS:
            [list] users - []
        '''

        assert isinstance(users, list), 'Invalid users argument, it must be a [user] objects list or a [user] object.'

        assert users != [], 'Invalid users argument, it must not be empty.'

        for e in users: assert isinstance(e, user), "Invalid list items, these must be [USER] objects."  

        username_list = []

        try:
            user_table = self.execute('SELECT * FROM user')

        except Exception as exc:
            print(exc)
            try:

                #   Table user does not exist
                self.execute('''CREATE TABLE user(id INTEGER PRIMARY KEY AUTOINCREMENT, username VARCHAR UNIQUE, password VARCHAR NOT NULL)''')
                user_table = self.execute('SELECT * FROM user')

                for user_tuple in user_table.fetchall():
                    #   Create a list with usernames
                    username_list.append(user_tuple[1])

            except Exception as exc:
                print(exc)



        for user_ in users:
            if user_.username not in username_list:
                #   Inserts user record into database.

                self.execute(f'INSERT INTO user (username, password) VALUES(?,?);',(user_.username, user_.password))
                self.connection.commit()
                print(f'User [{user_.username}] was added into the database.')

    def update(self, user_object = None):
        '''
        Update the user in the associated database.

        PARAMETERS:
            [user] object

        '''

        assert isinstance(user_object, user), 'Invalid function calling, you must specify at least 1 and only 1 argument that must be a [user] object'

        try:

            _ = self.execute(f'SELECT * FROM user WHERE username="{user_object.username}"')

            for i in _.fetchall():

                if i[2] != user_object.password:
                    _ = self.execute(f'UPDATE user SET password="{user_object.password}" WHERE username="{user_object.username}"')
                    self.connection.commit()
                    print(f'{user_object} password updated.')

            _ = self.execute(f'SELECT * FROM user WHERE password="{user_object.password}"')

            for i in _.fetchall():

                if i[1] != user_object.username:
                    _ = self.execute(f'UPDATE user SET username="{user_object.username}" WHERE password="{user_object.password}"')
                    self.connection.commit()
                    print(f'{user_object} username updated.')

        except Exception as exc:
            print(exc)
            print(f'There is an error in migration!')

    def get(self, username:str, safe:bool = True) -> dict|None:
        '''
        Returns a single user from the database as a dict.

        PARAMETERS:
            [str] username for fetch
            [bool:optional] safe = True -> in case of error, unsafe mode throws error, safe mode throw None.
        '''

        assert isinstance(username, str), 'Invalid username argument, it must be str type'
        assert isinstance(safe, bool), 'Invalid safe argument, it must be bool type'
        try:
            U = self.execute(f'SELECT * FROM user WHERE username="{username}"').fetchone()
            return {'id':U[0],'username':U[1],'password':[2]}
        except Exception as e:
            if safe: raise AssertionError(e)
            if not safe: return None

    def fetch(self, table:str='user', json=False) -> list:
        '''
        Fetch for all users in associated database and return them as Tuple or JSON/dict list.

        PARAMETERS:
            [str] Table name - 'user'
            [bool:optional] True for json or dict / False tuple list - False
        '''

        assert isinstance(table, str), 'Invalid table argument, it must be str type.'
        assert isinstance(json, bool), 'Invalid json argument, it must be bool type.'

        try:
            tuples = self.execute(f'SELECT * FROM {table}').fetchall()
            if json:
                x = []
                for _id, _username, _password in tuples:
                    x.append({
                        'ID': _id,
                        'username': _username,
                        'password': _password
                        })
                return x
            return tuples
        except Exception as e:
            try:
                print(e)
                self.execute(f'SELECT * FROM {table}')
                print('No users in database.')
            except:
                print('No such table in database.')
                raise ValueError(f'The specified table {table} does not exist or there is some error on connection.')
            #   No users in database.
            return []

    def delete(self, user_object):
        ''' Execute a delete sentence and delete a row in the database.'''
        assert isinstance(user_object, str) or isinstance(user_object, user), 'Invalid argument, it must be a [user] object or a username as str type.'
        

        self.execute(f'DELETE FROM user WHERE username="{user_object.username if isinstance(user_object, user) else user_object}" ')
        self.__connection.commit()

    def __repr__(self) -> str:
        return f'[sql] object at {self.file}'



class user():
    '''
    Base class for user creation

    PARAMETERS:
        [str] username  
         [str] password
        [str:optional] hash algorithm - 'SHA256'

    Password format: SALT\_/ALGORITHM\_/HASH

    [list] users: Will contain ALL the instances created.
    '''


    def __init__(self, username:str=False, password:str = False, algo:str=hashes.SHA256):

        assert isinstance(username, str), 'Invalid username argument, it must be str type.'
        assert isinstance(password, str), 'Invalid password argument, it must be str type.'

        self.__username:str = self.change_username(username)

        self.__password:str = password if '\_/' in password else self.change_password(password, algo) 

        #   Migrate to DB if are not.
        if self.username not in [e['username'] for e in user.DB.fetch('user',True)]:
            self.migrate_to.sql(self, user.DB)

        try:
            if self.DB.get(self.username, False) == None:
                self.migrate_to.sql(self, user.DB)
        
            #   get from the database to check is correctly created and obtain its ID.
            user_object = self.DB.get(self.username)

            self.__id = user_object['id']

        except Exception as E:
            print(E)
            raise EnvironmentError('The user was not created properly due to some error.')


    @property
    def username(self):
        return self.__username

    @property
    def password(self):
        return self.__password

    @property
    def id(self):
        return self.__id

    @classmethod
    def run(self, file=None):
        '''
        Initializator method for bound a database. It means that the next operations with users will be with this database.

        Create a new database if not exist, same with the "user" table.
        Automatically creates and migrates all the [user] objects.

        PARAMETERS: 
            [str: optional] File NAME, PATH for database or a [sql] object - sql.FILE_PATH_NAME 
        
        '''

        if isinstance(file, type(None)): 
            file = sql.FILE_PATH_NAME


        assert isinstance(file, str) or isinstance(file, sql), 'Invalid DB file path/name, it must be str type or a [sql] object.'
        
        #   bound main database.
        self.DB = sql(file) if isinstance(file, str) else file

        #   checks for a user table on the database, else creates it to avoid errors.
        try:
            self.DB.execute('SELECT * FROM user')
        except:
            self.DB.execute('''CREATE TABLE user(id INTEGER PRIMARY KEY AUTOINCREMENT, username VARCHAR UNIQUE, password VARCHAR NOT NULL)''')
                 
        #   clean local user objects.
        for e in [user_object for user_object in self.objects.all()]:
            self.objects.remove(e)

        #   fill local user objects based on the bound db.
        self.migrate_from.sql()
        

        

    @classmethod
    def exist(self, username:str):
        '''Returns a bool value whether the username exists in the local user objects or not.'''



        assert isinstance(username, str), 'Invalid username argument, it must be str type.'

        if username in [e.username for e in self.objects.all()]:
            return True
        return False

    def change_username(self, raw_user:str = ''):
        '''
        Username changer/creator.

        PARAMETERS:
            [str] raw username
        '''
        
        assert raw_user != '' and isinstance(raw_user, str), F'Invalid username argument "{raw_user}", it must be str type.'

        assert not self.exist(raw_user), f'Invalid username argument "{raw_user}", it is already in use.'

        if hasattr(self, 'username'):
            #   at change
            self.__username = raw_user
            self.DB.update(self)

        else:
            #   at creation
            return raw_user

    def change_password(self, raw_pass:str='',  algo=hashes.SHA256):
        '''
        Password changer/creator.
         New salt (therefore new hash and result) will be created on every executing.

        PARAMETERS:
            [str] raw password
             [str] raw algorithm - hashes.SHA256

        Password format: SALT\_/ALGORITHM\_/HASH
        SALT is STR _hex - ALGORITHM is STR - HASH is STR _B64
        '''


        assert issubclass(algo, hashes.HashAlgorithm), 'Invalid HASH ALGORITHM argument, it must inherit from cryptography.hazmat.primitives.hashes.'
        
        assert isinstance(raw_pass, str) and raw_pass != '', 'Invalid password argument, it must be str type.'


        salt = os.urandom(16)


        kdf = PBKDF2HMAC(
        algorithm = algo(),
        length = 32,
        salt = salt,
        iterations = 480000,
        )

        derived_password = kdf.derive(raw_pass.encode())
        
        p = f'{salt.hex()}\_/{algo.name.upper()}\_/{base64.urlsafe_b64encode(derived_password).decode()}'

        if hasattr(self,"password"):
            #   at change
            self.__password = p
            self.DB.update(self)

        else:
            #   at creation
            return p 

    def verify_password(self, raw_password:str):
        '''
        Returns a bool value whether the password is true or not.

        PARAMETERS:
            [STR] raw password

        EXAMPLE:
            user.objects.first().verify_password('HiSsTr0nGPassword')
        '''

        assert isinstance(raw_password, str), 'Invalid password, it must be str type.'

        bytes_password = raw_password.encode()

        salt, raw_algo, derived_password = self.__password.split('\_/', 2)
        
        salt = bytes.fromhex(salt)
        algo = eval(f'hashes.{raw_algo.upper()}')
        derived_password = base64.urlsafe_b64decode(derived_password)
        
        kdf = PBKDF2HMAC(
        algorithm = algo(),
        length = 32,
        salt = salt,
        iterations = 480000,
        )

        try:
            ify = kdf.verify(bytes_password, derived_password) == None
            return ify

        except:
            return False

    def __repr__(self):
        return f'[USER] {self.username}'


    class migrate_to:

        @classmethod
        def sql(self, user_objects=None, db_object=None):
            '''
            Access to the sql object if supplied, else to the bounded database and store the supplied user objects.

            PARAMETERS:
                [obj/list] objects to be migrated 
                 [class] SQL class to migrate to

            EXAMPLE: migrate_to.sql( user.objects.all(), sql('my_backup.db') )
            '''

            db_object = user.DB if isinstance(db_object, type(None)) else db_object

            assert isinstance(db_object, sql), 'Invalid db argument, it must be a [sql] object.'
            
            assert isinstance(user_objects, user) or isinstance(user_objects, list), 'Invalid user_objects argument, it must be a [user] object or a [user] object list.'
            

            user_objects = user_objects if isinstance(user_objects, list) else [user_objects]

            if isinstance(user_objects, list): 
                for list_object in user_objects: assert isinstance(list_object, user), 'Invalid user_objects in list, it must be ONLY [user] objects.'

            db_object.migrate(user_objects)

        @classmethod
        def json(self, include_password:bool = False):
            '''
            Returns a json from the list of local users.

            PARAMETERS:
                [bool:optional] include_password?
            '''

            assert isinstance(include_password, bool), 'Invalid include_password argument, it must be bool type.'
            
            return json.dumps([{'id': _user.id, 'username': _user.username, 'password': _user.password} if include_password else 
                    {'id': _user.id, 'username': _user.username} for _user in user.objects.all()])


    class migrate_from:

        @classmethod
        def sql(self, db_object = None, table:str='user') -> list:
            '''
            Given a sql object, it creates the users and stores them in the bound DB.

            PARAMETERS:
                [class] SQL object to migrate from  - user.DB
                 [str] Table name to migrate from. - 'user'
                 
            EXAMPLE: migrate_from.sql( sql('old_record.db') )
            '''

            db_object = user.DB if isinstance(db_object, type(None)) else db_object
            assert isinstance(db_object, sql), 'Invalid db_object argument, it must be a [sql] object'

            users_dict = db_object.fetch(table, True)

            #   Stores errors
            fl = []

            for _user in users_dict:
                try:
                    user.objects.create(_user['username'], _user['password'])
                except Exception as exc:
                    fl.append(exc)

            return print(f"METHOD: migrate_from.sql() finished with {len(fl)} errors{f': {[ e for e in fl]}' if len(fl) else '.'}")

        @classmethod
        def json(self, _json = {}, key_username:str = 'username', key_pass:str = 'password'):
            '''
            Given a json, a dict, a set or a list of them, it creates the users and stores them in the bound database.

            PARAMETERS:
                [set, dict, list.dict, list.sets] JSON objects to be created.
                 [str] key for username IF DICT present  'username'
                [str]  key for password IF DICT present  'password'

            EXAMPLES:
                [set] migrate_from.json( {'user','pass'} )
                 [dict] migrate_from.json( {'u':'Zac', 'pazz':'strong_PASSWORD_22'}, 'u', 'pazz' )
                [mixed list] migrate_from.json( [ {'username':'Zac', 'password':'weakpas'},
                                                  {'rick','PASS00c01014PASS'},
                                                  {'username':'Will', 'password':'0010pr02t2f2'} ] )  
            '''
            if isinstance(_json, str):
                _json = json.loads(_json)

            assert isinstance(_json, set) or isinstance(_json, dict) or isinstance(_json, list), 'Invalid JSON argument, it must be a list, a set or a dictionary.'
            
            assert len(_json) > 0, 'Invalid JSON argument, it must not be empty.'

            assert isinstance(key_username, str), 'Invalid key_username argument, it must be str type.'
            assert isinstance(key_pass, str), 'Invalid key_pass argument, it must be str type.'


            isdict = key_username in _json and key_pass in _json

            #   stores errors like key errors or name errors.
            fl = []

            if isinstance(_json, set) or isinstance(_json, dict):
                try:
                    if isdict:
                        user.objects.create(_json[key_username], _json[key_pass])
                    else:
                        #   is set
                        assert len(_json) == 2, 'Invalid json argument. It is wrongly defined, it must have ONLY TWO arguments for each set.'
                        
                        _json = list(_json)
                        user.objects.create(_json[0], _json[1])

                except Exception as z:
                    fl.append(z)

                return print(f"METHOD: migrate_from.json() finished with {len(fl)} errors{f': {[ e for e in fl]}' if len(fl) else '.'}")

            if isinstance(_json, list):
                for e in _json:
                    try:

                        if isinstance(e, str):
                            e = json.loads(e)

                        isdict = key_username in e and key_pass in e

                        if isdict:
                            user.objects.create(e[key_username], e[key_pass])
                        else:
                            #   is set
                            assert len(_json) == 2, 'Invalid json argument. It is wrongly defined, it must have ONLY TWO arguments for each set.'
                            
                            e = list(e)
                            user.objects.create(e[0], e[1])

                    except Exception as z:
                        fl.append(z)

                return print(f"METHOD: migrate_from.json() finished with {len(fl)} errors{f': {[ e for e in fl]}' if len(fl) else '.'}")


    class objects:
        
        __L = []

        @classmethod
        def append(self, object):
            self.__L.append(object)

        def create(username:str, password:str, algo:str = hashes.SHA256):
            '''
            Creates a user object on the database, after in the local storage and then returns it.

            PARAMETERS:
                [str]   Username
                 [str]  Password
                [str:optional] Hash algorithm type - hashes.SHA256

            EXAMPLE: 
                    create('Jeremy', 'mySTRongPASSw0rd')
                     create('Joseph', 'weakpass', hashes.MD5)

            '''

            assert isinstance(username, str), 'Invalid username argument, it must be str type.'
            assert isinstance(password, str), 'Invalid password argument, it must be str type.'

            _self = user(username, password)

            #   Update the object in the local objects class
            _self.objects.append(_self)

        @classmethod
        def delete(self, user_object = None, username = None):
            '''
            Delete user objects from database and local storage.

            PARAMETERS:
                [obj] [OBJECT USER]
                          or
                [str] username

            EXAMPLE:
                delete(username='rick')
                 delete(obj=objects.first())
            '''
            
            assert isinstance(user_object, user) or isinstance(username, str), 'Invalid user_object or username argument, it must be a [user] object or str type respectively.'



            if isinstance(username, str):
                assert user.exist(username), f'Invalid username argument, it must exist.'

                user.DB.delete(username)

                for i, user_object_local in enumerate(self.__L):
                    if user_object_local.username == username:
                        self.__L.pop(i)
                        break

            if isinstance(user_object, user):
                
                user.DB.delete(user_object.username)

                for i, user_object_local in enumerate(self.__L):

                    print(user_object_local is user_object)

                    if user_object_local is user_object or user_object_local.username == user_object.username:
                        self.__L.pop(i)
                        break

        @classmethod
        def remove(self, user_object = None, username = None):
            '''
            Removes a user from the local storage, but not from the database.
             Used after bound a new database.

            PARAMETERS:
                [user] user_object 
                [str] username 
            '''

            assert isinstance(user_object, user) or isinstance(username, str), 'Invalid argument, it must be a [user] object or a username as str type.'

            if isinstance(user_object, user):
                for i, user_object_local in enumerate(self.__L):

                    if user_object_local is user_object or user_object_local.username == user_object.username:
                        self.__L.pop(i)
                        print('acaba de borrarse', user_object_local)
                        break
                        

            if isinstance(username, str):
                assert user.exist(username), f'Invalid username argument, it must exist.'

                for i, user_object_local in enumerate(self.__L): 
                    if user_object_local.username == username: 
                        self.__L.pop(i)
                        break
 
        @classmethod
        def all(self):
            '''Returns the local user objects list'''
            return self.__L

        @classmethod
        def get(self, username:str, safe:bool = True):
            '''
            Returns the user object specified based in his username or None if non exists.

            PARAMETERS:  
                [str] username 
                [bool:optional] safe throws error, unsafe throws None - True
            '''

            for user_object in self.__L:
                if user_object.username == username:
                    return user_object

            if safe: raise AssertionError('Invalid user, it must exist.')
            if not safe: return None

        @classmethod
        def last(self):
            assert len(self.__L) > 0, 'Invalid call, user list is empty therefore no last [user].'
            return self.__L[-1]
        
        @classmethod
        def first(self):
            assert len(self.__L) > 0, 'Invalid call, user list is empty therefore no first [user].'
            return self.__L[0]

        @classmethod
        def contains(self, filter:str = None, field:str = 'username'):
            '''
            Check if a user contains a string in the specified field.

            PARAMETERS:
                [str] filter to look up -IS CASE SENSITIVE-
                [str:optional] field to look up - 'username'

            EXAMPLES:
                contains('l', 'username') > [OBJECT] July, [OBJECT] Flamengo
                contains('SHA256', 'password') > [USER] example
            '''

            assert isinstance(filter, str) and filter != None, 'Invalid filter argument, it must be str type.'
            assert isinstance(field, str), 'Invalid field argument, it must be str type.'

            matchs = []
            for e in self.__L:
                if filter in getattr(e, field.lower()):
                    matchs.append(e)
            return matchs

user.run()