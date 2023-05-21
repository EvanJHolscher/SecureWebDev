# SecureWebDev

Group Members:
Evan Holscher evanholscher@csu.fullerton.edu

Database Setup:
Installation (MariaDB):
sudo apt update
1. sudo apt-get install mariadb-server
2. Once the installation completes run: sudo service mariadb start

3. sudo mysql_secure_installation
4. Press enter when prompted for the current root password
5. Provide a new root password
6. Retype the root password
7. Answer "Yes" to all questions
8. Connect to the DB from command line as root user:

   sudo mysql -u root -p

9. Provide the root password
10. Create a database called "users"

   CREATE DATABASE users;

11. Switch to the "users" database

   USE users;

12. Create a table within the database called "appusers".
    Our table will consist of the username, password, session, salt, and info columns
    that are all character strings of 255 characters:

    CREATE TABLE appusers (username VARCHAR(255), password VARCHAR(255), info VARCHAR(255), session VARCHAR(255), salt VARCHAR(255));

13. Insert a user into the table:

    INSERT INTO appusers VALUES('testuser1', 'passw0rd',  'Where are the cats?',  'somesessionvalue', 'somesaltvalue');
14. Create a user account (appaccount) that will be used by our node.js application to 
    access the "users" database and give it priveleges to access all tables in the "users" 
    database:

    GRANT INSERT, UPDATE, SELECT ON users.* TO 'appaccount'@'localhost' IDENTIFIED BY 'apppass';

15. Exit from the root session:

    exit 

16. Login from command line as appaccount to test the account:

    mysql -u appaccount -p

17. Enter the password (apppass)

18. Select the "users" database:

    use users;

19. Display the appusers table:

  SELECT * FROM appusers;

Output:

+----------+----------+---------------------+-----------------+--------------+
| username | password | info                | session         | salt         |
+----------+----------+---------------------+-----------------+--------------+
|testuser1 | passw0rd | Where are the cats? | somesessionvalue| somesaltvalue|
+----------+----------+---------------------+-----------------+--------------+
20. Try inserting values into the table:

    INSERT INTO appusers VALUES ('test_user2', 'testpass', 'Hellllo???', 'sessionID', 'salty');

21. Display the database users to see if the record has been inserted. 

MariaDB [users]> select * from appusers;

+----------+----------+---------------------+-----------------+--------------+
| username | password | info                | session         | salt         |
+----------+----------+---------------------+-----------------+--------------+
| testuser1 | passw0rd| Where are the cats? | somesessionvalue| somesaltvalue|
| test_user2| testpass| hellllo???          | sessionID       | salty        |
+----------+----------+---------------------+-----------------+--------------+
22. Once it is verified that the appaccount can properly interact with the database, switch to the
    root user and drop the database to ensure proper functionality.
23. Switch back to the appaccount account once the db rows are clear.


Install Libraries:

1. Express:
Description: A fast, unopinionated, and minimalist web framework for Node.js.
Installation: npm install express

2. Express Session:
Description: Simple middleware for managing sessions in Express.
Installation: npm install express-session

3. Body Parser:
Description: Node.js body parsing middleware.
Installation: npm install body-parser

4. MySQL:
Description: A Node.js driver for MySQL.
Installation: npm install mysql

5. CryptoJS:
Description: JavaScript library for cryptographic operations.
Installation: npm install crypto-js

6. XSS:
Description: A library to sanitize user input and prevent cross-site scripting attacks.
Installation: npm install xss

7. Check Password Strength:
Description: A library to check the strength of a password.
Installation: npm install check-password-strength

8. Password Validator:
Description: A library to validate passwords based on custom rules.
Installation: npm install password-validator

9. Bcrypt:
Description: A library to encrypt and hash passwords.
Installation: npm install bcrypt

10. HTTPS:
Description: A module to create HTTPS servers.
Installation: No installation required. It's a built-in module in Node.js.

11. FS (File System):
Description: A module to handle file system operations.
Installation: No installation required. It's a built-in module in Node.js.

install all libraries: 
npm install express express-session body-parser mysql crypto-js xss check-password-strength password-validator bcrypt https fs

TO RUN PROGRAM:
-- In working directory of sessions.js -- 
node sessions.js
