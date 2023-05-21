'use strict'

// process.env.NODE_ENV = 'production';  <<-- Causing issues with express-session

// Import express
const  express = require('express');

// Import client sessions
const sessions = require('express-session');

// The body parser
const bodyParser = require("body-parser");

// The mysql library
const mysql = require('mysql');

// CryptoJS used for generating secret
const crypto = require('crypto');
// Instantiate an express app
const app = express();

// To protect against XSS attacks
const xss = require('xss');

// Check password strength
const checkPasswordStrength = require('check-password-strength')

// Set password paramater requirements
const passwordValidator = require('password-validator');

// Encryption/Decryption for passwords
const bcrypt = require('bcrypt');	

const https = require('https');

const fs = require('fs');

const saltRounds = 10;

// Set the view engine
app.set('view engine', 'ejs');

// Setup https
const options = {
	key: fs.readFileSync('private.key'),
	cert: fs.readFileSync('securecert.crt')
};

// Connect to the database
const  mysqlConn = mysql.createConnection({
	host: "localhost",
	user: "appaccount",
	password: "apppass",
	port: 3307,
	multipleStatements: true
	
});

// Needed to parse the request body
// Note that in version 4 of express, express.bodyParser() was
// deprecated in favor of a separate 'body-parser' module.
app.use(bodyParser.urlencoded({ extended: true })); 


// This will generate a random base64 string of size length
function makeSecret(length){
	const randomBytes = crypto.randomBytes(Math.ceil((3 * length) / 4));
	return randomBytes.toString('base64').slice(0, length);
}
// Generates secret
const secretString = makeSecret(32);
console.log(secretString);
// The session settings middleware	
app.use(sessions({
  cookieName: 'session',
  secret: secretString,
  resave: false,
  saveUninitialized: true,
  cookie:{
	httpOnly: true,
	maxAge: 60 * 1000,
	secure: true,
  }

})); 


app.get('/error',(req,res)=>{
	throw new Error('Something went wrong!');
});

app.use((err,req,res,next)=>{
	console.log(err.stack);
	res.status(500).send('Internal Server Error');
});

// The default page
// @param req - the request
// @param res - the response
app.get("/", function(req, res){
	
	// Is this user logged in?
	if(req.session.username)
	{
		// Yes!
		res.redirect('/dashboard');
	}
	else
	{
		// No!
		res.render('loginpage');
	}

});

// The login page
// @param req - the request
// @param res - the response
app.get('/dashboard', function(req, res){
	// Is this user logged in? Then show the dashboard
	if(req.session.username)
	{
		res.render('dashboard', {username: req.session.username});
	}
	//Not logged in! Redirect to the mainpage
	else
	{
		res.redirect('/');
	}

});




// The login script
// @param req - the request
// @param res - the response
app.post('/login', function(req, res) {
	// Get username/password from form
	const username = xss(req.body.username).toString().toLowerCase();
	const password = req.body.password;
  
	// Retrieve the salt from the database for the given username
	let selectQuery = "USE users; SELECT salt, password FROM appusers WHERE username = ?";
	mysqlConn.query(selectQuery, [username], function(err, salt) {
	  if (err) {
		throw new Error("Query selecting salt");
	  }
  
	  // Check if the user exists
	  if (salt[1].length == 0) {
		return res.render('loginpage', { error: 'Invalid username or password' });
	  }
	  console.log(salt[1].length)

	  // Retrieve the stored salt
	  const storedSalt = salt[1][0].salt;
	  
	  // Hash the provided password with the retrieved salt
	  bcrypt.hash(password, storedSalt, function(err, hash) {
		if (err) {
		  throw new Error("Hashing given password and retrieved salt");
		}
  
		// Compare the generated hash with the stored hash
		let storedHash = salt[1][0].password;
		console.log(storedHash);
		bcrypt.compare(password,storedHash, async function(err, result) {
		  if (err) {
			throw new Error("Comparing stored hash with password");
		  }
  
		  // Check if the passwords match
		  if (result) {
			console.log("Passwords match!");
			let updateQuery = "UPDATE appusers SET session = ? WHERE username = ?";

			// Chat GPT suggested wrapping this in a promise due to some errors I was receiving.
			await new Promise((resolve, reject) => {
				mysqlConn.query(updateQuery, [req.session.id, username], function(err, result) {
					if (err) {
					reject(err);
					} else {
					console.log("Session ID stored in the database " + req.session.id);
					resolve(result);
					}
				});
			});
				
		  } else {
			// Passwords don't match, show generic message
			console.log("Passwords do NOT match!");
			return res.render('loginpage', {error: "Incorrect Information"});
		  }
		  // If signed in, redirect to dashboard
		  req.session.username = username;
		  return res.redirect('/dashboard');
		});
	  });
  });
});

app.get('/register', function(req, res){
	res.render('registerpage', {error: null, passwordError: false})
});

// Schema to validate password
const schema = new passwordValidator();
schema
.is().min(10) 			// Minimum length of 10
.has().uppercase()  	// Must have at least 1 uppercase character
.has().lowercase() 		// Must have at least 1 lowercase character
.has().digits(2)		// Must have at least 2 digits
.has().symbols();		// Must have at least 1 symbol

app.post('/register', function(req, res){

	// Get username/password from form and sanitize
	let userName = xss(req.body.username).toString().toLowerCase();
	let password = req.body.password;

	// Check for max lenght recommendation of 64 characters for username/password
	if (userName.length > 64){
		return res.render('registerpage', {error: 'Maximum username length of 64 characters', passwordError: false});
	}
	if (password.length > 64){
		return res.render('registerpage', {error: 'Maximum password length of 64 characters', passwordError: true});
	}

	// Validate input data
	let checkQuery = "USE USERS; select * from appusers where username = ?";
	mysqlConn.query(checkQuery, [userName], function(err, results){
		if (err){
			throw new Error("Gathering username query")
		}
		console.log(results.length)
		// Check password strength
		let strength = checkPasswordStrength.passwordStrength(password);
		if (strength.id == 0){
			return res.render('registerpage', {error: 'Password too weak', passwordError: true});
		}
		
		// Check password schema
		let passwordSchemaCheck = schema.validate(password);
		if (!passwordSchemaCheck){
			return res.render('registerpage', {error: 'Password must include 1 uppercase, 1 lowercase, 2 digits, and 1 special symbol !@#$%^&*[]{}', passwordError: true});
		} 
		
		// Check if username exists
		if (results > 0) {
			return res.render('registerpage', {error: 'Username already exists', passwordError: false})
		} 
		// Generate and store salt and hash in database with username, password, and default session
		bcrypt.genSalt(saltRounds, function(err,salt){
			bcrypt.hash(password, salt, function(err, hash){

				// Query database to insert new user
				let insertQuery = "USE USERS; INSERT INTO appusers (username, password, session, salt) VALUES(?, ?, 'NOT LOGGED IN', ?)";
				mysqlConn.query(insertQuery, [userName, hash, salt], function(err, result){
					if (err){
						throw new Error("Inserting new user query");
					}
					else{
						console.log("New user " + userName + " inserted into database");
						return res.redirect("/");
					}
				});
			});

		});

	});
});

// The logout function
// @param req - the request
// @param res - the response
app.get('/logout', function(req, res){

	// Update DB
	let username = req.session.username
	let updateQuery = "USE USERS; UPDATE appusers SET session= 'NOT LOGGED IN' WHERE username= ?";
	mysqlConn.query(updateQuery, [username], function(err, result){
		if (err) throw new Error("Gathering username query")
		console.log("Session ID removed from database");

		// Destroy session and redirect to '/' which will render loginpage
		req.session.destroy(function(err){
			if (err) throw err;
			else{
				res.redirect('/');
			}
		});
	});
});

const httpsServer = https.createServer(options, app).listen(3000);


