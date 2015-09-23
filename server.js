var jsonServer = require('json-server')
var express = require('express');
var bodyParser = require('body-parser')
var low = require('lowdb');
var jwt = require('jsonwebtoken');
var db = low('users.json');
var server = express();
var secret = '12312';

var restrictAccess = {  					//select restricted entities and methods for user role
	posts: ['POST', 'PUT', 'DELETE'],
	tags: ['GET','POST', 'PUT', 'DELETE']
}; 

var authenticatedRoutes = ['posts', 'tags', 'comments'];

server.use( bodyParser.json() );

server.post('/login', function(req, res) {
	var userName = req.body._username;
	var pass = req.body._password;
	var user = 
		db('users')
			.find({
				"user" : userName,
				"pass": pass
			});

	if (!user) {
		res.status(401).json({
			code: 401,
			message: "Bad credentials"
		});
		
	} else {
		var token = jwt.sign({role: user.role}, secret, {
			expiresInMinutes: 60,
		});
		res.json({
			"token": token,
			"message": "Authenticated successfully"
		});
	}

});

server.use(function(req, res, next){
	var authRequired = false;
	
	authenticatedRoutes.forEach(function(route) {
		if (req.originalUrl.indexOf(route) != -1) {
			authRequired = true;
		}
	});
		
	if (!authRequired) {
		next();
		return;
	}
	
	var token = req.headers['authorization'];
	
	if (token) {
		token = token.replace('Bearer ', '')
	}
	
	jwt.verify(token, secret, function(err, decoded) {      
		if (err) {
			return res.status(401).json({ success: false, message: 'Failed to authenticate token.' });
		  } else {
			if (decoded.role == 'user') {
					for (var key in restrictAccess) {
							if (restrictAccess.hasOwnProperty(key)) {
									if (req.originalUrl.indexOf(key) != -1) {
											return res.status(403).json({ success: false, message: 'Access denied.' });
									}
							}
					}
			}
			
			req.decoded = decoded;    
			next();
		  }
	});
	
});

server.use(jsonServer);

var fs = require('fs');
jsonServer.low.db = JSON.parse(fs.readFileSync('db.json', 'utf8'));

server.listen(3001);
