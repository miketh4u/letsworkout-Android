


//////////////////////////////////////////////MODULES USED //////////////////////////////////////////////////
var express = require('express');
var bodyParser = require('body-parser');
var app = express();
var mongoose = require('mongoose');
var sessions = require('client-sessions'); // for sessions
var bcrypt = require('bcryptjs'); //for hashing the password
var csrf = require('csurf'); //set different token whenever a new page (witha form) is rendered
var passport = require('passport')
  , FacebookStrategy = require('passport-facebook').Strategy;

/* import from mongoose library the schema functions */

var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;

/* format for the mongo dbase */
var User = mongoose.model('User',new Schema ({
	id: ObjectId,
	username: {type: String, unique: true},
	firstName: String,
	lastName: String,
	email: {type: String, unique: true},
	password: String,
}));

/* set the app to use jade and 'pretty' for user friendly indentation in the html */
app.set('view engine','jade');
app.locals.pretty=true;

/* conect to mongo */
mongoose.connect('mongodb://localhost/letsworkout') ;

/////////////////////////////////////////////// MIDDLEWARE  ////////////////////////////////////////////////////
app.use(express.static(__dirname + '/views'));
app.use(bodyParser.urlencoded({ extended: true}));
app.use(sessions({
cookieName: 'session',
secret: 'bhbiabfsibfbu8ge8gb397g395v9wv35',
duration: 30 * 60 * 1000,
activeDuaration: 5 * 60 * 1000, 
httpOnly: true, //don't let browser js access cookies
secure: true,   //only use cookies over https
}));

/* use the csrf token to set up a unique token for each form that is posted to prevent 
   attacks */
app.use(passport.initialize());
app.use(csrf());

app.use(function(req, res, next) {
if(req.session && req.session.user) {
	User.findOne({email: req.session.user.email }, function(err,user) {
		if(user) {
			req.user = user;
			delete req.user.password;
			req.session.user = req.user;
			res.locals.user = req.user;
		}
		next();
	} );
} else {
	next();
}
});

/* use passport facebook to authenticate user using facebook */

passport.use(new FacebookStrategy({
    clientID: '737682413007256',
    clientSecret: '7a8b30b1481a815cbac7ae1436b547d2',
    callbackURL: "http://localhost:8000/auth/facebook/callback",
    passReqToCallback: true
  },
  function(req, accessToken, refreshToken, profile, done) {
     process.nextTick(function() {
      User.findOne({ username : profile.id }, function(err, user) {

                // if there is an error, stop everything and return that
                // ie an error connecting to the database
                if (err)
                    return done(err);

                // if the user is found, then log them in
                if (user) {
                	req.session.user = user;
                    return done(null, user); // user found, return that user
                } else {
                    // if there is no user found with that facebook id, create them
                    //console.log(profile);
                    var newUser  = new User({

                    // set all of the facebook information in our user model
                    username: profile.id, // set the users facebook id                   
                    //newUser.facebook.token = token; // we will save the token that facebook provides to the user                    
                    firstName: profile.name.givenName,
                    lastName: profile.name.familyName, // look at the passport user profile to see how names are returned
                    email: " ",    /* profile.emails[0].value, will fix this later since it could be only my facebook that does 
                                  this and facebook can return multiple emails so we'll take the first */
                    password: " ",
                     

                     });
                    
                    // save our user to the database
                    newUser.save(function(err,user) {
                        if (err)
                            throw err;

                        // if successful, return the new user
                        req.session.user = newUser;
                        console.log(req.session.user );
                        return done(null, newUser);
                    });
                    
                }
            });
       
    });
  }
)); 

/* this checks if there is a session for each page and if there is one, it checks to see if
   the user with that session is in the database if so ,it sets the locals for the user and 
   also deletes the password for security reasons from the req */



function requireLogin(req,res,next){
	if(!req.user) {
		res.redirect('/login');
	} else {
		next();
	}
}
//////////////////////////////////////////////// HOMEPAGE ///////////////////////////////////////////////////////////
app.get('/',function(req,res) {
res.render('index.jade');
});
app.get('/register', function(req, res) {
var r = req.csrfToken();
//console.log(r); 
res.render('register.jade',{csrfToken: r });
});


passport.serializeUser(function(user, done) {
  done(null, user);
});
 
passport.deserializeUser(function(obj, done) {
  done(null, obj);
});
/* Redirect the user to Facebook for authentication.  When complete,
   Facebook will redirect the user back to the application at
   /auth/facebook/callback */
app.get('/auth/facebook', passport.authenticate('facebook'));

/* Facebook will redirect the user to this URL after approval.  Finish the
   authentication process by attempting to obtain an access token.  If
   access was granted, the user will be logged in.  Otherwise,
   authentication has failed. */

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', {  successRedirect: '/dashboard',
                                      failureRedirect: '/login' }));
app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ['email'] })
); 

//////////////////////////////////////////////// REGISTER ////////////////////////////////////////////////////////////
/* This function posts the user info to the mongo db after registering */
app.post('/register', function(req,res) {

 var hash = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10));
 var user = new User ({

	username: req.body.username,
	firstName: req.body.firstName,
	lastName: req.body.lastName,
	email: req.body.email,
	password: hash,
}); 
 user.save(function(err) {
 	if(err) {
 		var error = "oopsy daisy, something ain't right please try again";
 		if(err.code === 11000) {
 			error = "That email is already taken, please try another";
 		}
 		res.render('register.jade',{error: error});
 	} else { 
 		res.redirect('/'); 
   }
 });
});


////////////////////////////////////////////// LOGIN  //////////////////////////////////////////////////////////////
app.get('/login',function(req,res) {
res.render('login.jade',{ csrfToken: req.csrfToken() });
});
app.post('/login', function(req,res) {
  User.findOne({ username: req.body.username }, function(err, user) {
    if (!user) {
    	res.render('login.jade', { error: 'Invalid username and or password.' });
    } else { 
             if(bcrypt.compareSync(req.body.password, user.password)) {
             	req.session.user = user; //sets acookie for the user information 
             	res.redirect('/dashboard');
             } else { res.render('login.jade', { error: 'Invalid username and or password.' });}
    }
  });
});


////////////////////////////////////////////// LOGGED IN ////////////////////////////////////////////////////////////
app.get('/dashboard',requireLogin,function(req,res) {
	res.render('dashboard.jade');
               //console.log(res.locals.user);
 });
app.get('/logout',function(req,res) {
req.session.reset();
res.redirect('/');
});
app.listen(8000);

