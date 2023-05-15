require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
   // cookie: { secure: true}        // for https connection
}));

app.use(passport.initialize());  
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());


// /*** Works with mongoose-local strategy only */
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());


/*** Works with any strategy */
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
      });
    });
  });
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});
/** serialise and deserialise */

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google", 
    passport.authenticate("google", { scope: ['profile'] })
);

app.get("/auth/google/secrets",
    passport.authenticate("google", {failureRedirect: '/login'}), function(req, res){
        res.redirect("/secrets");
    });

app.route("/login")
    .get(function(req, res){
        if(req.isAuthenticated()){
            res.redirect("/secrets")
        } else {
            res.render("login");
        }
    })
    .post(function(req, res){
        
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, function(err){
            if(err){
                console.log(err);
            } else {
                passport.authenticate("local", {failureRedirect: '/login', failureMessage: true})(req, res, function(){
                    res.redirect("/secrets");
                });
            }
        });
    });

app.route("/register")
    .get(function(req, res){
        res.render("register");
    })
    .post(function(req, res){

       User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local", {failureRedirect: '/register', failureMessage: true})(req, res, function(){
                res.redirect("/secrets");
            })
        }
       });
    });

app.route("/secrets")
    .get(function(req, res){
        if(req.isAuthenticated()){
            res.render("secrets");
        } else {
            res.redirect("/401");
        }
    })
    .post();

app.post("/logout", function(req, res){
    req.logout(function(err){
        if(err){
            console.log(err);
        } else{
            res.redirect("/");
        }
    });
});

app.get("/401", function(req, res){
    res.render("401");
});

app.listen(8080, function(){
    console.log("Server running at port 8080");
});


/*** Upgradation of security */

//const encrypt = require("mongoose-encryption");
//const md5 = require("md5");
//const bcrypt = require("bcrypt");

/****
 * Level 0  - Encryption using "mongoose-encryption"
 *      // userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});
 * Down-side: encryption involves a secret key and also decryption for retrieving.
 * 
 * Level 1 - Hashing using "md5"
 * Down-side: Simple hashing generates same hash everytime for a text, 
 *            hence prone to hacking (20,000,000,000 md5 hashes/sec)
 * 
 * Level 2 - Hashing + Salting using "bcrypt"
 * 
 * 
 * Level 3 - Using passport, passport-local-mongoose and express-session, implemented higher level of security. Also implements cookies for managing login session
 * 
 * Level 4 - Using oauth (Sign in with google)
 * 
 */