require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");
//const md5 = require("md5");
const bcrypt = require("bcrypt");

const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

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
 */

const User = mongoose.model("User", userSchema);

app.route("/")
    .get(function(req, res){
        res.render("home");
    })
    .post();

app.route("/login")
    .get(function(req, res){
        res.render("login");
    })
    .post(function(req, res){
        const username = req.body.username;        
        const password = req.body.password;        

        User.findOne({email: username}).then(function(doc){
            if(doc){
                bcrypt.compare(password, doc.password).then(function(result){
                    if(result){
                        res.render("secrets");
                    } else {
                        res.send("Incorrect credentials!");
                    }
                }).catch((error) => console.log(error));
            } else {
                res.send("Incorrect credentials!");
            }
        }).catch((error) => console.log(error));
    });

app.route("/register")
    .get(function(req, res){
        res.render("register");
    })
    .post(function(req, res){

        const email = req.body.username;        
        const pass = req.body.password;   

        bcrypt.hash(pass, saltRounds).then(function(hash){
            const user = new User({
                email: email,
                password: hash   
            });
    
            user.save().then(function(doc){
                res.render("secrets")
            }).catch((error) => console.log(error));
        }).catch((error) => console.log(error));

    });


app.listen(8080, function(){
    console.log("Server running at port 8080");
});