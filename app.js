require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");
const md5 = require("md5");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

/*** Encryption requires a secret key and also decryption at the time of retrieving.
 *  Hence hashing is preferred. (cannot be converted to plain text.) */
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});

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
        const password = md5(req.body.password);        

        User.findOne({email: username}).then(function(doc){
            if(doc){
                if(doc.password === password){
                    res.render("secrets");
                } else {
                    res.send("Incorrect credentials!");
                }
            }
        }).catch((error) => console.log(error));
    });

app.route("/register")
    .get(function(req, res){
        res.render("register");
    })
    .post(function(req, res){
        const user = new User({
            email: req.body.username,
            password: md5(req.body.password)    // hash the password
        });

        user.save().then(function(doc){
            res.render("secrets")
        }).catch((error) => console.log(error));

    });


app.listen(8080, function(){
    console.log("Server running at port 8080");
});