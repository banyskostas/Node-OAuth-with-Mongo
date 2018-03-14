// Required Modules
var express = require("express");
var morgan = require("morgan");
var bodyParser = require("body-parser");
var jwt = require("jsonwebtoken");
var mongoose = require("mongoose");
var dotenv = require('dotenv');
var app = express();

// Load env
dotenv.load();

var port = process.env.PORT || 3001;
var User = require('./models/user');

// Connect to DB
mongoose.connect(process.env.MONGO_URL);

app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(morgan("dev"));
app.use(function (req, res, next) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
    next();
});

app.post('/authenticate', function (req, res) {
    User.findOne({email: req.body.email, password: req.body.password}, function (err, user) {
        if (err) {
            res.json({
                type: false,
                data: "Error occured: " + err
            });
        } else {
            if (user) {
                // Create new token for existing user every time authenticate is made
                user.token = jwt.sign({
                    data: {
                        email: user.email
                    }
                }, process.env.JWT_SECRET, {expiresIn: parseInt(process.env.JWT_TOKEN_EXPIRE)});
                user.save(function (err, user1) {
                    res.json({
                        type: true,
                        token: user.token,
                        expiresIn: parseInt(process.env.JWT_TOKEN_EXPIRE)
                    });
                });
            } else {
                res.json({
                    type: false,
                    data: "Incorrect email/password"
                });
            }
        }
    });
});

app.post('/signin', function (req, res) {
    User.findOne({email: req.body.email, password: req.body.password}, function (err, user) {
        if (err) {
            res.json({
                type: false,
                data: "Error occured: " + err
            });
        } else {
            if (user) {
                res.json({
                    type: false,
                    data: "User already exists!"
                });
            } else {
                var userModel = new User();
                userModel.email = req.body.email;
                userModel.password = req.body.password;
                userModel.save(function (err, user) {
                    user.token = jwt.sign({
                        data: {
                            email: userModel.email
                        }
                    }, process.env.JWT_SECRET, {expiresIn: process.env.JWT_TOKEN_EXPIRE});
                    user.save(function (err, user1) {
                        res.json({
                            type: true,
                            data: user1,
                            token: user1.token
                        });
                    });
                })
            }
        }
    });
});

app.get('/me', ensureAuthorized, function (req, res) {
    getUserFromToken(req, res, function (user) {
        res.json({
            type: true,
            data: user
        });
    });
});

function getUserFromToken(req, res, callback) {
    var bearerHeader = req.headers["authorization"];
    var bearer = bearerHeader.split(" ");
    var bearerToken = bearer[1];

    User.findOne({token: bearerToken}, function (err, user) {
        if (err) {
            res.json({
                type: false,
                data: "Error occured: " + err
            });
        } else {
            callback(user);
        }
    });
}

function ensureAuthorized(req, res, next) {
    var bearerToken;
    var bearerHeader = req.headers["authorization"];
    console.log(bearerHeader);
    if (typeof bearerHeader !== 'undefined') {
        var bearer = bearerHeader.split(" ");
        bearerToken = bearer[1];
        console.log(bearerToken);
        jwt.verify(bearerToken, process.env.JWT_SECRET, function (err, decoded) {
            if (err || !decoded) {
                return res.sendStatus(401)
            } else {
                console.log("Decoded: " + JSON.stringify(decoded));
                next();
            }
        })
    } else {
        res.sendStatus(403);
    }
}

process.on('uncaughtException', function (err) {
    console.log(err);
});

// Start Server
app.listen(port, function () {
    console.log("Express server listening on port " + port);
});