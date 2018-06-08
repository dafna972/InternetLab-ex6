var nodemailer = require('nodemailer');
var User=require('../app/models/user');
var async = require('async');
var crypto=require('crypto');
var transporter = nodemailer.createTransport({
  service: 'gmail',
  secure:'false',
  auth: {
    user: 'shecodes18@gmail.com',
    pass: 'shecodes2018'
  },
  tls: {
    rejectUnauthorized: false
}
});




module.exports = function(app, passport) {

// normal routes ===============================================================

    // show the home page (will also have our login links)
    app.get('/', function(req, res) {
        res.render('index.ejs');
    });

    // PROFILE SECTION =========================
    app.get('/profile', isLoggedIn, function(req, res) {
        res.render('profile.ejs', {
            user : req.user
        });
    });

    // LOGOUT ==============================
    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });
    app.get('/forgot',function(req,res){
          res.render('forgot');
    });
     app.post('/sendMail',function(req,res){
         console.log("mail "+req.body.email);
         async.waterfall([
            function(done) {
              crypto.randomBytes(20, function(err, buf) {
                var token = buf.toString('hex');
                done(err, token);
              });
            },
            function(token, done) {
                console.log("find user: "+req.body.email);
                User.findOne({ 'local.email': req.body.email }, function(err, user) {
                  if (!user) {
                      console.log("cant find user");
                    req.flash('error', 'No account with that email address exists.');
                    return res.redirect('/forgot');
                  }
                  console.log("set token "+token);
                  user.local.resetPasswordToken = token;
                  user.local.resetPasswordExpires = Date.now() + 3600000; // 1 hour
                  console.log (`${JSON.stringify(user)}`)
                  user.save(function(err) {
                    done(err, token, user);
                  });
                });
              },
            function(token, user, done) {
            var mailOptions = {
            from: 'shecodes18@gmail.com',
            to: req.body.email,
            subject: 'Reset your password',
            html:'<h3>Reset password</h3></br><h5>Please click link below to reset your password</h5></br><a href="http://' + req.headers.host + '/reset/' + token + '\n\n">Reset</a>'
          };
          transporter.sendMail(mailOptions, function(error, info){
            if (error) {
                console.log("there is an error");
              console.log(error);
            } else {
              console.log('Email sent: ' + info.response);
            }
          });
     }
         ],
         function(err){
         });
         res.render('index');
        });

    app.get('/reset/:token',function(req,res){
        console.log("get reset");
        User.findOne({ 'local.resetPasswordToken': req.params.token, 'local.resetPasswordExpires': { $gt: Date.now() } }, function(err, user) {
            if (!user) {
                console.log("can't find user "+req.params.token+" user:"+req.user);
              req.flash('error', 'Password reset token is invalid or has expired.');
              return res.redirect('/forgot');
            }
            res.render('reset', {user: req.user });
          });
    });
     app.post('/reset/:token',function(req,res){
        async.waterfall([
            function(done) {
            console.log("post reset");
              User.findOne({'local.resetPasswordToken': req.params.token,'local.resetPasswordExpires': { $gt: Date.now() } }, function(err, user) {
                if (!user) {
                    console.log("can't find user");
                  req.flash('error', 'Password reset token is invalid or has expired.');
                  return res.redirect('back');
                }
        
                user.local.password = req.body.password;
                user.local.resetPasswordToken = undefined;
                user.local.resetPasswordExpires = undefined;
        
                user.save(function(err) {
                  req.logIn(user, function(err) {
                    done(err, user);
                  });
                });
              });
            }
        // res.render('reset');
         ], function(err) {
            res.redirect('/');
          });
     });
     
// =============================================================================
// AUTHENTICATE (FIRST LOGIN) ==================================================
// =============================================================================

    // locally --------------------------------
        // LOGIN ===============================
        // show the login form
        app.get('/login', function(req, res) {
            res.render('login.ejs', { message: req.flash('loginMessage') });
        });

        // process the login form
        app.post('/login', passport.authenticate('local-login', {
            successRedirect : '/profile', // redirect to the secure profile section
            failureRedirect : '/login', // redirect back to the signup page if there is an error
            failureFlash : true // allow flash messages
        }));

        // SIGNUP =================================
        // show the signup form
        app.get('/signup', function(req, res) {
            res.render('signup.ejs', { message: req.flash('signupMessage') });
        });

        // process the signup form
        app.post('/signup', passport.authenticate('local-signup', {
            successRedirect : '/profile', // redirect to the secure profile section
            failureRedirect : '/signup', // redirect back to the signup page if there is an error
            failureFlash : true // allow flash messages
        }));
/*
    // facebook -------------------------------

        // send to facebook to do the authentication
        app.get('/auth/facebook', passport.authenticate('facebook', { scope : ['public_profile', 'email'] }));

        // handle the callback after facebook has authenticated the user
        app.get('/auth/facebook/callback',
            passport.authenticate('facebook', {
                successRedirect : '/profile',
                failureRedirect : '/'
            }));

    // twitter --------------------------------

        // send to twitter to do the authentication
        app.get('/auth/twitter', passport.authenticate('twitter', { scope : 'email' }));

        // handle the callback after twitter has authenticated the user
        app.get('/auth/twitter/callback',
            passport.authenticate('twitter', {
                successRedirect : '/profile',
                failureRedirect : '/'
            }));


    // google ---------------------------------

        // send to google to do the authentication
        app.get('/auth/google', passport.authenticate('google', { scope : ['profile', 'email'] }));

        // the callback after google has authenticated the user
        app.get('/auth/google/callback',
            passport.authenticate('google', {
                successRedirect : '/profile',
                failureRedirect : '/'
            }));
*/
// =============================================================================
// AUTHORIZE (ALREADY LOGGED IN / CONNECTING OTHER SOCIAL ACCOUNT) =============
// =============================================================================

    // locally --------------------------------
        app.get('/connect/local', function(req, res) {
            res.render('connect-local.ejs', { message: req.flash('loginMessage') });
        });
        app.post('/connect/local', passport.authenticate('local-signup', {
            successRedirect : '/profile', // redirect to the secure profile section
            failureRedirect : '/connect/local', // redirect back to the signup page if there is an error
            failureFlash : true // allow flash messages
        }));
/*
    // facebook -------------------------------

        // send to facebook to do the authentication
        app.get('/connect/facebook', passport.authorize('facebook', { scope : ['public_profile', 'email'] }));

        // handle the callback after facebook has authorized the user
        app.get('/connect/facebook/callback',
            passport.authorize('facebook', {
                successRedirect : '/profile',
                failureRedirect : '/'
            }));

    // twitter --------------------------------

        // send to twitter to do the authentication
        app.get('/connect/twitter', passport.authorize('twitter', { scope : 'email' }));

        // handle the callback after twitter has authorized the user
        app.get('/connect/twitter/callback',
            passport.authorize('twitter', {
                successRedirect : '/profile',
                failureRedirect : '/'
            }));


    // google ---------------------------------

        // send to google to do the authentication
        app.get('/connect/google', passport.authorize('google', { scope : ['profile', 'email'] }));

        // the callback after google has authorized the user
        app.get('/connect/google/callback',
            passport.authorize('google', {
                successRedirect : '/profile',
                failureRedirect : '/'
            }));
*/
// =============================================================================
// UNLINK ACCOUNTS =============================================================
// =============================================================================
// used to unlink accounts. for social accounts, just remove the token
// for local account, remove email and password
// user account will stay active in case they want to reconnect in the future

    // local -----------------------------------
    app.get('/unlink/local', isLoggedIn, function(req, res) {
        var user            = req.user;
        user.local.email    = undefined;
        user.local.password = undefined;
        user.save(function(err) {
            res.redirect('/profile');
        });
    });
/*
    // facebook -------------------------------
    app.get('/unlink/facebook', isLoggedIn, function(req, res) {
        var user            = req.user;
        user.facebook.token = undefined;
        user.save(function(err) {
            res.redirect('/profile');
        });
    });

    // twitter --------------------------------
    app.get('/unlink/twitter', isLoggedIn, function(req, res) {
        var user           = req.user;
        user.twitter.token = undefined;
        user.save(function(err) {
            res.redirect('/profile');
        });
    });

    // google ---------------------------------
    app.get('/unlink/google', isLoggedIn, function(req, res) {
        var user          = req.user;
        user.google.token = undefined;
        user.save(function(err) {
            res.redirect('/profile');
        });
    });

*/
};



// route middleware to ensure user is logged in
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated())
        return next();

    res.redirect('/');
}
