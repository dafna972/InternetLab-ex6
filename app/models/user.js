// load the things we need
var mongoose = require('mongoose');
var bcrypt   = require('bcrypt-nodejs');

// define the schema for our user model
var userSchema = mongoose.Schema({

    local            : {
        email        : String,
        password     : String,
        resetPasswordToken: String,
        resetPasswordExpires: Date
    }
});

userSchema.pre('save', function(next) {
    var user = this;
    var SALT_FACTOR = 5;
  
    if (!user.isModified('local.password')) return next();
   console.log("update password");
    bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
      if (err) return next(err);
  
      bcrypt.hash(user.local.password, salt, null, function(err, hash) {
        if (err) return next(err);
        user.local.password = hash;
        next();
      });
    });
  });
  
// generating a hash
userSchema.methods.generateHash = function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

// checking if password is valid
userSchema.methods.validPassword = function(password) {
    return bcrypt.compareSync(password, this.local.password);
};

// create the model for users and expose it to our app
module.exports = mongoose.model('User', userSchema);
