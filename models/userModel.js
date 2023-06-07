const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const { timeEnd } = require('console');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please tell us your name!'],
  },
  email: {
    type: String,
    required: [true, 'Please Provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email'],
  },
  photo: String,
  role: {
    type: String,
    enum: ['user', 'guide', 'lead-guide', 'admin'],
    default: 'user',
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlenth: 8,
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password!'],
    validate: {
      // This only works on create and save
      validator: function (el) {
        return el === this.password;
      },
      message: 'Passwords are not the same',
    },
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
    select: false,
  },
  // *****
  loginAttempts: {
    type: Number,
    select: false,
  },
  firstLoginAttempt: {
    type: Date,
    select: false,
  },
  // *****
});

userSchema.pre('save', async function (next) {
  // return if modified is not modified (for example only email is edited)
  if (!this.isModified('password')) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  //   delete passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  // we set passwordchangedAt for current time - 1sec because sometimes if it is saved a bit late then user
  // will not be allowd to login because of this authentication check "Check if user changed password after the token was issued"
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// this is a query middleware and will execute on all queries starting with word find
// such as findByID, or find, or bindByIdAndUpdate as we have written /^find/  not find. had we written find, it would have executed
// only on query find.
userSchema.pre(/^find/, function (next) {
  this.find({ active: { $ne: false } });
  next();
});

// this is an instance method and it will be available on all documents of the collection
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changePasswordAfter = function (JWTTimestap) {
  if (this.passwordChangedAt) {
    const changedTimeStamp = parseInt(this.passwordChangedAt.getTime() / 1000);

    return JWTTimestap < changedTimeStamp;
  }

  // false means password is not changed
  return false;
};

userSchema.methods.createPasswordResetToken = function () {
  // crypto is a built-in node module
  const resetToken = crypto.randomBytes(32).toString('hex');
  // 'sha356' is an encryption algorithm.
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // console.log({ resetToken }, this.passwordResetToken);

  // here we set password reseting time to 10 minutes
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

// *******
// // Implementing 10 login attempts within an hour
// userSchema.methods.overLoginAttempts = function () {
//   // check if it's first attempt or the attempt is after an hour
//   let timeDiff = Date.now() - this.firstLoginAttempt;
//   if (!this.firstLoginAttempt || timeDiff >= 60 * 60 * 1000) {
//     this.firstLoginAttempt = Date.now();
//     this.loginAttempts = 0;

//     return false;
//   }

//   // check if attempts are within one hour, if so increment loginAttempts
//   if (timeDiff <= 60 * 60 * 1000 && this.loginAttempts <= 5) {
//     this.loginAttempts = this.loginAttempts + 1;
//     return false;
//   }

//   // if user attempted more than 10 times within an our return true
//   return true;
// };
// *******

const User = mongoose.model('User', userSchema);

module.exports = User;
