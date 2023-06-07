const fs = require('fs');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Tour = require('./../../models/tourModel');
const User = require('./../../models/userModel');
const Review = require('./../../models/reviewModel');

// dotenv.config({ path: './config.env' });
dotenv.config({ path: './../../config.env' });

const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);

mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('DB Connection Successfull!');
  })
  .catch((err) => {
    console.log('Error:', err.message);
  });

//   read tours data from the file
const tours = JSON.parse(fs.readFileSync(`${__dirname}/tours.json`, 'utf-8'));
const users = JSON.parse(fs.readFileSync(`${__dirname}/users.json`, 'utf-8'));
const reviews = JSON.parse(
  fs.readFileSync(`${__dirname}/reviews.json`, 'utf-8')
);

// Import the data into DB
async function importTours() {
  try {
    await Tour.create(tours);
    await User.create(users, { validateBeforeSave: false });
    await Review.create(reviews);
    console.log('Data imported Successfully');
  } catch (err) {
    console.log('Error: ', err);
  }
  process.exit();
}

// Delete the data from DB
async function deleteTours() {
  try {
    await Tour.deleteMany();
    await User.deleteMany();
    await Review.deleteMany();
    console.log('Data deleted Successfully');
  } catch (err) {
    console.log('Error : ', err);
  }
  process.exit();
}

if (process.argv[2] === '--import') {
  importTours();
}
if (process.argv[2] === '--delete') {
  deleteTours();
}

console.log(process.argv);
