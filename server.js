const mongoose = require('mongoose');
// dotenv module is used to connect config.env file to nodejs
const dotenv = require('dotenv');

process.on('uncaughtException', (err) => {
  console.log(err.name, err.message);
  console.log('uncaught Exception Shutting Down...');
  process.exit(1);
});
// this command will read variables from config.env file and save them into nodejs environment variables
dotenv.config({ path: './config.env' });

const app = require('./app');

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

// we set port to what comes from environment variable or it will be 3000
const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`App running on port ${port}...`);
});

// this is handling error made by mongoDB. although it's not running
process.on('unhandledRejection', (err) => {
  console.log(err.name, err.message);
  console.log('UNHANDLED ERROR SHUTTING DOWN...');
  server.close(() => {
    process.exit(1);
  });
});
