const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const tourRouter = require('./routes/tourRoutes');
const userRouter = require('./routes/userRoutes');
const reviewRouter = require('./routes/reviewRoutes');
const app = express();

// This middleware is used to set security HTTP headers
app.use(helmet());

// Developer Logging middleware
if (process.env.NODE_ENV === 'development') {
  // Morgan is a popular middleware for Node.js applications
  // that is used to log HTTP request details such as URL, HTTP method, response status, response time, and more.
  app.use(morgan('dev'));
}

// limmiter middleware for limiting too many requests from an IP to avoid DOS attack
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 100,
  message: 'Too many requests from  this IP, please try again in an hour!',
});

app.use('/api', limiter);

// express.json() is a built-in middleware function in Express.
//  This method is used to parse the incoming requests with JSON payloads and is based upon the bodyparser.
app.use(express.json({ limit: '10kb' }));

// Middleware for Data sainitization against noSQL qury injection
app.use(mongoSanitize());

// middleware for Data sainitization against XSS(cros side scripting) attacks
app.use(xss());

// middleware for preventing parameter pollution
app.use(
  hpp({
    whitelist: [
      'duration',
      'ratingQuantity',
      'ratingAverage',
      'maxGroupSize',
      'difficulty',
      'price',
    ],
  })
);

// express.static() is a built in middleware and it is used for serving static files.
app.use(express.static(`${__dirname}/public`));

// middleware for testing headers
app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  // console.log(req.headers);
  next();
});

// get request with id specified
// -> if we write ('/api/v1/tours/:id?) as our route handler this means that id parameter is optional
// and client can make request without specifying id parameter
// -> in url if we type like ('/api/v1/tours/:id/:x/:m) in req.params all these
// specified values will be stored as key values of object like {id: '10', x: '20', m: '3'} if the url
//  typed is ('/api/v1/tours/10/20/3)

//////////////////////////////////////////////////////////////////////////////////
// The app.route() function returns an instance of a single route,
// which you can then use to handle HTTP verbs with optional middleware.
// Use app.route() to avoid duplicate route names (and thus typo errors).

// app.route('/api/v1/tours').get(getAllTours).post(createNewTour);
// app
//   .route('/api/v1/tours/:id')
//   .get(getTour)
//   .patch(updateTour)
//   .delete(deleteTour);

/////////////////////////////////////////////////////////////
// **  Mounting Routers  **//

app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);

// Route handler for routes which are not handled in our app
app.all('*', (req, res, next) => {
  const err = new AppError(
    `Can't find ${req.originalUrl} on this server!`,
    404
  );
  // if next function recieve argument express will know there is error and will skip all other middlewares in
  // the middleware stack and send the error to global error handling middleware
  next(err);
});

app.use(globalErrorHandler);

module.exports = app;
