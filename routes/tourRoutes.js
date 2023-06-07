const express = require('express');
const tourController = require('../controllers/tourController.js');
const authController = require('../controllers/authController.js');
const reviewController = require('../controllers/reviewController');
const reviewRouter = require('./../routes/reviewRoutes.js');

// The express.Router() function is used to create a new router object
// The Express router object is a collection of middlewares and routes.
// router object is itself a middleware
// The router object allows developers to group related routes and handlers together under a common URL prefix,
//  making it easier to manage large applications with many routes.
//  It also enables developers to create modular and reusable route handlers that can be
// mounted at different URL paths within an application.
const router = express.Router();

router.use('/:tourId/reviews', reviewRouter);

// param is the middleware which runs for certain parameters defined in url, for example here it
// will run for the request which has id parameter in the request url
// router.param('id', tourController.checkId);

// We have specified this tour route for aliasing. if someone wants get top 5 cheap tours
// and aliasTopTours middleware is called on it before getting tours details
router
  .route('/top-5-cheap')
  .get(tourController.aliasTopTours, tourController.getAllTours);

router.route('/tour-stats').get(tourController.getTourStats);
router
  .route('/monthly-plan/:year')
  .get(
    authController.protect,
    authController.restrictTo('admin', 'lead-guide', 'guide'),
    tourController.getMonthlyPlan
  );
router
  .route('/tours-within/:distance/center/:latlng/unit/:unit')
  .get(tourController.getToursWithin);
router.route('/distances/:latlng/unit/:unit').get(tourController.getDistances);
router
  .route('/')
  .get(tourController.getAllTours)
  .post(
    authController.protect,
    authController.restrictTo('admin', 'lead-guide'),
    tourController.createTour
  );
router
  .route('/:id')
  .get(tourController.getTour)
  .patch(
    authController.protect,
    authController.restrictTo('admin', 'lead-guide'),
    tourController.updateTour
  )
  .delete(
    authController.protect,
    authController.restrictTo('admin', 'lead-guide'),
    tourController.deleteTour
  );

// router
//   .route('/:tourId/reviews')
//   .post(
//     authController.protect,
//     authController.restrictTo('user'),
//     reviewController.createReview
//   );

module.exports = router;
