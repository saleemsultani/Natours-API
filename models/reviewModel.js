const mongoose = require('mongoose');
const Tour = require('./tourModel');

const reviewSchema = new mongoose.Schema(
  {
    review: {
      type: String,
      required: [true, 'Review can not be empty!'],
    },
    rating: {
      type: Number,
      min: 1,
      max: 5,
    },
    createdAte: {
      type: Date,
      default: Date.now,
    },
    tour: {
      type: mongoose.Schema.ObjectId,
      ref: 'Tour',
      required: [true, 'Review must belong to a tour.'],
    },
    user: {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      required: [true, 'review must belong to a user.'],
    },
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

reviewSchema.index({ tour: 1, user: 1 }, { unique: true });

reviewSchema.pre(/^find/, function (next) {
  // this.populate({
  //  path: 'tour',
  //  select: 'name',
  // }).populate({
  //  path: 'user',
  //  select: 'name photo',
  // });

  this.populate({
    path: 'user',
    select: 'name photo',
  });

  next();
});

reviewSchema.statics.calcAverateRatings = async function (tourId) {
  const stats = await this.aggregate([
    { $match: { tour: tourId } },
    {
      $group: {
        _id: '$tour',
        nRating: { $sum: 1 },
        avgRating: { $avg: '$rating' },
      },
    },
  ]);
  // console.log(stats);

  if (stats.length > 0) {
    await Tour.findByIdAndUpdate(tourId, {
      ratingsQuantity: stats[0].nRating,
      ratingsAverage: stats[0].avgRating,
    });
  } else {
    await Tour.findByIdAndUpdate(tourId, {
      ratingsQuantity: 0,
      ratingsAverage: 4.5,
    });
  }
};

reviewSchema.post('save', function () {
  this.constructor.calcAverateRatings(this.tour);
});

// reviewSchema.pre(/^findOneAnd/, async function (next) {
//   //   // in query middleware we don't have access to current review document and this keyword will point to current query not current review document
//   //   // that's why we execute this query middleware first in order to access current document from current query
//   this.r = await this.findOne().clone();
//   //   // The Mongoose Query API clone () method is used to copy a mongoose query,
//   //   // and then can be executed anytime later.
//   //   // This method is useful if a query needs to be executed more than once,
//   //   //  as a single query can’t be executed twice.
//   next();
// });

// reviewSchema.post(/^findOne/, async function () {
//   //   // this.r = await this.findOne(); does not work here, because query has already executed
//   await this.r.constructor.calcAverateRatings(this.r.tour);
// });

const Review = mongoose.model('Review', reviewSchema);
module.exports = Review;
