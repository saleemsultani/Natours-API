const mongoose = require('mongoose');
const { default: slugify } = require('slugify');
const validator = require('validator');
// const User = require('./userModel');
// const slugify = require('slugify');

const tourSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'A tour must have a name'],
      unique: true,
      trim: true,
      minLength: [10, 'Tour name must have more or equal to 10 characters'],
      maxLength: [40, 'Tour name must have less or equal to 40 characters'],
    },
    slug: String,
    duration: {
      type: Number,
      required: [true, 'A tour must have a duration'],
    },
    maxGroupSize: {
      type: Number,
      required: [true, 'A tour must have a group size'],
    },
    difficulty: {
      type: String,
      required: [true, 'Atour must have a difficulty'],
      enum: {
        values: ['easy', 'difficult', 'medium'],
        message: 'difficulty has to be either: easy , difficult or medium',
      },
    },
    ratingsAverage: {
      type: Number,
      default: 4.5,
      min: [1, 'Rating must be more or equal to 1'],
      max: [5.0, 'Rating must be less or equal to 5'],
      set: (val) => Math.round(val * 10) / 10,
    },
    ratingsQuantity: {
      type: Number,
      default: 0,
    },
    price: {
      type: Number,
      required: [true, 'A tour must have a price'],
    },
    priceDiscount: {
      type: Number,
      validate: {
        validator: function (val) {
          return val < this.price;
        },
        message: 'Discount has to be less than regular price',
      },
    },
    summary: {
      type: String,
      trim: true, // trim removes all spaces at bbegining and end of string
      required: [true, 'Tour must have a Description'],
    },
    description: {
      type: String,
      trim: true,
    },
    imageCover: {
      type: String,
      required: [true, 'A tour must have a cover image'],
    },
    images: [String],
    createdAt: {
      type: Date,
      default: Date.now(),
      select: false, //this means never send this to user i.e it's hidden it will only be in the DB
    },
    startDates: [Date],
    secretTour: {
      type: Boolean,
      default: false,
    },
    startLocation: {
      // GeoJSON
      type: {
        type: String,
        default: 'Point',
        enum: ['Point'],
      },
      coordinates: [Number],
      address: String,
      description: String,
    },
    locations: [
      {
        type: {
          type: String,
          default: 'Point',
          enum: ['Point'],
        },
        coordinates: [Number],
        address: String,
        description: String,
        day: Number,
      },
    ],
    guides: [
      {
        type: mongoose.Schema.ObjectId,
        ref: 'User',
      },
    ],
  },
  // first object for mongoose.shcema() method is for schema
  // this is the second object for mongoose.schema() method which is for the options
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// seting index makes the read performance better. i.e instead of going through all documents in database
// only the list of the field for index is seted will be searched
// Here we set an index on price and ratingsAverage fields, in ascending and descending order respectively
tourSchema.index({ price: 1, ratingsAverage: -1 });
tourSchema.index({ slug: 1 });
tourSchema.index({ startLocation: '2dsphere' });

// this is the virtual property added to our schema. which will not be added to database
// but will be calculated everytime and returned
tourSchema.virtual('durationWeeks').get(function () {
  return this.duration / 7;
});

// Virtual populate. As we don't have any field named review in tour schema, and also there is no reference to review
// so to access reviews with tours, we do virtual populate.
// foreignField says that the field is saved with name "tour" in reviews schema and its saved with name "_id" in tours
tourSchema.virtual('reviews', {
  ref: 'Review',
  foreignField: 'tour',
  localField: '_id',
});

// Mongoose middleware:
// DOCUMENT MIDDLEWARE
// monoggse have pre middlwares which are triggered before actual event. and post middleware
//  will be triggered after actual event

// this for embedding tour guides i.e to save the guide details, not only guide id, into the database.
// tourSchema.pre('save', async function (next) {
//   const guidesPromises = this.guides.map(async (id) => await User.findById(id));
//   this.guides = await Promise.all(guidesPromises);
// });

// this is document middleware and will be triggered before the .save() command and .create() command
tourSchema.pre('save', function (next) {
  this.slug = slugify(this.name, { lower: true }); //Slugify module is used to slugify strings
  next();
});

// QUERY MIDDLEWARE:
// will run before query
// tourSchema.pre('find', function (next) {
tourSchema.pre(/^find/, function (next) {
  //but we have used /^find/ regular expression to run this middlware on all queries that have find for example findOne or findById
  this.find({ secretTour: { $ne: true } });
  this.start = Date.now();
  next();
});

tourSchema.pre(/^find/, function (next) {
  // populate function is used to embed referenced data, but only in query not in database. it means whn we make a getTour request
  // full data about guides will be returned not just id of guides exvept those we specified (like in this example select: '-__v -passwordChangedAt')
  // but in database there will be just ids of the guides not the entire data

  // Object passed to populate function specifies that the field which we want to populate is guides
  this.populate({
    path: 'guides',
    select: '-__v -passwordChangedAt',
  });
  next();
});

// This is post save middleware
tourSchema.post('save', function (doc, next) {
  next();
});

tourSchema.post(/^find/, function (docs, next) {
  console.log(`Query took ${Date.now() - this.start} milliseconds!`);
  next();
});

// AGGREGATION MIDDLEWARE:
// tourSchema.pre('aggregate', function (next) {
//   this.pipeline().unshift({ $match: { secretTour: { $ne: true } } });
//   console.log(this.pipeline());
//   next();
// });

// here we are creating a model out of the created schema
// first parameter is the name of collection we want set schema to, if it does'nt exist new collection
// with this name will be created
const Tour = mongoose.model('Tour', tourSchema);

module.exports = Tour;
