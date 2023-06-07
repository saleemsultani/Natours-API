class APIFeatures {
  constructor(query, queryString) {
    this.query = query;
    this.queryString = queryString;
  }

  filter() {
    // 1A) filtering
    // first way to build filter query

    // we use spread (...) operator to have a new object instead of creating a shallow copy
    const queryObj = { ...this.queryString };
    const excludedFields = ['page', 'sort', 'limit', 'fields'];
    excludedFields.forEach((el) => delete queryObj[el]);

    // Second way to filter i.e execute query
    // const query = Tour.find()
    // .where('duration')
    // .equals(5)
    // .where('difficulty')
    // .equals('easy');

    // 2A) Some advance filtering
    let queryStr = JSON.stringify(queryObj);
    // below query will replace all (gte,gt,lte,lt) with having a $ sign infront of it
    // so that mongooDB can understand our query
    queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, (match) => `$${match}`);
    this.query = this.query.find(JSON.parse(queryStr));

    return this;
  }

  sort() {
    // 2) Sorting
    // For descending order we use negative sign with the field for which we do sorting
    // and if we want to add second field for sorting we use comma (,) in URL for eg. price is negative
    // localhost:3000/api/v1/tours?sort=-price,ratingsAverage
    if (this.queryString.sort) {
      // if sorting is with respect to multiple fields from URL bbelow line of code will replace
      // comma with space i.e if sort=price,ratingsAverage so it will become price ratingAverage
      const sortBy = this.queryString.sort.split(',').join(' ');
      this.query = this.query.sort(sortBy);
    } else {
      this.query = this.query.sort('-createdAt');
    }

    return this;
  }

  limitFields() {
    // 3)Field Limiting
    if (this.queryString.fields) {
      const fields = this.queryString.fields.split(',').join(' ');
      this.query = this.query.select(fields);
    } else {
      // select(-'fieldName') is excluding of the field
      this.query = this.query.select('-__v');
    }

    return this;
  }

  paginate() {
    // 4)Pagination
    // to view some number of records on specific page
    const page = parseInt(this.queryString.page) || 1;
    const limit = parseInt(this.queryString.limit) || 100;
    // if we want to view 3 recordes of 4th page so we need to skip first 9 pages so (4-1)*3
    const skip = (page - 1) * limit;

    this.query = this.query.skip(skip).limit(limit);

    return this;
  }
}

module.exports = APIFeatures;
