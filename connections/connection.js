const mongoose = require('mongoose');
require('dotenv').config();

const connectionString = process.env.MONGO_DB_URL;

async function connectToMongoDB() {
  try {
    await mongoose.connect(connectionString);
    console.log('MongoDB connection successful.');
    return 200;
  } catch (error) {
    console.log('MongoDB connection failed.');
    console.log(error);
    return 500;
  }
}

module.exports = connectToMongoDB();
