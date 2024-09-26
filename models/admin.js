const mongoose = require('mongoose');
const validator = require('validator');

const mongoDBConnectionPromise = require('../connections/connection');

module.exports = mongoDBConnectionPromise.then((isConnected) => {
  if (isConnected) {
    const adminSchema = new mongoose.Schema({
      name: {
        type:String,
        required:true,
        minlength: 3
      },
      email: {
        type:String,
        required:true,
        unique:true,
        validate: {
          validator: validator.isEmail,
          message: 'Invalid email'
        }
      },
      password: {
        type:String,
        required:true,
        minlength: 8
      },
      permission:{
        type:String,
        enum: ['read', 'write'],
        required:true
      },
      post:{
        type:String,
        enum: ['admin', 'user'],
        required:true
      },
      token:{
        type: String
      }
    });

    const adminModel = mongoose.model('admins', adminSchema);
    return {
      status:200,
      msg:'success',
      model:adminModel
    };
  }else{
    return {
      status:500,
      msg:'error',
    };
  }
}).catch((error) => {
  console.log('Error connecting to MongoDB.');
  console.log(error);
  return {
    status:500,
    msg:error
  };
});