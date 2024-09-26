const mongoose = require('mongoose');

const mongoDBConnectionPromise = require('../connections/connection');

module.exports = mongoDBConnectionPromise.then((isConnected) => {
  if (isConnected) {
    const announcementsSchema = new mongoose.Schema({
      title: {
        type:String,
        required:true
      },
      date: {
        type:String,
        required:true
      },
      link: {
        type:String,
        required:true
      }
    });

    const announcementsModel = mongoose.model('announcements', announcementsSchema);
    return {
      status:200,
      msg:'success',
      model:announcementsModel
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