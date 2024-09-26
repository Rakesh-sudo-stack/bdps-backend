// Essential dependencies
const express = require('express');
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser');
const cors = require('cors');
const fileUpload = require('express-fileupload');

// Routers import
const adminRouter = require('./routers/adminRouter.js');
const imageSliderRouter = require('./routers/imageSliderRouter.js');
const announcementsRouter = require('./routers/announcementsRouter.js');
const noticeBoardRouter = require('./routers/noticeboard.js');

const app = express();
const port = process.env.PORT || 7070;

// Middlewares
app.use(express.json());
app.use(cookieParser());
app.use(cors());
app.use(fileUpload());

//Using routers
app.use('/admin', adminRouter);
app.use('/images', imageSliderRouter);
app.use('/announcements', announcementsRouter);
app.use('/notice-board', noticeBoardRouter);

app.listen(port, () => {
    console.log(`Listening on port ${port}`)
})
