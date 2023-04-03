// Essential dependencies
const express = require('express');
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser');
const cors = require('cors');

// Routers import
const adminRouter = require('./routers/adminRouter.js');

const app = express();
const port = process.env.PORT || 5000;

// Middlewares
app.use(express.json());
app.use(cookieParser());
app.use(cors());

//Using routers
app.use('/admin', adminRouter);

app.listen(port, () => {
    console.log(`Listening on port ${port}`)
})
