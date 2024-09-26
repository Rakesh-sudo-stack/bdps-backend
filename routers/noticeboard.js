const express = require('express');
const jwt = require('jsonwebtoken');

let models = {};
// Importing models
const setModels = () => {
    require('../models/noticeboard').then((data) => {
        models.noticeboard = data.model;
        console.log(data)
    })
}

setModels();

const adminAuth = (token) => {
    try {
        if (token === undefined) {
            return ({
                status: 500,
                msg: 'You are not a valid user'
            })
        } else {
            let auth = jwt.verify(token, process.env.JWT_SECRET_KEY);
            if (auth) {
                return ({
                    status: 200,
                    msg: 'Auth success'
                })
            } else {
                return ({
                    status: 500,
                    msg: 'Auth failed'
                })
            }
        }
    } catch (error) {
        return ({
            status: 500,
            msg: 'Auth failed',
            error
        })
    }

}

let router = express.Router();

router.post('/', (req, res) => {
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 500) {
        console.log('failed')
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    } 
    models.noticeboard.insertMany(req.body).then(() => {
        res.status(200).json({
            status: 200,
            msg: 'Notices Added'
        })
    }).catch(error=>{
        res.status(500).json({
            status: 500,
            msg: 'Some error occured',
            error
        })
    })
})

router.post('/uploads',async (req,res)=>{
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 500) {
        console.log('failed')
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    }
    try {
        const notices = await models.noticeboard.find();
        res.status(200).json({
            status: 200,
            msg: 'Successfully found',
            body: notices
        })
    } catch (err) {
        res.status(500).json({
            status: 500,
            msg: 'Some error occured',
            error: err
        })
    }
})

module.exports = router;