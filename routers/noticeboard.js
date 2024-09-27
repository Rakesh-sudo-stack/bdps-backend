const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

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
        const readBlacklist = () => {
            const blacklistFile = path.join(__dirname, './blacklist.txt');
            if (fs.existsSync(blacklistFile)) {
                const data = fs.readFileSync(blacklistFile, 'utf-8');
                const tokens = data.split('\n').filter(Boolean).map(token => token.trim());
                
                return tokens;
            }
            console.log('Blacklist file does not exist.');
            return [];
        };
        let blackdata = readBlacklist();
        console.log(blackdata, blackdata.includes(token))

        if (blackdata.length > 0 && blackdata.includes(token)) {
            return ({
                status: 500,
                msg: 'Someone has modified your permissions',
                modified:true
            })
        }
        if (token === undefined) {
            return ({
                status: 500,
                msg: 'You are not a valid user',
                modified:false
            })
        } else {
            let auth = jwt.verify(token, process.env.JWT_SECRET_KEY);
            if (auth) {
                return ({
                    status: 200,
                    msg: 'Auth success',
                    email: jwt.decode(token).email,
                    post: jwt.decode(token).post,
                    permission: jwt.decode(token).permission,
                    modified:false
                })
            } else {
                return ({
                    status: 500,
                    msg: 'Auth failed',
                    modified:false
                })
            }
        }
    } catch (error) {
        console.log(error)
        return ({
            status: 500,
            msg: 'Auth failed',
            error,
            modified:false
        })
    }

}

let router = express.Router();

router.post('/', (req, res) => {
    let auth = adminAuth(req.cookies.jwtbdps);
    
    if(auth.modified){
        res.clearCookie('jwtbdps')
    }
    if (auth.status === 500) {
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    } 
    if (!(auth.post == 'admin' || auth.permission == 'write')){
        return res.status(500).json({
            status:  500,
            msg: 'You dont have permission to edit'
        })
    }
    models.noticeboard.insertMany(req.body).then(() => {
        console.log(`${auth.email} has uploaded notice`)
        console.table(req.body)
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