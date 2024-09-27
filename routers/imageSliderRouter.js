const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs')

let router = express.Router();
let models = {};

// Importing models
const setModels = () => {
    require('../models/admin').then((data) => {
        models.admin = data.model;
        console.log(data)
    })
}

setModels();

function generateRandString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }

    return result;
}

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
        return ({
            status: 500,
            msg: 'Auth failed',
            error,
            modified:false
        })
    }

}

router.post('/upload', (req, res) => {

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

    console.log('proceeded')

    const file = req.files['slider-img']
    console.log(file)
    const filePath = path.join(__dirname, '../public/images', `${file.name}`)

    file.mv(filePath, err => {
        if (err) {
            console.log(err); return res.status(500).json({
                status: 500,
                msg: 'Some error occured',
                error: err
            })
        }
        console.log(`${auth.email} has uploaded image in slider`)
        res.status(200).json({
            status: 200,
            msg: 'Image Added'
        })
    })

})

router.post('/', (req, res) => {
    fs.readdir(path.join(__dirname, '../public/images/'), (err, data) => {
        if (err) {
            res.status(500).json({ status: 500, msg: 'Some error occured', err })
        }

        let promises = data.map((element) => {
            return new Promise((resolve, reject) => {
                fs.readFile(path.join(__dirname, `../public/images/${element}`), function (err, data) {
                    if (err) {
                        reject(err);
                    }
                    const base64 = Buffer.from(data).toString('base64');
                    const imageSrc = `data:image/*;base64,${base64}`;
                    resolve({token:generateRandString(10),name:element,img:imageSrc});
                })
            })
        });

        Promise.all(promises)
            .then((images) => {
                res.status(200).json({ status: 200, msg: 'Successfully got', body: images })
            })
            .catch((err) => {
                res.status(500).json({ status: 500, msg: 'Some error occured', err })
            })
    })
})


module.exports = router;