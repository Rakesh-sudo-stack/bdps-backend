const express = require('express');
const bcrypt = require('bcryptjs');
const sendMail = require('../controllers/sendMail')
const jwt = require('jsonwebtoken');

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

// global functions
function generateRandString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }

    return result;
}

// ADMIN LIST REQUEST
router.get('/', async (req, res) => {
    try {
        const admins = await models.admin.find().select({ _id: 0, password: 0 });
        res.status(200).json({
            status: 200,
            msg: 'Successfully found',
            body: admins
        })
    } catch (err) {
        res.status(500).json({
            status: 500,
            msg: 'Some error occured',
            error: err
        })
    }
})

//ADMIN INFO REQUEST
router.get('/:email', async (req, res) => {
    const email = req.params.email;
    try {
        const admins = await models.admin.find({ email }).select({ _id: 0, token: 0, password: 0 });
        if (admins.length >= 1) {
            res.status(200).json({
                status: 200,
                msg: 'Successfully Found',
                body: admins
            })
        } else {
            res.status(500).json({
                status: 500,
                msg: 'Email ID not found',
            })
        }
    } catch (err) {
        console.log(err);
        res.status(500).json({
            status: 500,
            msg: 'Some Error Occured',
            error: err
        })
    }
})

// ADD ADMIN REQUEST
router.post('/', async (req, res) => {

    const findUser = await models.admin.find({ email: req.body.email });

    let password = generateRandString(10);

    if (findUser.length === 0) {
        bcrypt.hash(password, 12, (err, hash) => {
            if (err) {
                console.error(err);
            } else {

                const User = new models.admin({ ...req.body, password: hash });
                const response = User.save();
                response.then(() => {
                    let subject = 'BDPS Admin'
                    let body = `
                    <h1>You have been added to BDPS Admin Page</h1>
                    <h4>Your email = ${req.body.email}</h4>
                    <h4>You password = ${password}</h4>
                    <br />
                    <br />
                    <br />
                    Please don't reply
                    `;
                    let mail = sendMail(req.body.email, subject, body).then((data) => {
                        res.status(200).json({
                            status: 200,
                            msg: data,
                            body: response
                        });
                    }).catch(() => {
                        res.status(500).json({
                            status: 500,
                            msg: data
                        });
                    })


                }).catch((error) => {
                    res.status(500).json({
                        status: 500,
                        msg: 'Some error occured',
                        error
                    })
                })
            }
        });
    } else {
        res.status(500).json({
            status: 500,
            msg: 'Email ID already exist',
        })
    }
})

// UPDATE ADMIN REQUEST
router.patch('/:email', async (req, res) => {

    async function updatedUser() {
        const updatedUser = await models.admin.updateOne({ email }, req.body, { new: true })
        res.status(200).json({
            status: 200,
            msg: 'User updated',
            body: updatedUser
        })
    }
    const email = req.params.email;
    // Find the user by their ID and update their details
    try {
        const findUser = await models.admin.find({ email });
        if (findUser.length >= 1) {

            try {
                bcrypt.hash(req.body.password, 12, (err, hash) => {
                    if (err) {
                        console.error(err);
                    } else {
                        console.log(hash)
                        req.body.password = hash;
                        updatedUser()
                    }
                });
            } catch (error) {
                res.status(500).json({
                    status: 500,
                    msg: 'Some error occured',
                    error
                })
            }
        } else {
            res.status(500).json({
                status: 500,
                msg: 'Email ID not found',
                body: findUser
            })
        }
    } catch (error) {
        res.status(500).json({
            status: 500,
            msg: 'Some error occured',
            error
        })
    }
})

//DELETE ADMIN REQUEST
router.delete('/:email', async (req, res) => {
    const email = req.params.email;
    const findUser = await models.admin.find({ email });
    if (findUser.length <= 0) {
        // User not found
        res.status(500).json({
            status: 500,
            msg: 'User not found',
        })
    } else {
        // Delete User
        try {
            let response = await models.admin.deleteOne({ email });
            res.status(200).json({
                status: 200,
                msg: 'Successfully deleted',
                body: response
            })
        } catch (error) {
            res.status(500).json({
                status: 500,
                msg: 'Some error occured',
                error: error
            })
        }
    }
})

// LOGIN REQUEST
router.post('/login', async (req, res) => {

    const updateToken = async (token) => {
        const updatedUser = await models.admin.updateOne({ email:req.body.email }, {token}, { new: true })
        res.status(200).json({
            status: 200,
            msg: 'Logged In',
            body: updatedUser
        })
    }

    const generateAuthToken = async () => {
        const token = jwt.sign({ email: req.body.email }, process.env.JWT_SECRET_KEY);
        res.cookie('jwtbdps', token, { maxAge: 2400000, httpOnly: true })
        return token;
    }

    const findUser = await models.admin.find({ email: req.body.email });
    if (findUser.length <= 0) {
        res.status(500).json({
            status: 500,
            msg: 'User not found',
        })
    } else {
        bcrypt.compare(req.body.password, findUser[0].password, function (error, result) {
            if (error) {
                res.status(500).json({
                    status: 500,
                    msg: 'Some error occured',
                    error
                })
            }

            if (result) {

                try {
                    let token = generateAuthToken().then((token)=>{
                        updateToken(token)
                    });
                } catch (error) {
                    res.status(500).json({
                        status: 500,
                        msg: 'Some error occured',
                        error
                    })
                }

            } else {
                
                res.status(500).json({
                    status: 500,
                    msg: 'Password didn\'t match'
                })
            }
        });

    }

})

router.post('/auth',(req,res)=>{
    try{
        let token = req.cookies.jwtbdps;
        if(token === undefined){
            res.status(500).json({
                status: 500,
                msg: 'Not a valid user'
            })
        }else{
            let auth = jwt.verify(token, process.env.JWT_SECRET_KEY);
            if(auth){
                res.status(200).json({
                status:200,
                msg: 'Auth success'
                })
            }else{
                res.status(500).json({
                    status:500,
                    msg:'Auth failed'
                })
            }
        }
    }catch(error){
        res.status(500).json({
            status:500,
            msg:'Auth failed',
            error
        })
    }
})

module.exports = router;