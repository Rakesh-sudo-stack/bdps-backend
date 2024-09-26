const express = require('express');
const bcrypt = require('bcryptjs');
const sendMail = require('../controllers/sendMail')
const jwt = require('jsonwebtoken');

let router = express.Router();
let models = {};

// Importing models
const setModels = () => {
    require('../models/admins').then((data) => {
        models.admin = data.model;
        console.log(data)
    })
}

setModels();

// Authorize Admin
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

const checkAdmin = async (token) => {
    try {
        const findUser = await models.admin.find({ token });
        console.log(findUser)
        if (findUser[0].post === 'admin') {
            return ({
                status: 200,
                msg: 'You are an admin'
            })

        } else {
            return ({
                status: 500,
                msg: 'You are not an admin',
            })
        }
    } catch (error) {
        return ({
            status: 500,
            msg: 'Some error occured',
            error
        })
    }
}

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
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 500) {
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    }
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
router.get('/email/:email', async (req, res) => {
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 500) {
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    }
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
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 500) {
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    }
    console.log(req.body)

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
                    console.log(password)
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
                        msg: 'Some Error Occured',
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
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 500) {
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    }

    async function updatedUser() {
        const updatedUser = await models.admin.updateOne({ email }, { post: req.body.post, permission: req.body.permission }, { new: true })
        res.status(200).json({
            status: 200,
            msg: 'User updated',
            body: updatedUser
        })
    }
    const email = req.params.email;
    // Find the user by their ID and update their details
    checkAdmin(req.cookies.jwtbdps).then(async (isAdmin) => {
        if (isAdmin.status === 500) {
            return res.status(500).json({
                status: isAdmin.status,
                msg: isAdmin.msg
            })
        }

        let adminEmail = jwt.decode(req.cookies.jwtbdps).email;

        if (adminEmail === email) {
            return res.status(500).json({
                status: 500,
                msg: 'You cannot edit yourself'
            })
        }

        try {
            const findUser = await models.admin.find({ email });
            if (findUser.length >= 1) {

                updatedUser();
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
                error:error
            })
        }
    })
})

//DELETE ADMIN REQUEST
router.delete('/:email', async (req, res) => {
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 500) {
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    }

    checkAdmin(req.cookies.jwtbdps).then(async (isAdmin) => {
        if (isAdmin.status === 500) {
            return res.status(500).json({
                status: isAdmin.status,
                msg: isAdmin.msg
            })
        }

        let adminEmail = jwt.decode(req.cookies.jwtbdps).email;
        const email = req.params.email;

        if (adminEmail === email) {
            return res.status(500).json({
                status: 500,
                msg: 'You cannot remove yourself'
            })
        }

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
    });


})

// LOGIN REQUEST
router.post('/login', async (req, res) => {

    console.log("Someone tried to login")

    const updateToken = async (token) => {
        const updatedUser = await models.admin.updateOne({ email: req.body.email }, { token }, { new: true })
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
                    let token = generateAuthToken().then((token) => {
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

router.post('/logout', async (req, res) => {
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 500) {
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    }

    res.clearCookie('jwtbdps');
    res.status(200).json({
        status: 200,
        msg: 'Logged Out'
    })

})

router.post('/auth', (req, res) => {
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 200) {
        res.status(200).json({
            status: auth.status,
            msg: auth.msg
        })
    } else {
        res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    }
})

router.post('/jwt/decode', (req, res) => {
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 500) {
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    }

    try {
        let decodejwt = jwt.decode(req.cookies.jwtbdps);
        res.status(200).json({
            status: 200,
            msg: 'Success',
            body: { email: decodejwt.email }
        })
    } catch (error) {
        res.status(500).json({
            status: 500,
            msg: 'Some error occured',
            error
        })
    }
})

router.post('/change-pass', async (req, res) => {
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 500) {
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    }

    let email = req.body.email;
    let oldpass = req.body.oldpass;
    let newpass = req.body.newpass;

    const findUser = await models.admin.find({ email });
    if (findUser.length <= 0) {
        return res.status(500).json({
            status: 500,
            msg: 'User not found',
        })
    }

    bcrypt.compare(oldpass, findUser[0].password, async function (error, result) {
        if (error) {
            res.status(500).json({
                status: 500,
                msg: 'Some error occured',
                error
            })
        }

        if (result) {
            newpass = await bcrypt.hash(newpass, 12)
            const updatedUser = await models.admin.updateOne({ email }, { password: newpass })
            res.status(200).json({
                status: 200,
                msg: 'Password changed'
            })

        } else {
            res.status(500).json({
                status: 500,
                msg: 'Password didn\'t match'
            })
        }
    });
})

router.post('/forgot-pass', async (req, res) => {let email = req.body.email;
    const findUser = await models.admin.find({ email });
    if (findUser.length <= 0) {
        return res.status(500).json({
            status: 500,
            msg: 'User not found',
        })
    }
    try {
        let newpass = generateRandString(10);
        hashpass = await bcrypt.hash(newpass, 12)
        const updatedUser = models.admin.updateOne({ email }, { password: hashpass })
        updatedUser.then(() => {
            let subject = 'BDPS Admin'
            let body = `
                    <h1>Your password has been changed</h1>
                    <h4>Your email = ${req.body.email}</h4>
                    <h4>You password = ${newpass}</h4>
                    <br />
                    <br />
                    <br />
                    Please don't reply
                    `;
            let mail = sendMail(req.body.email, subject, body).then((data) => {
                res.status(200).json({
                    status: 200,
                    msg: data
                });
            }).catch((err) => {
                res.status(500).json({
                    status: 500,
                    error: err
                });
            })
        })

    } catch (err) {
        res.status(300).json({
            status: 300,
            msg: 'Some error occured',
            error: err
        })
    }
})

router.post('/change-name', async (req, res) => {
    let auth = adminAuth(req.cookies.jwtbdps);
    if (auth.status === 500) {
        return res.status(500).json({
            status: auth.status,
            msg: auth.msg
        })
    }
    const email = jwt.decode(req.cookies.jwtbdps).email;
    try {
        const updatedUser = await models.admin.updateOne({ email }, { name: req.body.name }, { new: true })
        res.status(200).json({
            status: 200,
            msg: 'Name Changed',
            body: updatedUser
        })
    } catch (error) {
        res.status(500).json({
            status: 500,
            msg: 'Some error occured',
            error
        })
    }
})

module.exports = router;