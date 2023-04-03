const adminAuth = () => {
    try {
        let token = req.cookies.jwtbdps;
        if (token === undefined) {
            res.json({
                status: 500,
                msg: 'Not a valid user'
            })
        } else {
            let auth = jwt.verify(token, process.env.JWT_SECRET_KEY);
            if (auth) {
                res.json({
                    status: 200,
                    msg: 'Auth success'
                })
            } else {
                res.json({
                    status: 500,
                    msg: 'Auth failed'
                })
            }
        }
    } catch (error) {
        res.json({
            status: 500,
            msg: 'Auth failed',
            error
        })
    }

}

module.exports = adminAuth;