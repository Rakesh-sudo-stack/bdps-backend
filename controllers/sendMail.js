const nodemailer = require('nodemailer');

const sendMail = async (email, subject, body) => {
    try {
        let testAccount = await nodemailer.createTestAccount();

        // create reusable transporter object using the default SMTP transport
        let transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 587,
            auth: {
                user: process.env.NODEMAILER_EMAIL_ID,
                pass: process.env.NODEMAILER_EMAIL_PASSWORD
            }
        });

        // send mail with defined transport object
        let info = await transporter.sendMail({
            from: '"Rakesh Jaiswal" <rakeshkumar1957830@gmail.com>',
            to: email,
            subject,
            html: body,
        });
        return 'Check your gmail';
    } catch (error) {
        return 'Some error occured while sending mail'
    }
}

module.exports = sendMail;