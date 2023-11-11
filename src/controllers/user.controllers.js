const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken');


const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const { email, password, firstName,lastName, country, image, frontBaseUrl } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await User.create({
        email,
        password: hashedPassword,
        firstName,
        lastName,
        country,
        image,
    });

    const code = require('crypto').randomBytes(32).toString("hex")

    await EmailCode.create({
        code,
        userId: result.id
    })

    const link = `${frontBaseUrl}/auth/verify_email/${code}`

    await sendEmail({
        to:email,
        subject:'Verificate email for user app',
        html:`<h1>Hello ${firstName} ${lastName}</h1>
        <a href=${link}>${link}</a> <br>
        <h2>Thanks for sign up in user app</h2>
        `
    })
   
    return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const { firstName, lastName, country, image } = req.body;
    const result = await User.update(
        {firstName, lastName, country, image},
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyCode = catchError(async(req, res) => {
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({
        where: {code}});
    if(!emailCode) return res.status(401).json({message: "Code not found"});
    const user = await User.findByPk(emailCode.userId);
    user.isVerified = true;
    await user.save();
    emailCode.destroy();
    return res.json(user);
});

const loginToken = catchError(async(req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({
        where: {email}});
    if(!user) return res.status(401).json({ error: "invalid credentials" });

    if(!user.isVerified) return res.status(401).json({ error: "not verified" });

    const isValid = await bcrypt.compare(password, user.password);
    if(!isValid) return res.status(401).json({ error: "invalid credentials" });

    const token = jwt.sign(
		{ user }, 
		process.env.TOKEN_SECRET, 
		{ expiresIn: '1d' },
        );

        return res.json({user, token});
});

const userLogin = catchError(async(req, res) => {
    const user = req.user;
    return res.json(user);
});

const resetPasword = catchError(async(req, res) => {
    const { email, frontBaseUrl } = req.body;

    const user = await User.findOne({ email: email });
    if(!user) return res.status(401).json({ message: "mail error" });

    
    const code = require('crypto').randomBytes(32).toString("hex")

const link = `${frontBaseUrl}/auth/reset_password/${code}`

    await sendEmail({
        to:email,
        subject:'New password reset',
        html:`<h1>Hello</h1>
        <a href=${link}>${link}</a> <br>
        <h2>reset password</h2>
        `
    })

    await EmailCode.create({
        code,
        userId: user.id
    })
   
    return res.status(201).json(user);
});


const resetCode = catchError(async(req, res) => {
    const { password }  = req.body;
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({
        where: {code}
    })
    if(emailCode.code != code) return res.status(401);
    
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.findByPk(emailCode.userId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        await user.update({ password: hashedPassword });
        emailCode.destroy();

        return res.json({ message: "Password updated successfully" });
});



module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyCode,
    loginToken,
    userLogin,
    resetPasword,
    resetCode
}