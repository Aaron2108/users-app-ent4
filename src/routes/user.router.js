const { getAll, create, getOne, remove, update, verifyCode,loginToken, userLogin, resetPasword, resetCode } = require('../controllers/user.controllers');
const express = require('express');
const verifyJWT = require('../utils/verifyJWT');
const userRouter = express.Router();

userRouter.route('/')
    .get(verifyJWT,getAll)
    .post(create);

userRouter.route('/login')
    .post(loginToken);

userRouter.route('/me')
.get(verifyJWT,userLogin)

userRouter.route('/reset_password')
.post(resetPasword)

userRouter.route('/reset_password/:code')
.post(resetCode);

userRouter.route('/verify/:code')
    .get(verifyCode)

userRouter.route('/:id')
    .get(verifyJWT,getOne)
    .delete(verifyJWT,remove)
    .put(verifyJWT,update);

module.exports = userRouter;