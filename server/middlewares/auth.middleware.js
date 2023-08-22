import AppError from "../utils/error.util.js";
import jwt from 'jsonwebtoken';

const isLoggedIn = async (req, res, next) => {
    const {token} = req.cookies;

    if(!token) {
        return next(new AppError('Unauthenticated, please try again', 400));
    }

    const userDetails = await jwt.verify(token, '237dc14c874f6dcc6df556e1b43bf2da0a8da436fce45e0ae47c003d07ca81ee');
    req.user = userDetails;
    next();
}

export {
    isLoggedIn
}