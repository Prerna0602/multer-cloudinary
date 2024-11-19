const jwt = require('jsonwebtoken');

const authenticateJWt = (req,res,next) => {
    const token = req.header('Authorization')?.split(' ')[1]
    if(!token){
        return res.status(403).json({message : 'No token privided,authorization denied'})
    };
    try{
        const decoded = jwt.verify(token,process.env.JWT_SECRET);
        req.user = decoded;
        next();
    }catch(error){
        return res.status(401).json({message : 'Invalid Token, authorization denied'})
    }
};

module.exports = {authenticateJWt};