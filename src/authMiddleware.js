const jwt = require("jsonwebtoken");

module.exports.authMiddleware = function(level) {
  return function(req, res, next) {
    if(level === authLevel.public) {
      return next();
    }

    const authorization = req.headers.authorization;

    if(!authorization) {
      return res.status(401).json({ message: 'Not authenticated!' });
    } else {
      if(authorization.indexOf('Bearer ') !== 0) {
        return res.status(401).json({ message: 'Not a valid token!' });
      }

      const token = authorization.replace('Bearer ', '');

      try {
        const payload = decode(token);

        console.log('PAYLOAD:', payload);

        const { uid, ext } = payload;

        if(ext < Date.now()) {
          return res.status(401).json({ message: 'Token expired!' });
        }

        res.locals.user = {
          id: uid
        }
        
        next();
      } catch(err) {
        return res.statu(400).json({ message: 'Invalid token!'});
      }
    }
  }
}


async function decodeToken(token) {
  const decodedToken = await jwt.decode(token, { complete: true });

  return decodedToken["payload"];
}