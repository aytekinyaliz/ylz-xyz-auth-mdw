const jwt = require("jsonwebtoken");
const { authLevel } = require('./authLevel');

module.exports.authMiddleware = function(level) {
  return async function(req, res, next) {
    if(level === authLevel.public) {
      return next();
    }

    const { authorization } = req.headers;

    if(!authorization || authorization.indexOf('Bearer ') !== 0) {
      return res.status(401).json({ message: 'Not authenticated!' });
    }

    const token = authorization.replace('Bearer ', '');

    try {
      const payload = await decodeToken(token);

      const { uid, ext } = payload;

      if(ext < Date.now()) {
        return res.status(401).json({ message: 'Token expired!' });
      }

      res.locals.user = {
        token,
        id: uid
      }
      
      next();
    } catch(err) {
      console.log('ERROR:', err);

      return res.status(400).json({ message: 'Invalid token!'});
    }
  }
}


async function decodeToken(token) {
  const decodedToken = await jwt.decode(token, { complete: true });

  return decodedToken["payload"];
}