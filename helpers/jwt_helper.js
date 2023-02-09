const JWT = require('jsonwebtoken')
const createError = require('http-errors')
const client = require('./init_redis')

module.exports = {
  signAccessToken: (userId) => {
    return new Promise((resolve, reject) => {
      const payload = {}
      const secret = process.env.ACCESS_TOKEN_SECRET
      const options = {
        expiresIn: '1h',
        issuer: 'pickurpage.com',
        audience: userId,
      }
      JWT.sign(payload, secret, options, (err, token) => {
        if (err) {
          console.log(err.message)
          reject(createError.InternalServerError())
          return
        }
        resolve(token)
      })
    })
  },
  verifyAccessToken: (req, res, next) => {
    if (!req.headers['authorization']) return next(createError.Unauthorized())
    const authHeader = req.headers['authorization']
    const bearerToken = authHeader.split(' ')
    const token = bearerToken[1]
    JWT.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
      if (err) {
        const message =
          err.name === 'JsonWebTokenError' ? 'Unauthorized' : err.message
        return next(createError.Unauthorized(message))
      }
      req.payload = payload
      next()
    })
  },
  signRefreshToken: (userId) => {
    console.log("jwt_helper.js :-   userId::",userId);
    return new Promise((resolve, reject) => {
      console.log("jwt_helper.js :-   new Promise::");
      const payload = {}
      const secret = process.env.REFRESH_TOKEN_SECRET
      const options = {
        expiresIn: '1y',
        issuer: 'ram.com',
        audience: userId,
      }
      console.log("jwt_helper.js :-   new Promise:: here");
      JWT.sign(payload, secret, options, (err, token) => {
        console.log("jwt_helper.js :-   JWT.sign payload ::",payload, " , secret ::",secret," , options", options);
        if (err) {
          console.log("jwt_helper.js :-   err.message ::",err.message)
          // reject(err)
          reject(createError.InternalServerError());
        }

        client.SET(userId, token, 'EX', 365 * 24 * 60 * 60, (err, reply) => {
          console.log("jwt_helper.js :-   client.SET BEGIN ::");
          if (err) {
            console.log("jwt_helper.js :-   client.SET ::",err);
            reject(createError.InternalServerError())
            return
          }
          console.log("jwt_helper.js :-   token ::",token);
          resolve(token)
        });
      });
    })
  },
  verifyRefreshToken: (refreshToken) => {
    console.log("jwt_helper.js :-   verifyRefreshToken() refreshToken::",refreshToken);
    return new Promise((resolve, reject) => {
      JWT.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (err, payload) => {
          if (err){
            console.log("jwt_helper.js :- verifyRefreshToken()  err::",err);
            return reject(createError.Unauthorized());
          } 
          const userId = payload.aud;
          console.log("jwt_helper.js :-  verifyRefreshToken() payload::",payload);
          console.log("jwt_helper.js :-  verifyRefreshToken() userId::",userId);
          client.GET(userId, (err, result) => {
            if (err) {
              console.log("jwt_helper.js :-  verifyRefreshToken() err::",err.message);
              reject(createError.InternalServerError())
              return
            }
            if (refreshToken === result) return resolve(userId);
            console.log("jwt_helper.js :-  verifyRefreshToken() createError.Unauthorized ");

            reject(createError.Unauthorized())
          })
        }
      )
    })
  },
}
