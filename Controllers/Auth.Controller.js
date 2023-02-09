const createError = require('http-errors')
const User = require('../Models/User.model')
const { authSchema } = require('../helpers/validation_schema')
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} = require('../helpers/jwt_helper')
const client = require('../helpers/init_redis')

module.exports = {
  register: async (req, res, next) => {
    try {
      // const { email, password } = req.body
      // if (!email || !password) throw createError.BadRequest()
      console.log("register() req.body ::",req.body);

      const result = await authSchema.validateAsync(req.body)

      const doesExist = await User.findOne({ email: result.email })
      if (doesExist)
        throw createError.Conflict(`${result.email} is already been registered`)

      const user = new User(result)
      const savedUser = await user.save()
      const accessToken = await signAccessToken(savedUser.id)
      const refreshToken = await signRefreshToken(savedUser.id)

      res.send({ accessToken, refreshToken })
    } catch (error) {
      if (error.isJoi === true) error.status = 422
      next(error)
    }
  },

  login: async (req, res, next) => {
    try {
      console.log("login() req.body ::",req.body);
      const result = await authSchema.validateAsync(req.body);
      console.log("login() result ::",result);
      const user = await User.findOne({ email: result.email });
      console.log("login() user ::",user);
      if (!user) throw createError.NotFound('User not registered')
      console.log("login() TEST 1111 ::");
      const isMatch = await user.isValidPassword(result.password);
      console.log("login() isMatch ::",isMatch);
      if (!isMatch)
        throw createError.Unauthorized('Username/password not valid')
        console.log("login() TEST 2222 ::");
      const accessToken = await signAccessToken(user.id);
      console.log("login() accessToken ::",accessToken);
      const refreshToken = await signRefreshToken(user.id)
      console.log("login() refreshToken ::",refreshToken);
      res.send({ accessToken, refreshToken })
    } catch (error) {
      if (error.isJoi === true)
        return next(createError.BadRequest('Invalid Username/Password'))
      next(error)
    }
  },

  refreshToken: async (req, res, next) => {
    try {
      const { refreshToken } = req.body
      if (!refreshToken) throw createError.BadRequest()
      const userId = await verifyRefreshToken(refreshToken)

      const accessToken = await signAccessToken(userId)
      const refToken = await signRefreshToken(userId)
      res.send({ accessToken: accessToken, refreshToken: refToken })
    } catch (error) {
      next(error)
    }
  },

  logout: async (req, res, next) => {
    console.log("logout() req.body ::",req.body);
    try {
      const { refreshToken } = req.body;
      console.log("logout() refreshToken ::",refreshToken);
      if (!refreshToken) throw createError.BadRequest()
      const userId = await verifyRefreshToken(refreshToken);
      console.log("logout() userId ::",userId);
      client.DEL(userId, (err, val) => {
        if (err) {
          console.log("logout() err ::",err.message)
          throw createError.InternalServerError()
        }
        console.log("logout() val ::",val, " , user log out successfully.");
        res.sendStatus(204)
      })
    } catch (error) {
      next(error)
    }
  },
}
