const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config({
  path: "../config/config.env",
});

module.exports = function (req, res, next) {
  const token = req.header("auth-token");
  if (!token) return res.status(401).json("Access denied");
  try {
    const verified = jwt.verify(token, process.env.TOKEN_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json("Invalid token");
  }
};
