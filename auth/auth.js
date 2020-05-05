const express = require("express");
const router = express.Router();
const pool = require("../query");
const bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const moment = require("moment")


dotenv.config({
  path: "../config/config.env",
});

//Create a user
router.post("/signup", async (req, res) => {
  const {
    role_name,
    role_id,
    email,
    password,
    first_name,
    last_name,
    state
  } = req.body;

  const d = new Date()
  const created_at = moment(d).format("YYYY-MM-DD HH:mm:ss")

  var salt = bcrypt.genSaltSync(10);
  let hashedPassword = await bcrypt.hash(password, salt);

  if (!role_id || !email || !password || !first_name || !last_name || !state) {
    errors.push({
      message: "Please enter all fields",
    });
  }

  if (password.length < 6) {
    res.status(400).json({
      message: "Password should be at least 6 characters"
    })
  }

  const queryObj = {
    text: "SELECT * FROM Users WHERE email = $1",
    values: [email],
  };

  pool.query(queryObj, (err, results) => {
    if (err) {
      res.json({
        message: err,
      });
    }

    if (!results) {
      res.status(400).json({
        message: "Something went wrong with the registration. Try again!",
      });
    }

    if (results.rowCount > 0) {
      res.status(401).json({
        message: "Email already exists",
      });
    }
  });

  const roleQueryObj = {
    text: "SELECT * FROM Roles WHERE name = $1",
    values: [role_name],
  };

  // check for role
  pool.query(roleQueryObj, (err, results) => {
    if (err) {
      throw err;
    }

    if (role_id == 1 && role_name == "superadmin") {
      res.status(403).json({
        message: "Access forbidden"
      })
    } else if (role_id == 2 && role_name == "superadmin") {
      const queryObjTwo = {
        text: "INSERT INTO Users (role_id, email, password, first_name, last_name, state, created_at) VALUES($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        values: [role_id, email, hashedPassword, first_name, last_name, state, created_at],
      };
      pool.query(queryObjTwo, (err, results) => {
        if (err) {
          throw err
        }
        res.status(200).json({
          message: "User created successfully",
        });
      });
    } else if (role_id == 1) {
      const queryObjTwo = {
        text: "INSERT INTO Users (role_id, email, password, first_name, last_name, state, created_at) VALUES($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        values: [role_id, email, hashedPassword, first_name, last_name, state, created_at],
      };
      pool.query(queryObjTwo, (err, results) => {
        if (err) {
          res.json({
            message: err,
          });
        }
        res.json({
          message: "User created successfully",
        });
        console.log(res);
      });
    } else if (role_id == 2) {
      res.status(403).json({
        message: "Access denied"
      })
    } else {
      res.status(400).json({
        message: "Please pass a role id of 1 or 2"
      })
    }
  });
});

//User login
router.post("/login", (req, res) => {
  const {
    email
  } = req.body;
  pool.query(
    "SELECT * FROM Users WHERE email = $1",
    [email],
    (err, results) => {
      if (results.rowCount == 0) {
        res.json({
          message: "Wrong email or password",
        });
      }
      if (err) {
        throw err;
      }
      if (results.rowCount == 1) {
        const user = results.rows[0];
        const {
          password
        } = req.body;
        pool.query(
          "SELECT * FROM Users WHERE password = $1",
          [password],
          (err, results) => {
            bcrypt.compare(password, user.password, (err, isMatch) => {
              if (err) {
                throw err;
              }
              if (isMatch) {
                const token = jwt.sign({
                  _id: user.id,
                },
                  process.env.TOKEN_SECRET
                );
                res.header("auth-token", token).json({
                  message: "Login successful",
                  token
                });
              }
              if (!isMatch) {
                res.json({
                  message: "Please make sure your password is correct",
                });
              }
            });
          }
        );
      }
    }
  );
});

module.exports = router;