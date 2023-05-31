const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const db = require("../database"); 
require("dotenv").config();

const login = (req, res) => {
  let { email, password } = req.body;

  const sql = `SELECT * FROM klupea.users WHERE email = ?;`;
  db.query(sql, email, (err, result) => {
    if (err) {
      res.send({ err: err });
    } else if (result.length > 0) {
      bcrypt.compare(password, result[0].password, (err, response) => {
        if (response) {
          const id = result[0].id;
          const token = generateAccessToken(id);
          const refreshToken = generateRefreshToken(id);

          const tokenExpiry = new Date(Date.now() + 15 * 1000); // 15min
          const refreshTokenExpiry = new Date(
            Date.now() + 24 * 60 * 60 * 1000
          ); 

          // Set the token and refresh token as HTTP-only cookies with expiry dates
          res.cookie("token", token, { httpOnly: true, expires: tokenExpiry });
          res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            expires: refreshTokenExpiry,
          });

          res.status(200).json({
            auth: true,
            result: result,
            token: token,
            refreshToken: refreshToken,
          });
        } else {
          return res.status(401).json({ auth: false, msg: "Wrong Email or Password !" });
        }
      });
    } else {
      return res.status(401).json({ auth: false, msg: "User doesn't exisit" });
    }
  });
};

// Generate JWT token
const generateAccessToken = (id) => {
  return jwt.sign({ id }, process.env.SECRET_TOKEN, {
    expiresIn: "2h",
  });
};

// Generate Refresh Token
const generateRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.SECRET_RTOKEN, {
    expiresIn: "15d",
  });
};

const updateUserData = (req, res) => {
  const id = req.params.id;
  const data = req.body;
  const sql = `UPDATE users SET ? WHERE id = ?`;
  const sql2 = `SELECT * FROM users WHERE id = ?`;
  db.query(sql, [data, id], (err, result) => {
    if (err) {
      console.log(err, "errrrreur");
      return res.json(err);
    }
    console.log(result);
    db.query(sql2, id, (err, result2) => {
      if (err) {
        console.log(err, "err");
        return res.json(err);
      }
      return res.json(result2[0]);
    });
  });
};

const userInfo = (req, res) => {
  const { id } = req.params;
  const sql = `SELECT * FROM klupea.users WHERE id=?;`;
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.send(result);
    }
  });
};

const deleteAccount = (req, res) => {
  const id = req.params.id;
  const sql = `DELETE FROM users WHERE id = ?`;
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.send(result);
    }
  });
};

const restPassword = (req, res) => {
  const { activationCode } = req.params;
  const { password, confirmPass } = req.body;
  console.log(password, confirmPass, activationCode);
  if (password === confirmPass) {
    const sql = `SELECT * FROM users WHERE activationCode=? AND isActive="true"`;
    db.query(sql, activationCode, (err, result) => {
      if (result.length > 0) {
        bcrypt.hash(password, saltRounds, (err, hash) => {
          if (err) {
            console.log(err);
          }
          console.log("heeee");
          const sql = `UPDATE klupea.users SET password=?`;
          db.query(sql, [hash], (err, result) => {
            if (err) {
              console.log(err);
              res.send("An error occured, please retry later");
            } else {
              res.status(200).send("Password Updated Successfully !");
            }
          });
        });
      }
    });
  }
};

module.exports = {
  login,
  updateUserData,
  userInfo,
  deleteAccount,
  restPassword,
};
