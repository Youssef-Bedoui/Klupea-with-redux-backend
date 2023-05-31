const jwt = require("jsonwebtoken");

const verifyAndRefreshToken = (req, res, next) => {
  console.log("verifyAndRefreshToken middleware called");

  const { token, refreshToken } = req.cookies;
  req.refreshToken = refreshToken;

  // check for presence of token in cookies
  if (!token) {
    if (!refreshToken) {
      console.log("No Token Found");
      return res.status(401).send("No Token Found");
    }

    jwt.verify(
      refreshToken,
      process.env.SECRET_RTOKEN,
      (err, refreshTokenInfo) => {
        if (err) {
          console.log("Invalid refresh token");
          return res.status(401).send("Invalid refresh token");
        } else {
          const { id } = refreshTokenInfo;
          let newToken = jwt.sign({ id }, process.env.SECRET_TOKEN, {
            expiresIn: "2h",
          });

          res.cookie("token", newToken, {
            httpOnly: true,
            maxAge: 2 * 24 * 60 * 1000,
          });
          req.token = newToken;
          console.log("New token generated:", newToken);
          next();
        }
      }
    );
  } else {
    jwt.verify(token, process.env.SECRET_TOKEN, (err, tokenInfo) => {
      if (err) {
        console.log("Invalid token");
        return res.send("not authorized");
      }
      console.log("token:", token, "refreshToken:", refreshToken);
      req.token = token;
      next();
    });
  }
};

const checkRefToken = (req, res) => {
  // Get the refresh token from the cookies
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.send({ msg: "No refreshToken" });
  }

  // Verify the refresh token
  jwt.verify(refreshToken, process.env.SECRET_RTOKEN, (err, userData) => {
    if (err) {
      return res.send({ msg: "Invalid refreshToken" });
    }

    // Return a success message if the refresh token is valid
    return res.send({ msg: "Authenticated user" });
  });
};

const getTokens = (req, res) => {
  const{id} = req.body;
  const token = generateAccessToken(id);
  const refreshToken = generateRefreshToken(id);

  const tokenExpiry = new Date(Date.now() + 15 *  60 * 1000); 
  const refreshTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

  // Set the token and refresh token as HTTP-only cookies with expiry dates
  res.cookie("token", token, { httpOnly: true, expires: tokenExpiry });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    expires: refreshTokenExpiry,
  });

  res.status(200).json({
    token: token,
    refreshToken: refreshToken,
  });
};

// Generate JWT token
const generateAccessToken = (id) => {
  return jwt.sign({ id }, process.env.SECRET_TOKEN, {
    expiresIn: "15min",
  });
};

// Generate Refresh Token
const generateRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.SECRET_RTOKEN, {
    expiresIn: "1d",
  });
};
// const { token, refreshToken } = req;
// console.log(res)
// console.log("Token:", token);
// console.log("Refresh Token:", refreshToken);

// res.status(200).json({ token, refreshToken });

const logout = (req, res) => {
  res.clearCookie("token");
  res.clearCookie("refreshToken");
  res.status(200).send("Logout succes");
};

require("dotenv").config();
module.exports = { verifyAndRefreshToken, checkRefToken, getTokens, logout };
