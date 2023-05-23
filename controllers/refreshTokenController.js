const usersDB = {
  users: require("../model/users.json"),
  setUsers: function (data) {
    this.users = data;
  },
};

const jwt = require("jsonwebtoken");
require("dotenv").config();

const handleRefreshToken = (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(401); // Unauthorized
  const refreshToken = cookies.jwt;

  const foundUser = usersDB.users.find(usr => usr.refreshToken === refreshToken);
  if (!foundUser) return res.sendStatus(403); // Forbidden
  // evaluate JWTs
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    (err, decoded) => {
        if (err || foundUser.username !== decoded.username) return res.sendStatus(403);
        const roles = Object.values(foundUser.roles);
        const accessToken = jwt.sign(
            { 
              "UserInfo": {
                  "username": decoded.username,
                  "roles": roles
              }    
            },    
            process.env.ACCESS_TOKEN_SECRET,
            // make it 5 min (45s only in DEV MODE)
            { expiresIn: "300s" }            
        );
        res.json({ accessToken })
    }
  );
  }

module.exports = { handleRefreshToken }
