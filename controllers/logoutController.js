const usersDB = {
  users: require("../model/users.json"),
  setUsers: function (data) {
    this.users = data;
  },
};
// Mock Data Json File
const fsPromises = require("fs").promises;
const path = require('path');

const handleLogout = async (req, res) => {
  // On client delete the accessToken
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(204);// No content  
  const refreshToken = cookies.jwt;

  const foundUser = usersDB.users.find(usr => usr.refreshToken === refreshToken);
  if (!foundUser) {
    res.clearCookie("jwt", {
      httpOnly: true,
      sameSite: "None",
      //uncomment when not in DEV MODE
      //secure: true,
      // set to 1 Day (2 min only for DEV MODE)
      maxAge: 24 * 60 * 60 * 1000
    });
    return res.sendStatus(204); // No content
  }

  // Delete refreshToken in DB
  const otherUsers = usersDB.users.filter(usr => usr.refreshToken !== foundUser.refreshToken);
  const currentUser = {...foundUser, refreshToken: ""};
  usersDB.setUsers([...otherUsers, currentUser]);
  await fsPromises.writeFile(
    path.join(__dirname, "..", "model", "users.json"),
    JSON.stringify(usersDB.users)
  );

  res.clearCookie("jwt", {
    httpOnly: true,
    sameSite: "None",
    //uncomment when not in DEV MODE
    //secure: true,
    // set to 1 Day (2 min only for DEV MODE)
    maxAge: 24 * 60 * 60 * 1000,
  });
  res.sendStatus(204);
}

module.exports = { handleLogout }
