const usersDB = {
    users: require("../model/users.json"),
    setUsers: function (data) { this.users = data }
}

const fsPromises = require("fs").promises;
const path = require('path');
const bcrypt = require('bcrypt');


const handleNewUser = async (req, res) => {
    const { user, pwd } = req.body;
    if (!user || !pwd) return res.status(400).json({ "message": "Username and password are required!"});
    // Check for duplicate username in the DB
    const duplicateUsername = usersDB.users.find(usr => usr.username === user);

    if (duplicateUsername) return res.sendStatus(409); //Conflict
    try {
        // Encrypt the password
        const hashPwd = await bcrypt.hash(pwd, 10);
        // Store new user
        const newUser = { 
            "username": user,
            "roles": { "User": 2001 },
             "password": hashPwd };
        usersDB.setUsers([...usersDB.users, newUser]);
        await fsPromises.writeFile(
            path.join(__dirname, "..", "model", "users.json"),
            JSON.stringify(usersDB.users)
        );
        console.log(usersDB.users);
        res.status(201).json({ "success": `New user ${user} created!` });        
    } catch (error) {
        res.status(500).json({ "message": error.message });
    }
}

module.exports = { handleNewUser }