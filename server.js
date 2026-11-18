const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./database");

const app = express();

app.use(express.json());

const PORT = 3000;

// JWT Secret Key
const JWT_SECRET = "my_secret_key_123";

// Home route
app.get("/", (req, res) => {
    res.send("Registration and Login API is Running");
});

// REGISTER API
app.post("/register/", async (req, res) => {

    const { username, name, password } = req.body;

    if (!username || !name || !password) {
        return res.status(400).send("All fields are required");
    }

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {

            if (err) {
                return res.status(500).send("Database error");
            }

            if (user) {
                return res.status(400).send("User already exists");
            }

            try {
                const hashedPassword = await bcrypt.hash(password, 10);

                db.run(
                    `INSERT INTO users (username, name, password)
                     VALUES (?, ?, ?)`,
                    [username, name, hashedPassword],
                    function (err) {

                        if (err) {
                            return res.status(500).send("Registration failed");
                        }

                        return res.status(200).send("User registered successfully");
                    }
                );

            } catch (error) {
                return res.status(500).send("Password hashing failed");
            }
        }
    );
});


// LOGIN API
app.post("/login/", (req, res) => {

    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send("Username and password are required");
    }

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {

            if (err) {
                return res.status(500).send("Database error");
            }

            if (!user) {
                return res.status(400).send("Invalid user");
            }

            try {
                const isPasswordCorrect = await bcrypt.compare(
                    password,
                    user.password
                );

                if (!isPasswordCorrect) {
                    return res.status(400).send("Invalid password");
                }

                const token = jwt.sign(
                    { username: username },
                    JWT_SECRET,
                    { expiresIn: "1h" }
                );

                return res.status(200).json({
                    jwt_token: token
                });

            } catch (error) {
                return res.status(500).send("Login failed");
            }
        }
    );
});


// Start Server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});
*
