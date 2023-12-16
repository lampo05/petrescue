const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bodyParser = require('body-parser'); // Tambahkan ini
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    authPlugins: {
        mysql_clear_password: () => () => Buffer.from(process.env.DB_PASSWORD + '\0'),
    },
});

const jwtSecret = process.env.JWT_SECRET;

db.connect((err) => {
    if (err) {
        console.error('Koneksi ke MySQL gagal: ', err);
    } else {
        console.log('Terhubung ke MySQL');
        console.log('Host Cloud SQL: ', process.env.DB_HOST);
        console.log('Nama Database: ', process.env.DB_DATABASE);
    }
});

// Middleware untuk memverifikasi token JWT
function verifyToken(req, res, next) {
    console.log('Executing verifyToken middleware');

    const authHeader = req.header('Authorization');

    if (!authHeader) {
        console.log('No token found');
        return res.status(403).json({
            error: true,
            message: 'Access denied. Token not found.'
        });
    }

    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            console.error('JWT Verification Error:', err);
            return res.status(401).json({
                error: true,
                message: 'Invalid token'
            });
        }

        console.log('User from token:', user);

        if (!user || !user.user_id) {
            console.error('User not found in the token');
            return res.status(401).json({
                error: true,
                message: 'User not found'
            });
        }

        req.user = user;
        next();
    });
}

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(express.json());
module.exports = verifyToken;


app.use(bodyParser.urlencoded({
    extended: true
})); // Tambahkan ini
app.use(express.json());

app.post('/register', (req, res) => {
    const {
        name,
        email,
        password
    } = req.body;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({
            error: true,
            message: 'invalid email format'
        });
    }

    if (password.length < 8) {
        return res.status(400).json({
            error: true,
            message: 'Password must be at least 8 characters long'
        });
    }

    const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
    db.query(checkEmailQuery, [email], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'there is an error'
            });
        }

        if (results.length > 0) {
            return res.status(400).json({
                error: true,
                message: 'email is registered'
            });
        }

        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error(err);
                return res.status(500).json({
                    error: true,
                    message: 'there is an error'
                });
            }

            const insertUserQuery = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
            db.query(insertUserQuery, [name, email, hashedPassword], (err) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({
                        error: true,
                        message: 'there is an error'
                    });
                }

                res.status(201).json({
                    error: false,
                    message: 'User Created'
                });
            });
        });
    });
});

app.post('/login', (req, res) => {
    const {
        email,
        password
    } = req.body;

    const findUserQuery = 'SELECT * FROM users WHERE email = ?';
    db.query(findUserQuery, [email], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'There is an error'
            });
        }

        if (results.length === 0 || !(await bcrypt.compare(password, results[0].password))) {
            return res.status(401).json({
                error: true,
                message: 'Email or password is incorrect'
            });
        }

        // Pastikan bahwa user_id disertakan dalam payload token
        const token = jwt.sign({
                user_id: results[0].user_id, // Pastikan user_id ada di sini
                email: results[0].email
            },
            jwtSecret, {
                expiresIn: '1h'
            }
        );

        res.json({
            error: false,
            message: 'Success',
            loginResult: {
                userId: results[0].user_id,
                name: results[0].name,
                token: token
            }
        });
    });
});

// ... (kode yang sudah ada)

// Menampilkan daftar hewan lost
app.get('/lost', (req, res) => {
    const getLostPetsQuery = 'SELECT * FROM pets WHERE type = "lost"';
    db.query(getLostPetsQuery, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'there is an error'
            });
        }
        res.json(results);
    });
});

// Menampilkan daftar hewan found
app.get('/found', (req, res) => {
    const getFoundPetsQuery = 'SELECT * FROM pets WHERE type = "found"';
    db.query(getFoundPetsQuery, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'there is an error'
            });
        }
        res.json(results);
    });
});

// Menampilkan detail hewan berdasarkan ID
app.get('/pet/:id', (req, res) => {
    const petId = req.params.id;
    const getPetDetailsQuery = 'SELECT * FROM pets WHERE pet_id = ?';
    db.query(getPetDetailsQuery, [petId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'there is an error'
            });
        }
        if (results.length === 0) {
            return res.status(404).json({
                error: true,
                message: 'Pet not found'
            });
        }
        res.json(results[0]);
    });
});

// Pencarian hewan berdasarkan nama
app.get('/search/:name', (req, res) => {
    const petName = req.params.name;
    const searchPetsQuery = 'SELECT * FROM pets WHERE pet_name LIKE ?';
    db.query(searchPetsQuery, [`%${petName}%`], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'there is an error'
            });
        }
        res.json(results);
    });
});

// Menampilkan profil pengguna berdasarkan token JWT
app.get('/profile', verifyToken, (req, res) => {
    const userId = req.user.user_id;
    const getUserProfileQuery = 'SELECT name, email FROM users WHERE user_id = ?';

    db.query(getUserProfileQuery, [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'There is an error'
            });
        }

        if (results.length === 0) {
            return res.status(404).json({
                error: true,
                message: 'User not found'
            });
        }

        const {
            name,
            email
        } = results[0];
        res.json({
            name,
            email
        });
    });
});



// Melaporkan hewan hilang
app.post('/report/lost', verifyToken, (req, res) => {
    const {
        pet_name,
        type,
        gender,
        date_lost_found,
        description,
        reward,
        image_url,
        province,
        regency,
        found_area
    } = req.body;

    const userEmail = req.user.email;

    // Dapatkan user_id berdasarkan email
    const getUserIdQuery = 'SELECT user_id FROM users WHERE email = ?';
    db.query(getUserIdQuery, [userEmail], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'there is an error'
            });
        }
        if (results.length === 0) {
            return res.status(404).json({
                error: true,
                message: 'User not found'
            });
        }

        const userId = results[0].user_id;

        const insertLostPetQuery = `
            INSERT INTO pets (user_id, pet_name, type, gender, date_lost_found, description, reward, image_url, province, regency, found_area)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        db.query(
            insertLostPetQuery,
            [userId, pet_name, type, gender, date_lost_found, description, reward, image_url, province, regency, found_area],
            (err) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({
                        error: true,
                        message: 'there is an error'
                    });
                }
                res.status(201).json({
                    error: false,
                    message: 'Lost pet reported successfully'
                });
            }
        );
    });
});


// Melaporkan hewan ditemukan
app.post('/report/found', verifyToken, (req, res) => {
    const {
        pet_name,
        type,
        gender,
        date_lost_found,
        description,
        reward,
        image_url,
        province,
        regency,
        found_area
    } = req.body;

    const userEmail = req.user.email;

    // Dapatkan user_id berdasarkan email
    const getUserIdQuery = 'SELECT user_id FROM users WHERE email = ?';
    db.query(getUserIdQuery, [userEmail], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'there is an error'
            });
        }
        if (results.length === 0) {
            return res.status(404).json({
                error: true,
                message: 'User not found'
            });
        }

        const userId = results[0].user_id;

        const insertFoundPetQuery = `
            INSERT INTO pets (user_id, pet_name, type, gender, date_lost_found, description, reward, image_url, province, regency, found_area)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        db.query(
            insertFoundPetQuery,
            [userId, pet_name, type, gender, date_lost_found, description, reward, image_url, province, regency, found_area],
            (err) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({
                        error: true,
                        message: 'there is an error'
                    });
                }
                res.status(201).json({
                    error: false,
                    message: 'Found pet reported successfully'
                });
            }
        );
    });
});

// Menghapus posting hewan berdasarkan ID
app.delete('/pet/:id', verifyToken, (req, res) => {
    const petId = req.params.id;
    const deletePetQuery = 'DELETE FROM pets WHERE pet_id = ?';
    db.query(deletePetQuery, [petId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'there is an error'
            });
        }
        if (results.affectedRows === 0) {
            return res.status(404).json({
                error: true,
                message: 'Pet not found'
            });
        }
        res.json({
            error: false,
            message: 'Pet deleted successfully'
        });
    });
});


app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: true,
        message: 'there is an error'
    });
});

app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});