const express = require('express');
const multer = require('multer');
const {
    Storage
} = require('@google-cloud/storage');
const axios = require('axios');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
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

const storage = new Storage({
    projectId: 'pet-rescue-407209',
    keyFilename: './pet-rescue.json',
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



async function listBucket() {
    const bucketName = 'pet-rescue-407209.appspot.com';

    try {
        const [files] = await storage.bucket(bucketName).getFiles();

        console.log('Daftar objek dalam bucket:');
        files.forEach(file => {
            console.log(file.name);
        });
    } catch (err) {
        console.error('Gagal membaca bucket:', err);
    }
}

listBucket();

const storageMulter = multer.memoryStorage();
const uploadMulter = multer({
    storage: storageMulter,
});

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(express.json());


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
                expiresIn: '7d'
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
// app.get('/pet/:id', (req, res) => {
//     const petId = req.params.id;
//     const getPetDetailsQuery = 'SELECT * FROM pets WHERE pet_id = ?';
//     db.query(getPetDetailsQuery, [petId], (err, results) => {
//         if (err) {
//             console.error(err);
//             return res.status(500).json({
//                 error: true,
//                 message: 'there is an error'
//             });
//         }
//         if (results.length === 0) {
//             return res.status(404).json({
//                 error: true,
//                 message: 'Pet not found'
//             });
//         }
//         res.json(results[0]);
//     });
// });

// Pencarian hewan berdasarkan nama
app.get('/search/:name', (req, res) => {
    const petName = req.params.name;
    const searchPetsQuery = 'SELECT * FROM pets WHERE LOWER(pet_name) LIKE LOWER(?)';
    db.query(searchPetsQuery, [`%${petName}%`], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'There is an error'
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

const predictionEndpoint = 'https://pet-rescue-y3vz2akfrq-et.a.run.app/predict';

// ... (kode lainnya)
app.put('/report/lost', verifyToken, async (req, res) => {
    try {
        console.log('Request Body:', req.body);

        const {
            pet_id, // Extract pet_id from the request body
            pet_name,
            gender,
            date_lost_found,
            reward,
            province,
            regency,
            found_area,
            email,
            phone_number
        } = req.body;

        // Dapatkan user_id berdasarkan email dari token JWT
        const userId = req.user.user_id;

        // Lakukan pembaruan entri di database
        const updateLostPetQuery = `
            UPDATE pets
            SET
                pet_name = ?,
                gender = ?,
                date_lost_found = ?,
                reward = ?,
                province = ?,
                regency = ?,
                found_area = ?,
                email = ?,
                phone_number = ?
            WHERE user_id = ? AND pet_id = ?;
        `;

        const updateResult = await db.promise().execute(updateLostPetQuery, [
            pet_name,
            gender,
            date_lost_found,
            reward,
            province,
            regency,
            found_area,
            email,
            phone_number,
            userId,
            pet_id,
        ]);

        console.log('Update result:', updateResult);

        res.status(200).json({
            error: false,
            message: 'Entri hewan hilang diperbarui dengan sukses'
        });
    } catch (error) {
        console.error('Error processing report/lost:', error);
        return res.status(500).json({
            error: true,
            message: 'Error processing report/lost. Lihat log server untuk rincian.',
        });
    }
});






async function saveToCloudStorage(imageBuffer) {
    try {
        const bucketName = 'pet-rescue-407209.appspot.com';
        const bucket = storage.bucket(bucketName);

        const fileName = `images/${Date.now()}_image.jpg`;

        const file = bucket.file(fileName);
        await file.save(imageBuffer, {
            contentType: 'image/jpeg',
        });

        const fileUrl = `https://storage.googleapis.com/${bucketName}/${fileName}`;
        return fileUrl;
    } catch (error) {
        console.error('Error saving to Cloud Storage:', error);
        throw error;
    }
}

//const upload = multer(); // Set the destination folder for uploaded files

app.post('/report/found', verifyToken, (req, res) => {
    const {
        pet_name,
        type,
        gender,
        date_lost_found,
        reward,
        image_url,
        province,
        regency,
        found_area,
        email,
        phone_number
    } = req.body;

    // Check if required fields are present
    if (!pet_name || !type || !gender || !date_lost_found || !province || !regency || !found_area || !email || !phone_number) {
        return res.status(400).json({
            error: true,
            message: 'Semua kolom yang diperlukan harus diisi.'
        });
    }

    const userEmail = req.user.email;

    // Dapatkan user_id berdasarkan email
    const getUserIdQuery = 'SELECT user_id FROM users WHERE email = ?';
    db.query(getUserIdQuery, [userEmail], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: true,
                message: 'Ada kesalahan pada server'
            });
        }
        if (results.length === 0) {
            return res.status(404).json({
                error: true,
                message: 'User tidak ditemukan'
            });
        }

        const userId = results[0].user_id;

        const insertLostPetQuery = `
            INSERT INTO pets (user_id, pet_name, type, gender, date_lost_found,  reward, image_url, province, regency, found_area, email, phone_number)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        db.query(
            insertLostPetQuery,
            [userId, pet_name, type, gender, date_lost_found, reward, image_url, province, regency, found_area, email, phone_number],
            (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({
                        error: true,
                        message: 'Ada kesalahan pada server',
                        errorDetails: err.message
                    });
                }

                console.log("Insert result:", result);

                res.status(201).json({
                    error: false,
                    message: 'Hewan ditemukan dilaporkan dengan sukses'
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
