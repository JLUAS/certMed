const express = require('express');
const cors = require('cors');
const multer = require('multer');
const mysql = require('mysql');
const dotenv = require("dotenv");
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require("bcryptjs");
const path = require('path');
const fs = require('fs');

// Configuración de multer para almacenar el archivo en memoria
dotenv.config({ path: './.env' });

const app = express();

// Definir el directorio de carga de archivos
const uploadDir = path.join(__dirname, 'public', 'uploads');

// Verificar si el directorio de uploads existe; si no, crearlo
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configuración de multer para almacenar archivos subidos
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './'); // Directorio donde se guardarán las imágenes
  },
  filename: function (req, file, cb) {
    // Crear un nombre único para el archivo subido
    cb(null, Date.now() + path.extname(file.originalname)); // Añade un timestamp al nombre del archivo
  }
});

const upload = multer({ storage: storage });

app.use(bodyParser.json());
app.use(cors());

const port = process.env.PORT || 3030;

const dbConfig = {
  host: process.env.host,
  user: process.env.user,
  password: process.env.password,
  database: process.env.database,
  connectionLimit: 10,
};

const pool = mysql.createPool(dbConfig);

pool.on('connection', (connection) => {
  console.log('New connection established with ID:', connection.threadId);
});

pool.on('acquire', (connection) => {
  console.log('Connection %d acquired', connection.threadId);
});

pool.on('release', (connection) => {
  console.log('Connection %d released', connection.threadId);
});

pool.on('error', (err) => {
  console.error('MySQL error: ', err);
});

function handleDisconnect() {
  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error getting connection: ', err);
      setTimeout(handleDisconnect, 2000);
    } else {
      connection.release();
      console.log('MySQL connected');
    }
  });
}

handleDisconnect();

app.post('/register', async (req, res) => {
    const { email, password, username, rol, auth, authCode, speciality, hSpeciality } = req.body;
    console.log(req.body)
    const hashedPassword = await bcrypt.hash(password, 10);
    pool.getConnection((err, connection) => {
        if (err) return res.status(500).send(err);

        connection.beginTransaction(err => {
        if (err) {
            connection.release();
            return res.status(500).send(err);
        }

        connection.query('INSERT INTO users (email, password, username, rol, auth, authCode, speciality, hSpeciality) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [email, hashedPassword, username, rol, auth, authCode, speciality, hSpeciality], (err, result) => {
            if (err) {
            connection.rollback(() => {
                connection.release();
                return res.status(500).send(err);
            });
            } else {
            connection.commit(err => {
                if (err) {
                connection.rollback(() => {
                    connection.release();
                    return res.status(500).send(err);
                });
                } else {
                connection.release();
                res.status(200).send('Usuario registrado correctamente');
                }
            });
            }
        });
        });
    });
})

app.post('/login', (req, res) => {
    const { username, password } = req.body;
  
    pool.getConnection((err, connection) => {
      if (err) return res.status(500).send(err);
      connection.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        connection.release();
        if (err) return res.status(500).send(err);
        if (!results.length || !(await bcrypt.compare(password, results[0].password))) {
          return res.status(401).send('Nombre de usuario o contraseña incorrecta');
        }
        const token = jwt.sign({ id: results[0].id, role: results[0].role }, 'secretkey', { expiresIn: '74h' });
        res.status(200).send({ token });
      });
    });
  });

app.listen(port, () => {
    console.log(`Servidor ejecutándose en el puerto ${port}`);
});