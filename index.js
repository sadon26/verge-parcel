const express = require("express");
const morgan = require("morgan");
const auth = require("./auth/auth");
const parcel = require("./parcel/parcel");
const dotenv = require("dotenv")

dotenv.config({
    path: "./config/config.env"
})

const app = express();

app.use(express.json());
app.use(morgan('dev'));


app.get('/', (req, res) => {
    res.json({
        message: "Welcome to our parcel delivery app"
    });
})
//Route for sign up and login auth
app.use('/api/v1/auth', auth);

//Route for parcel delivery app
app.use('/api/v1/parcel', parcel)

PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server is running on PORT ${ PORT }`)
})