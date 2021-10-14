
const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')


const JWT_SECRET = 'sdjkfh8923yhjdksbfma@#*(&@*!^#&@bhjb2qiuhesdbhjdsfg839ujkdhfjk'

mongoose.connect('mongodb+srv://macbook:macbook@cluster0.ztfod.mongodb.net/myFirstDatabase?retryWrites=true&w=majority', {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	useCreateIndex: true
})



const app = express();
app.use(bodyParser.json())
app.use('/', express.static(path.join(__dirname, 'static')))


app.post('/create-user', async (req, res) => {
	const { username, password: plainTextPassword } = req.body

	if (!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Invalid username' })
	}

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

	const password = await bcrypt.hash(plainTextPassword, 10)

	try {
		const response = await User.create({
			username,
			password
		})
		console.log('User created successfully: ', response)
	} catch (error) {
		if (error.code === 11000) {
			// duplicate key
			return res.json({ status: 'error', error: 'Username already in use' })
		}
		throw error
	}

	res.json({ status: 'ok' })
})

app.post('/login-user', async (req, res) => {
	const { username, password } = req.body
	const user = await User.findOne({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Invalid username/password' })
	}

	if (await bcrypt.compare(password, user.password)){

		jwt.sign({user}, 'secretkey', { expiresIn: '3000s' }, (err, token) => {
		  res.json({
			token
		  });
		});
	}

});

app.post('/auth', verifyToken, (req, res) => {  
	jwt.verify(req.token, 'secretkey', (err, authData) => {
	  if(err) {
		res.sendStatus(401);
	  } else {
		res.json({
		  message: 'Authorization Successfull',
		  authData
		});
	  }
	});
  });



function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  console.log(typeof bearerHeader)
  if(typeof bearerHeader !== 'undefined') {
    const bearer = bearerHeader.split(' ');
    const bearerToken = bearer[1];
    req.token = bearerToken;
    next();
  } else {
	  console.log("in else")
    res.sendStatus(403);
  }

}

app.listen(5000, () => console.log('Server started on port 5000'));