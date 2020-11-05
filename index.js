import bcrypt from 'bcrypt';
import express from 'express';
import session from 'express-session';
import mongoose from 'mongoose';
import passport from 'passport';
import path from 'path';

import UserModel from './mongodb/UserModel.js';

const app = express();

const {
	MONGODB,
	PORT
} = process.env;

const port = PORT || 3000;

// Throw error if dotenv isn't used in start command
if (!MONGODB) throw new Error('Please use "npm start" to start the server!');

mongoose.connect(MONGODB, {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	useFindAndModify: false,
});

passport.serializeUser(function(user, done) {
	done(null, user);
});

passport.deserializeUser(function(user, done) {
	done(null, user);
});

app
	.use(express.json())
	.use(express.urlencoded({ extended: true }))
	.use(session({
		secret: 'secret', 
		resave: true, 
		saveUninitialized: true 
	}))
	.use(express.static('public'))
	.set('views', path.join(path.resolve(), 'views'))
	.set('view engine', 'ejs')
	.get('/', async (req, res) => {
		res.render('index', {
			authenticated: req.session.loggedin,
			username: req.session.username || null
		});
	})
	.get('/login', async (req, res) => {
		return res.render('login');
	})
	.post('/login', async (req, res) => {
		const {
			email,
			password
		} = req.body;
		if (!email || !password) return res.send('Please enter Email and Password!');
		const user = await UserModel.findOne({ email: email });
		if (!user) return res.send('That email is not registered!');
		if (await bcrypt.compare(password, user.password)) {
			req.session.loggedin = true;
			req.session.username = user.username;
			return res.redirect('/');
		} else {
			return res.send('Incorrect Email and/or Password!');
		}
	})
	.get('/register', async (req, res) => {
		return res.render('register');
	})
	.post('/register', async (req, res) => {
		const {
			email,
			password,
			username
		} = req.body;
		if (!email || !password || !username) return res.send('Please enter Email, Username and Password!');
		const alreadyRegistered = {
			email: await UserModel.findOne({ email: email }),
			username: await UserModel.findOne({ username: username })
		}
		if (alreadyRegistered.email) return res.send('That email is already registered!');
		if (alreadyRegistered.username) return res.send('That username is already registered!');
		const hashedPassword = await bcrypt.hash(password, 10);
		const schema = new UserModel({
			_id: new mongoose.Types.ObjectId(),
			username: username,
			email: email,
			password: hashedPassword,
		});
		schema.save().then(() => {
			req.session.loggedin = true;
			req.session.username = username;
			return res.redirect('/');
		}).catch(() => {
			return res.redirect('/register');
		});
	})
	.listen(port, (err) => {
		if (err) console.log(err);
		else console.log(`Server online on port ${port}`);
	});