require('./utils.js');
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const app = express();

const saltRounds = 12;
const PORT = process.env.PORT || 3000;
// expire time set at 1 hour calculated in milliseconds
const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
const mongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}` +
                 `@${mongodb_host}/${mongodb_database}` +
                 `?retryWrites=true&w=majority`;

const { database } = include('databaseconnection');
const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + '/public'));

var mongoStore = MongoStore.create(
{
    mongoUrl: mongoUrl,
    crypto:
    {
        secret: mongodb_session_secret,
    },
});

app.use(session(
{
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
}));

// middleware authen to check if user is logged in
function isValidSession(req)
{
    if (req.session.authenticated)
    {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next)
{
    if (isValidSession(req))
    {
        next();
    }
    else
    {
        res.redirect('/login');
    }
}

// middleware authen to check if user is admin
function isAdmin(req)
{
    if (req.session.user_type == 'admin')
    {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next)
{
    if (!isAdmin(req))
    {
        res.status(403);
        res.render('403');
        return;
    }
    else
    {
        next();
    }
}

app.get('/', (req, res) =>
{
    res.render('index',
    {
        authenticated: req.session.authenticated || false,
        name: req.session.name || '',
    });
});

app.get('/signup', (req, res) =>
{
    res.render('signup', { error: null });
});

app.post('/signupSubmit', async (req, res) =>
{
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
    {
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required(),
    });

    const validationResult = schema.validate({ name, email, password });

    if (validationResult.error != null)
    {
        return res.render('signup',
        {
            error: validationResult.error.details[0].message,
        });
    }

    const existingUser = await userCollection.findOne({ email: email });

    if (existingUser)
    {
        return res.render('signup', { error: 'Email already exists.' });
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne(
    {
        name: name,
        email: email,
        password: hashedPassword,
        user_type: 'user',
    });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.user_type = 'user';
    req.session.cookie.maxAge = expireTime;

    req.session.save(() =>
    {
        res.redirect('/members');
    });
});

app.get('/login', (req, res) =>
{
    res.render('login', { error: null });
});

app.post('/loginSubmit', async (req, res) =>
{
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
    {
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required(),
    });

    const validationResult = schema.validate({ email, password });

    if (validationResult.error != null)
    {
        return res.render('login',
        {
            error: validationResult.error.details[0].message,
        });
    }

    const user = await userCollection.findOne({ email: email });

    if (!user)
    {
        return res.render('login', { error: 'User not found.' });
    }

    if (await bcrypt.compare(password, user.password))
    {
        req.session.authenticated = true;
        req.session.name = user.name;
        req.session.user_type = user.user_type || 'user';
        req.session.cookie.maxAge = expireTime;

        req.session.save(() =>
        {
            res.redirect('/members');
        });
    }
    else
    {
        return res.render('login', { error: 'Invalid password.' });
    }
});

app.get('/members', sessionValidation, (req, res) =>
{
    const images =
    [
        '/Darth_umanaga.png',
        '/sebastionhohoho.png',
        '/the_filalfel_castro.png',
    ];
    res.render('members', { name: req.session.name, images: images });
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) =>
{
    const users = await userCollection.find().toArray();
    res.render('admin', { users: users });
});

app.get('/promoteUser', sessionValidation, adminAuthorization, async (req, res) =>
{
    const schema = Joi.object({ email: Joi.string().email().required() });
    const { error } = schema.validate({ email: req.query.email });
    if (error) return res.status(400).send('Invalid email.');

    await userCollection.updateOne(
        { email: req.query.email },
        { $set: { user_type: 'admin' } },
    );
    res.redirect('/admin');
});

app.get('/demoteUser', sessionValidation, adminAuthorization, async (req, res) =>
{
    const schema = Joi.object({ email: Joi.string().email().required() });
    const { error } = schema.validate({ email: req.query.email });
    if (error) return res.status(400).send('Invalid email.');

    await userCollection.updateOne(
        { email: req.query.email },
        { $set: { user_type: 'user' } },
    );
    res.redirect('/admin');
});

app.get('/logout', (req, res) =>
{
    req.session.destroy();
    res.redirect('/');
});

app.use((req, res) =>
{
    res.status(404).render('404');
});

app.listen(PORT, () =>
{
    console.log(`Server is running on port ${PORT}`);
});