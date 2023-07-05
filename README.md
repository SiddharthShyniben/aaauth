# aaauth: Simple. OPinionated. Auth.
 
aaauth is a simple, opinionated, auth library. It provides a router and a middleware function which you can use.

```js
import express from 'express';
import Aaauth from 'aaauth';

import {createUser, userExists, getUser, storeRefreshToken, refreshTokenExists, invalidateRefreshToken} from './db.js';

const app = express();

const aaauth = Aaauth({
	jwtSecret: process.env.JWT_SECRET,
	createUser, userExists, getUser, storeRefreshToken, refreshTokenExists, invalidateRefreshToken
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(aaauth.router);

app.get('/', (req, res) => { // Normal route
	res.send('Hello World!');
});

app.get('/secure', aaauth.authenticate, (req, res) => { // Secure route: needs access token
	res.send(`Hello, ${req.user.username}!`);
});

app.listen(3000, () => {
	console.log('Example app listening on port 3000!');
});
```

## Features

- Small: less than 150 lines of code
- Simple: just `app.use(aaauth.router)` and your router is up
- Uses JWT and supports access tokens and refresh tokens
	- Partially supports RTR

## Docs

The aaauth library exposes a single function: `Aaauth`. This function takes an object with the following properties:

 * `jwtSecret: string`: The secret used to sign the JWT.
 * `userFields: string[]`: All the properties a user object should have. 
 * `jwtFields: string[]`: All the properties a JWT should have.
 * `createUser(user: {username: string, password: string, ...other details})`: A function which creates a user.
 * `userExists(user: {username: string})`: A function which checks if a user exists.
 * `getUser(user: {username: string})`: A function which gets a user.
 * `storeRefreshToken(token: string, user: {username: string, password: string, ...other details})`: A function which stores a refresh token.
 * `refreshTokenExists(token: string)`: A function which checks if a refresh token exists.
 * `invalidateRefreshToken(token: string, user: {username: string, password: string, ...other details})`: A function which invalidates a refresh token.

The `Aaauth` function returns an object with the following properties:

 * `router: Router`: An express router.
 * `authenticate: function`: A middleware function which is used for secure routes.

The router registers 3 routes: `/login`, `/register` and `/token`.

 * `/register`: `POST` to this route with all user data and it will validate it and call the `createUser` function.
 * `/login`: `POST` to this route with a username and password. It responds with a refresh token and an access token.
 * `/token`: `POST` to this route with a refresh token and it responds with a new access token and refresh token.

You can use the `authenticate` function to protect routes.

```js
app.get('/secure', aaauth.authenticate, (req, res) => { // Secure route: needs access token
	res.json({
		message: 'Hello World!',
		user: req.user
	});
});
```
