A lightweight authentication setup using JSON Web Tokens (JWT) with Express and MongoDB. This approach issues signed tokens after a successful login and validates them on protected routes. MongoDB stores user data, while bcrypt handles password hashing. The workflow covers user registration, login, token verification, optional refresh logic, and secure access control for API endpoints. This structure keeps authentication stateless, scalable, and straightforward to integrate into any Node.js application.

Steps to run
1. Install dependencies:
   npm install

2. Start the server:
   node server.js
   or
   nodemon server.js

3. Environment:
   Ensure MONGO_URI (and other required vars like JWT_SECRET) are set in your .env before starting the server.


