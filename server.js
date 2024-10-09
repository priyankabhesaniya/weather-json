const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const bodyParser = require('body-parser');
const http = require('http');
const jwt = require('jsonwebtoken');

const SECRET_KEY = 'mnbvc';
const expiresIn = '1h';
const blacklist = new Set(); 
const httpServer = http.createServer(server);

server.use(middlewares);
server.use(bodyParser.json());

const createToken = (payload) => {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
};
const verifyToken = (token) => {
  return jwt.verify(token, SECRET_KEY, (err, decoded) => (decoded !== undefined ? decoded : err));
};
server.post('/logout', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (token) {
    blacklist.add(token);
    return res.status(200).json({ message: 'Logged out successfully' });
  } else {
    return res.status(400).json({ message: 'No token provided' });
  }
});
server.post('/login', (req, res) => {
  const { email, password } = req.body;
  const db = router.db;
  const admin = db.get('users').find({ email, password }).value();
  console.log("🚀 ~ server.post ~ admin:", admin)

  if (!admin) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  const token = createToken({ id: admin.id, email: admin.email });
  return res.status(200).json({ token,admin });
});

server.use((req, res, next) => {
  if(req.method === 'POST' && req.path == "/users"){
    next()
    return
  }
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE' || req.method === 'GET') {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(403).json({ message: 'No token provided' });
    }
   if (blacklist.has(token)) {
    return res.status(403).json({ message: 'Invalid token (logged out)' });
  }
    try {
      const verified = verifyToken(token);
      if (verified instanceof Error) {
        return res.status(403).json({ message: 'Invalid token' });
      }
      next();
    } catch (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
  } else {
    next();
  }
});





server.use(router);
const port = 5000
httpServer.listen(port, () => {
  console.log('JSON Server is running on port ' + port);
});
