
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.SECRET_KEY || "fallback_secret";



app.use(cors());
app.use(express.json());


const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 

  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid Token" });
    req.user = user; // Simpan data user di request
    next();
  });
};


app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) return res.status(400).json({ error: "Input tidak lengkap" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: { username, passwordHash: hashedPassword }
    });
    res.status(201).json({ id: newUser.id, username: newUser.username });
  } catch (error) {
    
    if (error.code === 'P2002') {
      return res.status(409).json({ error: "Username already exists" });
    }
    res.status(500).json({ error: "Something went wrong" });
  }
});


app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = await prisma.user.findUnique({ where: { username } });
  if (!user) return res.status(401).json({ error: "User not found" });

  const validPassword = await bcrypt.compare(password, user.passwordHash);
  if (!validPassword) return res.status(401).json({ error: "Invalid credentials" });

 
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});


app.post('/api/posts', authenticate, async (req, res) => {
  const { content } = req.body;


  if (!content || content.length > 200) {
    return res.status(422).json({ error: "Content must be 1-200 characters" });
  }

  const newPost = await prisma.post.create({
    data: {
      content,
      userId: req.user.id 
    }
  });

  res.status(201).json({
    id: newPost.id,
    userid: newPost.userId,
    content: newPost.content,
    createdat: newPost.createdAt
  });
});


app.post('/api/follow/:userid', authenticate, async (req, res) => {
  const followeeId = parseInt(req.params.userid);
  const followerId = req.user.id;

  if (followerId === followeeId) {
    return res.status(400).json({ error: "Cannot follow yourself" });
  }

  try {
    
    const targetUser = await prisma.user.findUnique({ where: { id: followeeId } });
    if (!targetUser) return res.status(404).json({ error: "User not found" });

    await prisma.follow.create({
      data: { followerId, followeeId }
    });
    res.json({ message: `You are now following user ${followeeId}` });
  } catch (error) {
    
    res.status(400).json({ message: "Already following or error" });
  }
});


app.delete('/api/follow/:userid', authenticate, async (req, res) => {
  const followeeId = parseInt(req.params.userid);
  const followerId = req.user.id;

  try {
    await prisma.follow.delete({
      where: {
        followerId_followeeId: { followerId, followeeId }
      }
    });
    res.json({ message: `You unfollowed user ${followeeId}` });
  } catch (error) {
    res.status(404).json({ error: "Relationship not found" });
  }
});


app.get('/api/feed', authenticate, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;

  try {
  
    const following = await prisma.follow.findMany({
      where: { followerId: req.user.id },
      select: { followeeId: true }
    });

    
    const followingIds = following.map(f => f.followeeId);

    
    const posts = await prisma.post.findMany({
      where: {
        userId: { in: followingIds }
      },
      orderBy: { createdAt: 'desc' }, 
      skip: skip,
      take: limit,
      include: {
        user: { select: { username: true } } 
      }
    });

    res.json({ page, posts });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch feed" });
  }
});

app.get("/", (req, res) => {
  res.json({ message: "Backend is running 🚀. Welcome to API base route." });
});

app.get("/api", (req, res) => {
  res.json({ message: "API running successfully 🚀" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});