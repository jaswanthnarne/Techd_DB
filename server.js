const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = require('./config/dbconfig');

// Route imports
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const ctfRoutes = require('./routes/ctfRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();


// ✅ FIX: Trust proxy ONLY for Vercel production
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
  console.log('🔧 Trust proxy enabled for Vercel');
}
connectDB();


// CORS configuration for Vercel
const allowedOrigins = [
  'https://ctftechd.vercel.app',
  'https://ctfchallange.vercel.app',
  'http://localhost:5173',
  'http://localhost:3000',
];

// Security Middleware
app.use(helmet());
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or server-to-server)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.some(allowedOrigin => {
      if (allowedOrigin.includes('*')) {
        const domain = allowedOrigin.replace('*.', '');
        return origin.endsWith(domain);
      }
      return origin === allowedOrigin;
    })) {
      callback(null, true);
    } else {
      console.log('Blocked by CORS:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With']
}));

// Handle preflight requests
app.options('*', cors());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500, // requests per window
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Body Parsing Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl} - Origin: ${req.headers.origin || 'No Origin'}`);
  next();
});

// API Routes
app.use('/api/auth', authRoutes.router);
app.use('/api/admin', adminRoutes.router);
app.use('/api/ctf', ctfRoutes);
app.use('/api/user', userRoutes);

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    platform: 'Vercel',
    cors: {
      allowedOrigins: allowedOrigins,
      currentOrigin: req.headers.origin || 'No Origin Header'
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'CTF Platform API - Pure CTF Management System',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    platform: 'Vercel',
    status: 'operational',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/api/auth',
      admin: '/api/admin', 
      ctf: '/api/ctf',
      user: '/api/user',
      health: '/api/health'
    },
    frontend: 'https://ctftechd.vercel.app',
    documentation: 'Visit /api for API documentation'
  });
});

// API info endpoint
app.get('/api', (req, res) => {
  res.json({
    name: 'CTF Platform API',
    version: '1.0.0',
    status: 'operational',
    platform: 'Vercel',
    timestamp: new Date().toISOString(),
    cors: {
      enabled: true,
      allowedOrigins: allowedOrigins
    },
    endpoints: {
      auth: {
        login: 'POST /api/auth/login',
        register: 'POST /api/auth/register',
        logout: 'POST /api/auth/logout',
        'google-auth': 'POST /api/auth/google',
        'forgot-password': 'POST /api/auth/forgot-password',
        'reset-password': 'POST /api/auth/reset-password'
      },
      admin: {
        users: 'GET /api/admin/users',
        challenges: 'GET/POST /api/admin/challenges',
        categories: 'GET/POST /api/admin/categories'
      },
      ctf: {
        challenges: 'GET /api/ctf/challenges',
        submit: 'POST /api/ctf/submit',
        leaderboard: 'GET /api/ctf/leaderboard'
      },
      user: {
        profile: 'GET /api/user/profile',
        'update-profile': 'PUT /api/user/profile'
      }
    }
  });
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    availableRoutes: [
      '/api/auth/*',
      '/api/admin/*',
      '/api/ctf/*', 
      '/api/user/*',
      '/api/health',
      '/api'
    ],
    documentation: 'Visit /api for API documentation'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error Stack:', err.stack);
  
  // CORS errors
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ 
      error: 'CORS Error: Origin not allowed',
      allowedOrigins: allowedOrigins,
      yourOrigin: req.headers.origin,
      documentation: 'Make sure your frontend URL is in the allowed origins list'
    });
  }
  
  // JSON parsing errors
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ 
      error: 'Invalid JSON in request body',
      message: 'Please check your request body format'
    });
  }
  
  // Rate limit errors
  if (err.status === 429) {
    return res.status(429).json({
      error: 'Rate limit exceeded',
      message: 'Too many requests from this IP, please try again later.'
    });
  }
  
  // MongoDB errors
  if (err.name === 'MongoError' || err.name === 'MongoNetworkError') {
    return res.status(503).json({
      error: 'Database error',
      message: 'Service temporarily unavailable. Please try again later.'
    });
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
    return res.status(401).json({
      error: 'Authentication error',
      message: 'Invalid or expired token'
    });
  }
  
  // Default error
  res.status(err.status || 500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message,
    ...(process.env.NODE_ENV !== 'production' && { 
      stack: err.stack,
      details: err 
    })
  });
});

const PORT = process.env.PORT || 3000;

// Export for Vercel (required for serverless functions)
module.exports = app;

// Only start server locally when not in production
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`
🚀 CTF Platform Server running on port ${PORT}
📊 Environment: ${process.env.NODE_ENV || 'development'}
🔗 Frontend URL: https://ctftechd.vercel.app
📧 Email Service: ${process.env.EMAIL_USER ? 'Enabled' : 'Disabled'}
🌐 Platform: ${process.env.NODE_ENV === 'production' ? 'Vercel' : 'Local Development'}
✅ Health Check: http://localhost:${PORT}/api/health
📚 API Docs: http://localhost:${PORT}/api
🗄️ Database: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Connecting...'}
    `);
  });
}