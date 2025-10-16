const mongoose = require('mongoose');

const submissionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  ctf: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'CTF',
    required: true
  },
  flag: {
    type: String,
    required: true
  },
  isCorrect: {
    type: Boolean,
    default: false
  },
  points: {
    type: Number,
    default: 0
  },
  screenshot: {
    public_id: String,
    url: String,
    filename: String,
    size: Number,
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  },
  submissionStatus: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  adminFeedback: {
    type: String,
    default: ''
  },
  submittedAt: {
    type: Date,
    default: Date.now
  },
  reviewedAt: Date,
  reviewedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin'
  },
  ipAddress: String,
  userAgent: String,
  attemptNumber: {
    type: Number,
    default: 1
  }
}, { timestamps: true });

// Compound index to track user submissions per CTF
// submissionSchema.index({ user: 1, ctf: 1 });
submissionSchema.index({ ctf: 1, submittedAt: -1 });
submissionSchema.index({ user: 1, submittedAt: -1 });
submissionSchema.index({ submissionStatus: 1 });

module.exports = mongoose.model('Submission', submissionSchema);