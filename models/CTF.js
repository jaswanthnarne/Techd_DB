const mongoose = require('mongoose');

const ctfSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: ['Web Security', 'Cryptography', 'Forensics', 'Reverse Engineering', 'Pwn', 'Misc']
  },
  points: {
    type: Number,
    required: true,
    min: 0
  },
  difficulty: {
    type: String,
    enum: ['Easy', 'Medium', 'Hard', 'Expert'],
    default: 'Easy'
  },
  // Active hours configuration
  activeHours: {
    startTime: {
      type: String, // Format: "HH:MM" 24-hour format
      required: true
    },
    endTime: {
      type: String, // Format: "HH:MM" 24-hour format
      required: true
    },
  timezone: {
    type: String,
    default: 'Asia/Kolkata' // Your timezone
  }
  },
  // Schedule configuration
  schedule: {
    startDate: {
      type: Date,
      required: true
    },
    endDate: {
      type: Date,
      required: true
    },
    recurrence: {
      type: String,
      enum: ['once', 'daily', 'weekly', 'monthly'],
      default: 'once'
    }
  },
  ctfLink: {
    type: String,
    default: ''
  },
  // CTF status and visibility
  isVisible: {
    type: Boolean,
    default: false
  },
  isPublished: {
    type: Boolean,
    default: false
  },
  status: {
    type: String,
    enum: ['upcoming', 'active', 'ended', 'inactive'],
    default: 'upcoming'
  },
  // Participants and submissions
  participants: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    joinedAt: {
      type: Date,
      default: Date.now
    },
    submittedAt: Date,
    isCorrect: {
      type: Boolean,
      default: false
    },
    pointsEarned: {
      type: Number,
      default: 0
    },
    attempts: {
      type: Number,
      default: 0
    }
  }],
  totalSubmissions: {
    type: Number,
    default: 0
  },
  correctSubmissions: {
    type: Number,
    default: 0
  },
  // Additional CTF configuration
  maxAttempts: {
    type: Number,
    default: 1
  },
  hints: [{
    text: String,
    cost: { type: Number, default: 0 }
  }],
  files: [{
    filename: String,
    url: String,
    size: Number
  }],
  rules: {
    requireScreenshot: {
      type: Boolean,
      default: false
    },
    allowMultipleSubmissions: {
      type: Boolean,
      default: false
    }
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    required: true
  }
}, { 
  timestamps: true 
});

// Enhanced status calculation based on timing
// In CTF.js - Replace calculateStatus and isCurrentlyActive methods
ctfSchema.methods.calculateStatus = function() {
  const now = new Date();
  
  console.log('🔍 CTF Status Calculation (Active Hours Only):', {
    title: this.title,
    now: now.toISOString(),
    currentTime: now.toTimeString().slice(0, 8),
    startTime: this.activeHours.startTime,
    endTime: this.activeHours.endTime,
    isVisible: this.isVisible,
    isPublished: this.isPublished
  });
  
  // If CTF is manually set to inactive or not published
  if (!this.isVisible || !this.isPublished) {
    console.log('❌ CTF is manually invisible or not published');
    return 'inactive';
  }
  
  // Check if within active hours
  if (this.activeHours && this.activeHours.startTime && this.activeHours.endTime) {
    const currentTime = now.toTimeString().slice(0, 8); // Get HH:MM:SS format
    
    // Convert times to minutes since midnight for easy comparison
    const timeToMinutes = (timeStr) => {
      const [hours, minutes] = timeStr.split(':').map(Number);
      return hours * 60 + minutes;
    };
    
    const currentMinutes = timeToMinutes(currentTime);
    const startMinutes = timeToMinutes(this.activeHours.startTime);
    const endMinutes = timeToMinutes(this.activeHours.endTime);
    
    console.log('🕒 Active Hours Comparison:', {
      currentMinutes,
      startMinutes,
      endMinutes,
      withinHours: currentMinutes >= startMinutes && currentMinutes <= endMinutes
    });
    
    // Check if within daily active hours
    if (currentMinutes >= startMinutes && currentMinutes <= endMinutes) {
      console.log('✅ CTF is active (within active hours)');
      return 'active';
    } else {
      console.log('⏸️ CTF is inactive (outside active hours)');
      return 'inactive';
    }
  }
  
  // If no active hours defined, consider it always active when published and visible
  console.log('✅ CTF is active (no active hours defined)');
  return 'active';
};

// Active hours check only
// ctfSchema.methods.isCurrentlyActive = function() {
//   const status = this.calculateStatus();
//   const isActive = status === 'active';
//   console.log('🔍 isCurrentlyActive check:', {
//     title: this.title,
//     status: status,
//     result: isActive
//   });
//   return isActive;
// };

//Change currently time-zone after deployment

// In CTF.js - Replace the isCurrentlyActive method with this:
ctfSchema.methods.isCurrentlyActive = function() {
  const now = new Date();
  
  // Convert to IST (Asia/Kolkata) timezone
  const istTimeString = now.toLocaleTimeString('en-US', { 
    timeZone: 'Asia/Kolkata',
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
  
  console.log('🌍 Timezone Check:', {
    serverUTC: now.toISOString(),
    istTime: istTimeString,
    startTime: this.activeHours.startTime,
    endTime: this.activeHours.endTime,
    timezone: 'Asia/Kolkata' // Your timezone
  });

  const [startHours, startMinutes] = this.activeHours.startTime.split(':').map(Number);
  const [endHours, endMinutes] = this.activeHours.endTime.split(':').map(Number);

  // Use IST time for comparison
  const [currentHours, currentMinutes] = istTimeString.split(':').map(Number);
  
  const currentMinutesTotal = currentHours * 60 + currentMinutes;
  const startMinutesTotal = startHours * 60 + startMinutes;
  const endMinutesTotal = endHours * 60 + endMinutes;

  console.log('📊 Time Comparison (IST):', {
    currentTime: `${currentHours}:${currentMinutes.toString().padStart(2, '0')}`,
    currentMinutes: currentMinutesTotal,
    startMinutes: startMinutesTotal,
    endMinutes: endMinutesTotal,
    withinHours: currentMinutesTotal >= startMinutesTotal && currentMinutesTotal <= endMinutesTotal
  });

  // Handle case where active hours cross midnight
  let isActive;
  if (endMinutesTotal < startMinutesTotal) {
    // Active hours cross midnight (e.g., 22:00 - 06:00)
    isActive = currentMinutesTotal >= startMinutesTotal || currentMinutesTotal <= endMinutesTotal;
  } else {
    // Normal case (e.g., 02:00 - 18:00)
    isActive = currentMinutesTotal >= startMinutesTotal && currentMinutesTotal <= endMinutesTotal;
  }

  console.log('✅ Final Active Status:', isActive);
  return isActive;
};


// In CTF.js - Fix the canSubmit method
ctfSchema.methods.canSubmit = function() {
  // Check if CTF is visible, published, and active
  if (!this.isVisible || !this.isPublished) {
    console.log('❌ Cannot submit: CTF not visible or not published');
    return false;
  }

  // Use backend status as primary check
  if (this.status?.toLowerCase() !== 'active') {
    console.log('❌ Cannot submit: Backend status is', this.status);
    return false;
  }

  // Then check active hours
  const isActive = this.isCurrentlyActive();
  console.log('✅ Backend canSubmit result:', isActive);
  return isActive;
};

// Pre-save middleware to auto-calculate status
ctfSchema.pre('save', function(next) {
  console.log('💾 Pre-save middleware triggered for:', this.title);
  
  // Always calculate status, but respect manual inactive setting
  const newStatus = this.calculateStatus();
  
  // Only update status if it's different and CTF is visible
  if (this.status !== newStatus) {
    console.log('🔄 Status changed:', {
      from: this.status,
      to: newStatus,
      isVisible: this.isVisible
    });
    this.status = newStatus;
  } else {
    console.log('✅ Status unchanged:', this.status);
  }
  
  next();
});
// In CTF.js - Fix the isCurrentlyActive method
ctfSchema.methods.isCurrentlyActive = function() {
  const now = new Date();
  
  console.log('🔍 Backend Active Hours Check:', {
    startTime: this.activeHours.startTime,
    endTime: this.activeHours.endTime,
    currentTime: now.toTimeString(),
    currentHours24: now.getHours(),
    currentMinutes: now.getMinutes(),
    timezone: this.activeHours.timezone || 'UTC'
  });

  const [startHours, startMinutes] = this.activeHours.startTime.split(':').map(Number);
  const [endHours, endMinutes] = this.activeHours.endTime.split(':').map(Number);

  const currentMinutes = now.getHours() * 60 + now.getMinutes();
  const startMinutesTotal = startHours * 60 + startMinutes;
  const endMinutesTotal = endHours * 60 + endMinutes;

  console.log('📊 Backend Time Comparison:', {
    currentMinutes,
    startMinutesTotal,
    endMinutesTotal,
    currentTime24: `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`
  });

  // Handle case where active hours cross midnight
  let isActive;
  if (endMinutesTotal < startMinutesTotal) {
    // Active hours cross midnight (e.g., 22:00 - 06:00)
    isActive = currentMinutes >= startMinutesTotal || currentMinutes <= endMinutesTotal;
  } else {
    // Normal case (e.g., 02:00 - 18:00)
    isActive = currentMinutes >= startMinutesTotal && currentMinutes <= endMinutesTotal;
  }

  console.log('✅ Backend Active Status:', isActive);
  return isActive;
};

// Update canSubmit method
ctfSchema.methods.canSubmit = function() {
  // Check if CTF is visible, published, and active
  if (!this.isVisible || !this.isPublished) {
    console.log('❌ Cannot submit: CTF not visible or not published');
    return false;
  }

  // Use backend status as primary check
  if (this.status?.toLowerCase() !== 'active') {
    console.log('❌ Cannot submit: Backend status is', this.status);
    return false;
  }

  // Then check active hours
  const isActive = this.isCurrentlyActive();
  console.log('✅ Backend canSubmit result:', isActive);
  return isActive;
};

ctfSchema.methods.canSubmit = function() {
  // Check if CTF is visible, published, and active
  if (!this.isVisible || !this.isPublished) {
    return false;
  }

  // Use backend status as primary check
  if (this.status?.toLowerCase() !== 'active') {
    return false;
  }

  // Then check active hours
  return this.isCurrentlyActive();
};

// In your CTF model (models/CTF.js) - Add these methods:

// Force status update (admin override)
ctfSchema.methods.forceStatusUpdate = function(status) {
  console.log('🔄 Force status update:', {
    from: this.status,
    to: status,
    title: this.title
  });
  
  this.status = status;
  
  // Adjust visibility based on forced status
  if (status === 'active' || status === 'upcoming') {
    this.isVisible = true;
    this.isPublished = true;
  } else if (status === 'ended' || status === 'inactive') {
    this.isVisible = false;
  }
  
  return this;
};

// Toggle activation with proper status calculation
ctfSchema.methods.toggleActivation = async function() {
  this.isVisible = !this.isVisible;
  
  if (this.isVisible) {
    // When activating, recalculate status based on timing
    this.status = this.calculateStatus();
  } else {
    // When deactivating, set to inactive
    this.status = 'inactive';
  }
  
  await this.save();
  return this;
};

// Enhanced analytics method
ctfSchema.methods.getAnalytics = function() {
  const participants = this.participants || [];
  const correctSubmissions = participants.filter(p => p.isCorrect).length;
  const totalSubmissions = this.totalSubmissions || 0;
  
  return {
    basic: {
      title: this.title,
      category: this.category,
      difficulty: this.difficulty,
      points: this.points,
      status: this.status,
      totalParticipants: participants.length,
      correctSubmissions,
      totalSubmissions,
      successRate: totalSubmissions > 0 ? 
        Math.round((correctSubmissions / totalSubmissions) * 100) : 0,
      averageAttempts: participants.length > 0 ? 
        (participants.reduce((sum, p) => sum + (p.attempts || 0), 0) / participants.length).toFixed(1) : 0
    },
    participants: participants.map(p => ({
      user: p.user,
      joinedAt: p.joinedAt,
      submittedAt: p.submittedAt,
      isCorrect: p.isCorrect,
      pointsEarned: p.pointsEarned,
      attempts: p.attempts
    })),
    timing: {
      activeHours: this.activeHours,
      schedule: this.schedule,
      currentStatus: this.isCurrentlyActive() ? 'Active' : 'Inactive',
      nextActive: this.calculateNextActivePeriod?.() || 'Not scheduled'
    },
    performance: {
      completionRate: participants.length > 0 ? 
        Math.round((correctSubmissions / participants.length) * 100) : 0,
      averageTimeToSolve: this.calculateAverageSolveTime?.() || 'N/A'
    }
  };
};

// Calculate average solve time (optional enhancement)
ctfSchema.methods.calculateAverageSolveTime = function() {
  const correctParticipants = this.participants.filter(p => p.isCorrect && p.joinedAt && p.submittedAt);
  
  if (correctParticipants.length === 0) return 'N/A';
  
  const totalTime = correctParticipants.reduce((sum, p) => {
    const solveTime = new Date(p.submittedAt) - new Date(p.joinedAt);
    return sum + solveTime;
  }, 0);
  
  const averageMs = totalTime / correctParticipants.length;
  const minutes = Math.floor(averageMs / (1000 * 60));
  const hours = Math.floor(minutes / 60);
  
  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`;
  }
  return `${minutes}m`;
};
// Check if user has pending submission for this CTF
ctfSchema.methods.hasPendingSubmission = function(userId) {
  return this.participants.some(p => 
    p.user.toString() === userId.toString() && 
    p.hasPendingSubmission
  );
};

// Update participant submission status
ctfSchema.methods.updateParticipantSubmissionStatus = function(userId, hasPending) {
  const participant = this.participants.find(p => 
    p.user.toString() === userId.toString()
  );
  
  if (participant) {
    participant.hasPendingSubmission = hasPending;
  }
  
  return this;
};

// Update CTF status
ctfSchema.methods.updateStatus = async function() {
  const newStatus = this.calculateStatus();
  
  if (this.status !== newStatus) {
    this.status = newStatus;
    await this.save();
  }
  
  return this;
};



// Check if user can submit
ctfSchema.methods.canSubmit = function() {
  const now = new Date();
  return this.isVisible && 
         now >= this.schedule.startDate && 
         now <= this.schedule.endDate && 
         this.isCurrentlyActive();
};

// Add participant to CTF
ctfSchema.methods.addParticipant = function(userId) {
  const existingParticipant = this.participants.find(
    p => p.user.toString() === userId.toString()
  );
  
  if (!existingParticipant) {
    this.participants.push({
      user: userId,
      joinedAt: new Date()
    });
  }
  
  return this;
};

// In CTF.js - Fix the submitFlag method
ctfSchema.methods.submitFlag = function(userId, flag, screenshot = null) {
  const participant = this.participants.find(
    p => p.user.toString() === userId.toString()
  );
  
  if (!participant) {
    throw new Error('User is not a participant of this CTF');
  }
  
  // Enhanced validation with detailed logging
  console.log('🔍 submitFlag - Validation Check:', {
    title: this.title,
    isVisible: this.isVisible,
    isPublished: this.isPublished,
    status: this.status,
    isCurrentlyActive: this.isCurrentlyActive(),
    canSubmit: this.canSubmit(),
    activeHours: this.activeHours,
    currentTime: new Date().toLocaleTimeString()
  });

  // Direct validation instead of relying on canSubmit()
  if (!this.isVisible || !this.isPublished) {
    throw new Error('CTF is not available for submissions');
  }

  if (this.status?.toLowerCase() !== 'active') {
    throw new Error(`CTF is ${this.status}. Submissions are not allowed.`);
  }

  if (!this.isCurrentlyActive()) {
    throw new Error(`CTF is only active between ${this.activeHours.startTime} - ${this.activeHours.endTime}`);
  }

  if (participant.attempts >= this.maxAttempts && !this.rules.allowMultipleSubmissions) {
    throw new Error('Maximum attempts reached');
  }
  
  participant.attempts += 1;
  participant.submittedAt = new Date();
  
  // Compare with the actual flag
  const isCorrect = flag === this.flag;
  
  if (isCorrect) {
    participant.isCorrect = true;
    participant.pointsEarned = this.points;
    this.correctSubmissions += 1;
  }
  
  this.totalSubmissions += 1;
  
  return {
    isCorrect,
    points: isCorrect ? this.points : 0,
    attempts: participant.attempts,
    maxAttempts: this.maxAttempts
  };
};

// Static method to update all CTF statuses
ctfSchema.statics.updateAllStatuses = async function() {
  const ctfs = await this.find();
  let updated = 0;
  
  for (const ctf of ctfs) {
    const newStatus = ctf.calculateStatus();
    if (ctf.status !== newStatus) {
      ctf.status = newStatus;
      await ctf.save();
      updated++;
    }
  }
  
  return { updated };
};

// Pre-save middleware to auto-calculate status
ctfSchema.pre('save', function(next) {
  // Only auto-calculate if not manually set to inactive
  if (this.isVisible) {
    this.status = this.calculateStatus();
  }
  next();
});

// Indexes for better performance
ctfSchema.index({ 'schedule.startDate': 1, 'schedule.endDate': 1 });
ctfSchema.index({ status: 1 });
ctfSchema.index({ isVisible: 1, isPublished: 1 });
ctfSchema.index({ category: 1 });
ctfSchema.index({ difficulty: 1 });

module.exports = mongoose.model('CTF', ctfSchema);