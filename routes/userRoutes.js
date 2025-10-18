// const express = require('express');
// const mongoose = require('mongoose');
// const User = require('../models/User');
// const CTF = require('../models/CTF');
// const Submission = require('../models/Submission');
// const { requireAuth } = require('./authRoutes');
// const { body, validationResult } = require('express-validator');

// const router = express.Router();

// // ==========================
// // USER PROFILE ROUTES
// // ==========================

// // Get user profile
// router.get('/profile', requireAuth, async (req, res) => {
//   try {
//     const user = await User.findById(req.user._id)
//       .select('-password -passwordResetToken -passwordResetExpires -loginHistory');

//     res.json({
//       message: 'Profile retrieved successfully',
//       user
//     });
//   } catch (error) {
//     console.error('Get profile error:', error);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// // Update user profile
// router.patch('/profile', requireAuth, [
//   body('email').optional().isEmail().withMessage('Please provide a valid email'),
//   body('contactNumber').optional().isMobilePhone().withMessage('Please provide a valid phone number'),
//   body('expertiseLevel').optional().isIn(['Beginner', 'Junior', 'Intermediate', 'Senior', 'Expert']).withMessage('Invalid expertise level')
// ], async (req, res) => {
//   try {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return res.status(400).json({
//         error: 'Validation failed',
//         details: errors.array()
//       });
//     }

//     const allowedUpdates = [
//       'fullName', 'contactNumber', 'specialization',
//       'expertiseLevel'
//     ];

//     const updates = {};
//     allowedUpdates.forEach(field => {
//       if (req.body[field] !== undefined) {
//         updates[field] = req.body[field];
//       }
//     });

//     // Handle email separately (needs uniqueness check)
//     if (req.body.email && req.body.email !== req.user.email) {
//       const existingUser = await User.findOne({ email: req.body.email });
//       if (existingUser) {
//         return res.status(400).json({ error: 'Email already taken' });
//       }
//       updates.email = req.body.email;
//     }

//     const user = await User.findByIdAndUpdate(
//       req.user._id,
//       { $set: updates },
//       { new: true, runValidators: true }
//     ).select('-password -passwordResetToken -passwordResetExpires -loginHistory');

//     res.json({
//       message: 'Profile updated successfully',
//       user
//     });
//   } catch (error) {
//     console.error('Update profile error:', error);
//     if (error.name === 'ValidationError') {
//       const errors = Object.values(error.errors).map(err => err.message);
//       return res.status(400).json({ error: 'Validation failed', details: errors });
//     }
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// // Get user dashboard data
// router.get('/dashboard', requireAuth, async (req, res) => {
//   try {
//     const userId = req.user._id;

//     // Get basic user info
//     const user = await User.findById(userId)
//       .select('fullName email role specialization expertiseLevel lastLogin');

//     // Get CTF participation stats
//     const ctfStats = await CTF.aggregate([
//       { $match: { 'participants.user': userId } },
//       {
//         $group: {
//           _id: null,
//           totalJoined: { $sum: 1 },
//           solvedCTFs: {
//             $sum: {
//               $cond: [
//                 {
//                   $gt: [
//                     {
//                       $size: {
//                         $filter: {
//                           input: '$participants',
//                           as: 'p',
//                           cond: {
//                             $and: [
//                               { $eq: ['$$p.user', userId] },
//                               { $eq: ['$$p.isCorrect', true] }
//                             ]
//                           }
//                         }
//                       }
//                     },
//                     0
//                   ]
//                 }, 1, 0
//               ]
//             }
//           }
//         }
//       }
//     ]);

//     // Get submission stats
//     const submissionStats = await Submission.aggregate([
//       { $match: { user: userId } },
//       {
//         $group: {
//           _id: null,
//           totalSubmissions: { $sum: 1 },
//           correctSubmissions: { $sum: { $cond: ['$isCorrect', 1, 0] } },
//           totalPoints: { $sum: '$points' }
//         }
//       }
//     ]);

//     // Get recent submissions
//     const recentSubmissions = await Submission.find({ user: userId })
//       .populate('ctf', 'title category points')
//       .sort({ submittedAt: -1 })
//       .limit(5)
//       .select('isCorrect points submittedAt ctf');

//     // Get active CTFs
//     const activeCTFs = await CTF.find({
//       'participants.user': userId,
//       status: 'active',
//       isVisible: true
//     })
//     .select('title description category points difficulty activeHours')
//     .limit(3);

//     const dashboardData = {
//       user,
//       stats: {
//         ctfs: ctfStats[0] || { totalJoined: 0, solvedCTFs: 0 },
//         submissions: submissionStats[0] || { totalSubmissions: 0, correctSubmissions: 0, totalPoints: 0 },
//         accuracy: submissionStats[0] ?
//           Math.round((submissionStats[0].correctSubmissions / submissionStats[0].totalSubmissions) * 100) : 0
//       },
//       recentActivity: recentSubmissions,
//       activeCTFs
//     };

//     res.json({
//       message: 'Dashboard data retrieved successfully',
//       ...dashboardData
//     });
//   } catch (error) {
//     console.error('Get dashboard error:', error);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// // ==========================
// // USER CTF ROUTES
// // ==========================

// // Get user's submission for a specific CTF
// router.get('/ctfs/:id/my-submission', requireAuth, async (req, res) => {
//   try {
//     const { id } = req.params;
//     const userId = req.user._id;

//     console.log('🔍 Fetching submission for CTF:', id, 'User:', userId);

//     if (!mongoose.Types.ObjectId.isValid(id)) {
//       return res.status(400).json({ error: 'Invalid CTF ID format' });
//     }

//     const submission = await Submission.findOne({
//       user: userId,
//       ctf: id
//     })
//     .populate('ctf', 'title category points activeHours schedule')
//     .populate('reviewedBy', 'fullName email')
//     .sort({ submittedAt: -1 });

//     if (!submission) {
//       return res.status(404).json({
//         error: 'No submission found for this CTF',
//         submission: null
//       });
//     }

//     console.log('✅ Submission found:', submission._id);
//     res.json({
//       message: 'Submission found',
//       submission
//     });
//   } catch (error) {
//     console.error('❌ Get user submission error:', error);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// // Get user's CTF progress
// router.get('/ctfs/:id/progress', requireAuth, async (req, res) => {
//   try {
//     const { id } = req.params;
//     const userId = req.user._id;

//     if (!mongoose.Types.ObjectId.isValid(id)) {
//       return res.status(400).json({ error: 'Invalid CTF ID format' });
//     }

//     const ctf = await CTF.findById(id)
//       .select('title description category points difficulty status activeHours schedule participants rules');

//     if (!ctf) {
//       return res.status(404).json({ error: 'CTF not found' });
//     }

//     // Find user's participation
//     const participation = ctf.participants.find(
//       p => p.user.toString() === userId.toString()
//     );

//     // Get user's submissions for this CTF
//     const submissions = await Submission.find({
//       user: userId,
//       ctf: id
//     }).sort({ submittedAt: -1 });

//     const progress = {
//       hasJoined: !!participation,
//       isSolved: participation ? participation.isCorrect : false,
//       pointsEarned: participation ? participation.pointsEarned : 0,
//       attempts: participation ? participation.attempts : 0,
//       maxAttempts: ctf.maxAttempts,
//       submittedAt: participation ? participation.submittedAt : null,
//       submissions: submissions,
//       canSubmit: ctf.canSubmit() && (!participation?.isCorrect || ctf.rules.allowMultipleSubmissions)
//     };

//     res.json({
//       ctf: {
//         _id: ctf._id,
//         title: ctf.title,
//         description: ctf.description,
//         category: ctf.category,
//         points: ctf.points,
//         difficulty: ctf.difficulty,
//         status: ctf.status,
//         activeHours: ctf.activeHours,
//         schedule: ctf.schedule,
//         isCurrentlyActive: ctf.isCurrentlyActive(),
//         rules: ctf.rules
//       },
//       progress
//     });
//   } catch (error) {
//     console.error('Get CTF progress error:', error);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// // Get user's submission history
// router.get('/my-submissions', requireAuth, async (req, res) => {
//   try {
//     const { page = 1, limit = 20, ctfId } = req.query;

//     let filter = { user: req.user._id };
//     if (ctfId) {
//       filter.ctf = ctfId;
//     }

//     const submissions = await Submission.find(filter)
//       .populate('ctf', 'title category points')
//       .sort({ submittedAt: -1 })
//       .limit(limit * 1)
//       .skip((page - 1) * limit)
//       .select('-ipAddress -userAgent');

//     const total = await Submission.countDocuments(filter);

//     res.json({
//       submissions,
//       pagination: {
//         page: parseInt(page),
//         limit: parseInt(limit),
//         total,
//         pages: Math.ceil(total / limit)
//       }
//     });
//   } catch (error) {
//     console.error('Get submissions error:', error);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// // ==========================
// // USER STATISTICS ROUTES
// // ==========================

// // Get user's statistics
// router.get('/stats', requireAuth, async (req, res) => {
//   try {
//     const userId = req.user._id;

//     // Total submissions and correct submissions
//     const submissionStats = await Submission.aggregate([
//       { $match: { user: userId } },
//       {
//         $group: {
//           _id: null,
//           totalSubmissions: { $sum: 1 },
//           correctSubmissions: {
//             $sum: { $cond: ['$isCorrect', 1, 0] }
//           },
//           totalPoints: { $sum: '$points' }
//         }
//       }
//     ]);

//     // CTFs participated in
//     const ctfStats = await CTF.aggregate([
//       { $match: { 'participants.user': userId } },
//       {
//         $group: {
//           _id: null,
//           totalCTFs: { $sum: 1 },
//           solvedCTFs: {
//             $sum: {
//               $cond: [
//                 {
//                   $gt: [
//                     {
//                       $size: {
//                         $filter: {
//                           input: '$participants',
//                           as: 'p',
//                           cond: {
//                             $and: [
//                               { $eq: ['$$p.user', userId] },
//                               { $eq: ['$$p.isCorrect', true] }
//                             ]
//                           }
//                         }
//                       }
//                     },
//                     0
//                   ]
//                 }, 1, 0
//               ]
//             }
//           }
//         }
//       }
//     ]);

//     // Category-wise performance
//     const categoryStats = await Submission.aggregate([
//       {
//         $match: {
//           user: userId,
//           isCorrect: true
//         }
//       },
//       {
//         $lookup: {
//           from: 'ctfs',
//           localField: 'ctf',
//           foreignField: '_id',
//           as: 'ctfInfo'
//         }
//       },
//       { $unwind: '$ctfInfo' },
//       {
//         $group: {
//           _id: '$ctfInfo.category',
//           totalSolved: { $sum: 1 },
//           totalPoints: { $sum: '$points' }
//         }
//       },
//       { $sort: { totalPoints: -1 } }
//     ]);

//     // Recent activity
//     const recentActivity = await Submission.find({ user: userId })
//       .populate('ctf', 'title category')
//       .sort({ submittedAt: -1 })
//       .limit(10)
//       .select('isCorrect points submittedAt ctf');

//     const stats = {
//       submissions: submissionStats[0] || {
//         totalSubmissions: 0,
//         correctSubmissions: 0,
//         totalPoints: 0
//       },
//       ctfs: ctfStats[0] || { totalCTFs: 0, solvedCTFs: 0 },
//       categories: categoryStats,
//       recentActivity,
//       accuracy: submissionStats[0] ?
//         Math.round((submissionStats[0].correctSubmissions / submissionStats[0].totalSubmissions) * 100) : 0
//     };

//     res.json({ stats });
//   } catch (error) {
//     console.error('Get user stats error:', error);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// // Get user ranking
// router.get('/ranking', requireAuth, async (req, res) => {
//   try {
//     const userId = req.user._id;

//     // Get global ranking
//     const globalRanking = await Submission.aggregate([
//       {
//         $match: { isCorrect: true }
//       },
//       {
//         $group: {
//           _id: '$user',
//           totalPoints: { $sum: '$points' },
//           solveCount: { $sum: 1 },
//           lastSolve: { $max: '$submittedAt' }
//         }
//       },
//       {
//         $lookup: {
//           from: 'users',
//           localField: '_id',
//           foreignField: '_id',
//           as: 'user'
//         }
//       },
//       {
//         $unwind: '$user'
//       },
//       {
//         $project: {
//           'user.password': 0,
//           'user.loginHistory': 0,
//           'user.passwordResetToken': 0,
//           'user.passwordResetExpires': 0
//         }
//       },
//       {
//         $sort: {
//           totalPoints: -1,
//           lastSolve: 1
//         }
//       }
//     ]);

//     // Find user's position
//     const userRank = globalRanking.findIndex(rank =>
//       rank._id.toString() === userId.toString()
//     );

//     const userRanking = userRank !== -1 ? {
//       position: userRank + 1,
//       totalPoints: globalRanking[userRank].totalPoints,
//       solveCount: globalRanking[userRank].solveCount,
//       totalParticipants: globalRanking.length
//     } : {
//       position: globalRanking.length + 1,
//       totalPoints: 0,
//       solveCount: 0,
//       totalParticipants: globalRanking.length
//     };

//     // Get top 10 users
//     const topUsers = globalRanking.slice(0, 10);

//     res.json({
//       userRanking,
//       topUsers
//     });
//   } catch (error) {
//     console.error('Get user ranking error:', error);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// module.exports = router;

const express = require("express");
const mongoose = require("mongoose");
const User = require("../models/User");
const CTF = require("../models/CTF");
const Submission = require("../models/Submission");
const { requireAuth } = require("./authRoutes");
const { body, validationResult } = require("express-validator");

const router = express.Router();

// ==========================
// USER PROFILE ROUTES
// ==========================

// Get user profile
router.get("/profile", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select(
      "-password -passwordResetToken -passwordResetExpires -loginHistory"
    );

    res.json({
      message: "Profile retrieved successfully",
      user,
    });
  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Update user profile
router.patch(
  "/profile",
  requireAuth,
  [
    body("email")
      .optional()
      .isEmail()
      .withMessage("Please provide a valid email"),
    body("contactNumber")
      .optional()
      .isMobilePhone()
      .withMessage("Please provide a valid phone number"),
    body("expertiseLevel")
      .optional()
      .isIn(["Beginner", "Junior", "Intermediate", "Senior", "Expert"])
      .withMessage("Invalid expertise level"),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: "Validation failed",
          details: errors.array(),
        });
      }

      const allowedUpdates = [
        "fullName",
        "contactNumber",
        "specialization",
        "expertiseLevel",
      ];

      const updates = {};
      allowedUpdates.forEach((field) => {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      });

      // Handle email separately (needs uniqueness check)
      if (req.body.email && req.body.email !== req.user.email) {
        const existingUser = await User.findOne({ email: req.body.email });
        if (existingUser) {
          return res.status(400).json({ error: "Email already taken" });
        }
        updates.email = req.body.email;
      }

      const user = await User.findByIdAndUpdate(
        req.user._id,
        { $set: updates },
        { new: true, runValidators: true }
      ).select(
        "-password -passwordResetToken -passwordResetExpires -loginHistory"
      );

      res.json({
        message: "Profile updated successfully",
        user,
      });
    } catch (error) {
      console.error("Update profile error:", error);
      if (error.name === "ValidationError") {
        const errors = Object.values(error.errors).map((err) => err.message);
        return res
          .status(400)
          .json({ error: "Validation failed", details: errors });
      }
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Get user dashboard data
router.get("/dashboard", requireAuth, async (req, res) => {
  try {
    const userId = req.user._id;

    // Get basic user info
    const user = await User.findById(userId).select(
      "fullName email role specialization expertiseLevel lastLogin"
    );

    // Get CTF participation stats
    const ctfStats = await CTF.aggregate([
      { $match: { "participants.user": userId } },
      {
        $group: {
          _id: null,
          totalJoined: { $sum: 1 },
          solvedCTFs: {
            $sum: {
              $cond: [
                {
                  $gt: [
                    {
                      $size: {
                        $filter: {
                          input: "$participants",
                          as: "p",
                          cond: {
                            $and: [
                              { $eq: ["$$p.user", userId] },
                              { $eq: ["$$p.isCorrect", true] },
                            ],
                          },
                        },
                      },
                    },
                    0,
                  ],
                },
                1,
                0,
              ],
            },
          },
        },
      },
    ]);

    // Get submission stats
    const submissionStats = await Submission.aggregate([
      { $match: { user: userId } },
      {
        $group: {
          _id: null,
          totalSubmissions: { $sum: 1 },
          correctSubmissions: { $sum: { $cond: ["$isCorrect", 1, 0] } },
          totalPoints: { $sum: "$points" },
        },
      },
    ]);

    // Get recent submissions
    const recentSubmissions = await Submission.find({ user: userId })
      .populate("ctf", "title category points")
      .sort({ submittedAt: -1 })
      .limit(5)
      .select("isCorrect points submittedAt ctf");

    // Get active CTFs
    const activeCTFs = await CTF.find({
      "participants.user": userId,
      status: "active",
      isVisible: true,
    })
      .select("title description category points difficulty activeHours")
      .limit(3);

    const dashboardData = {
      user,
      stats: {
        ctfs: ctfStats[0] || { totalJoined: 0, solvedCTFs: 0 },
        submissions: submissionStats[0] || {
          totalSubmissions: 0,
          correctSubmissions: 0,
          totalPoints: 0,
        },
        accuracy: submissionStats[0]
          ? Math.round(
              (submissionStats[0].correctSubmissions /
                submissionStats[0].totalSubmissions) *
                100
            )
          : 0,
      },
      recentActivity: recentSubmissions,
      activeCTFs,
    };

    res.json({
      message: "Dashboard data retrieved successfully",
      ...dashboardData,
    });
  } catch (error) {
    console.error("Get dashboard error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ==========================
// USER CTF ROUTES
// ==========================

// Get user's joined CTFs
router.get("/ctfs/joined", requireAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status = "all" } = req.query;

    let timeFilter = {};
    const now = new Date();

    if (status === "active") {
      timeFilter = {
        "schedule.startDate": { $lte: now },
        "schedule.endDate": { $gte: now },
      };
    } else if (status === "upcoming") {
      timeFilter = { "schedule.startDate": { $gt: now } };
    } else if (status === "past") {
      timeFilter = { "schedule.endDate": { $lt: now } };
    }

    const ctfs = await CTF.find({
      "participants.user": req.user._id,
      isVisible: true,
      ...timeFilter,
    })
      .populate("createdBy", "fullName email")
      .select("-flag")
      .sort({ "schedule.startDate": 1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await CTF.countDocuments({
      "participants.user": req.user._id,
      isVisible: true,
      ...timeFilter,
    });

    res.json({
      ctfs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Get joined CTFs error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get user's submission for a specific CTF
router.get("/ctfs/:id/my-submission", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    console.log("🔍 Fetching submission for CTF:", id, "User:", userId);

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid CTF ID format" });
    }

    const submission = await Submission.findOne({
      user: userId,
      ctf: id,
    })
      .populate("ctf", "title category points activeHours schedule")
      .populate("reviewedBy", "fullName email")
      .sort({ submittedAt: -1 });

    if (!submission) {
      return res.status(404).json({
        error: "No submission found for this CTF",
        submission: null,
      });
    }

    console.log("✅ Submission found:", submission._id);
    res.json({
      message: "Submission found",
      submission,
    });
  } catch (error) {
    console.error("❌ Get user submission error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get user's CTF progress
router.get("/ctfs/:id/progress", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid CTF ID format" });
    }

    const ctf = await CTF.findById(id).select(
      "title description category points difficulty status activeHours schedule participants rules"
    );

    if (!ctf) {
      return res.status(404).json({ error: "CTF not found" });
    }

    // Find user's participation
    const participation = ctf.participants.find(
      (p) => p.user.toString() === userId.toString()
    );

    // Get user's submissions for this CTF
    const submissions = await Submission.find({
      user: userId,
      ctf: id,
    }).sort({ submittedAt: -1 });

    const progress = {
      hasJoined: !!participation,
      isSolved: participation ? participation.isCorrect : false,
      pointsEarned: participation ? participation.pointsEarned : 0,
      attempts: participation ? participation.attempts : 0,
      maxAttempts: ctf.maxAttempts,
      submittedAt: participation ? participation.submittedAt : null,
      submissions: submissions,
      canSubmit:
        ctf.canSubmit() &&
        (!participation?.isCorrect || ctf.rules.allowMultipleSubmissions),
    };

    res.json({
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        description: ctf.description,
        category: ctf.category,
        points: ctf.points,
        difficulty: ctf.difficulty,
        status: ctf.status,
        activeHours: ctf.activeHours,
        schedule: ctf.schedule,
        isCurrentlyActive: ctf.isCurrentlyActive(),
        rules: ctf.rules,
      },
      progress,
    });
  } catch (error) {
    console.error("Get CTF progress error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get user's submission history
router.get("/my-submissions", requireAuth, async (req, res) => {
  try {
    const { page = 1, limit = 20, ctfId } = req.query;

    let filter = { user: req.user._id };
    if (ctfId) {
      filter.ctf = ctfId;
    }

    const submissions = await Submission.find(filter)
      .populate("ctf", "title category points")
      .sort({ submittedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select("-ipAddress -userAgent");

    const total = await Submission.countDocuments(filter);

    res.json({
      submissions,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Get submissions error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ==========================
// USER STATISTICS ROUTES
// ==========================

// Get user's statistics
router.get("/stats", requireAuth, async (req, res) => {
  try {
    const userId = req.user._id;

    // Total submissions and correct submissions
    const submissionStats = await Submission.aggregate([
      { $match: { user: userId } },
      {
        $group: {
          _id: null,
          totalSubmissions: { $sum: 1 },
          correctSubmissions: {
            $sum: { $cond: ["$isCorrect", 1, 0] },
          },
          totalPoints: { $sum: "$points" },
        },
      },
    ]);

    // CTFs participated in
    const ctfStats = await CTF.aggregate([
      { $match: { "participants.user": userId } },
      {
        $group: {
          _id: null,
          totalCTFs: { $sum: 1 },
          solvedCTFs: {
            $sum: {
              $cond: [
                {
                  $gt: [
                    {
                      $size: {
                        $filter: {
                          input: "$participants",
                          as: "p",
                          cond: {
                            $and: [
                              { $eq: ["$$p.user", userId] },
                              { $eq: ["$$p.isCorrect", true] },
                            ],
                          },
                        },
                      },
                    },
                    0,
                  ],
                },
                1,
                0,
              ],
            },
          },
        },
      },
    ]);

    // Category-wise performance
    const categoryStats = await Submission.aggregate([
      {
        $match: {
          user: userId,
          isCorrect: true,
        },
      },
      {
        $lookup: {
          from: "ctfs",
          localField: "ctf",
          foreignField: "_id",
          as: "ctfInfo",
        },
      },
      { $unwind: "$ctfInfo" },
      {
        $group: {
          _id: "$ctfInfo.category",
          totalSolved: { $sum: 1 },
          totalPoints: { $sum: "$points" },
        },
      },
      { $sort: { totalPoints: -1 } },
    ]);

    // Recent activity
    const recentActivity = await Submission.find({ user: userId })
      .populate("ctf", "title category")
      .sort({ submittedAt: -1 })
      .limit(10)
      .select("isCorrect points submittedAt ctf");

    const stats = {
      submissions: submissionStats[0] || {
        totalSubmissions: 0,
        correctSubmissions: 0,
        totalPoints: 0,
      },
      ctfs: ctfStats[0] || { totalCTFs: 0, solvedCTFs: 0 },
      categories: categoryStats,
      recentActivity,
      accuracy: submissionStats[0]
        ? Math.round(
            (submissionStats[0].correctSubmissions /
              submissionStats[0].totalSubmissions) *
              100
          )
        : 0,
    };

    res.json({ stats });
  } catch (error) {
    console.error("Get user stats error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get user ranking
router.get("/ranking", requireAuth, async (req, res) => {
  try {
    const userId = req.user._id;

    // Get global ranking
    const globalRanking = await Submission.aggregate([
      {
        $match: { isCorrect: true },
      },
      {
        $group: {
          _id: "$user",
          totalPoints: { $sum: "$points" },
          solveCount: { $sum: 1 },
          lastSolve: { $max: "$submittedAt" },
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "user",
        },
      },
      {
        $unwind: "$user",
      },
      {
        $project: {
          "user.password": 0,
          "user.loginHistory": 0,
          "user.passwordResetToken": 0,
          "user.passwordResetExpires": 0,
        },
      },
      {
        $sort: {
          totalPoints: -1,
          lastSolve: 1,
        },
      },
    ]);

    // Find user's position
    const userRank = globalRanking.findIndex(
      (rank) => rank._id.toString() === userId.toString()
    );

    const userRanking =
      userRank !== -1
        ? {
            position: userRank + 1,
            totalPoints: globalRanking[userRank].totalPoints,
            solveCount: globalRanking[userRank].solveCount,
            totalParticipants: globalRanking.length,
          }
        : {
            position: globalRanking.length + 1,
            totalPoints: 0,
            solveCount: 0,
            totalParticipants: globalRanking.length,
          };

    // Get top 10 users
    const topUsers = globalRanking.slice(0, 10);

    res.json({
      userRanking,
      topUsers,
    });
  } catch (error) {
    console.error("Get user ranking error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
