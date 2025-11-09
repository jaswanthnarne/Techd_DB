const express = require("express");
const mongoose = require("mongoose");
const CTF = require("../models/CTF");
const Submission = require("../models/Submission");
const { requireAuth } = require("./authRoutes");
const { requireAdmin } = require("./adminRoutes");
const {
  uploadToCloudinary,
  deleteFromCloudinary,
} = require("../utils/cloudinary");
const multer = require("multer");

const { body, validationResult } = require("express-validator");

const router = express.Router();

// ==========================
// PUBLIC ROUTES
// ==========================

// Health check
router.get("/health", (req, res) => {
  res.json({
    message: "CTF service is running",
    timestamp: new Date().toISOString(),
  });
});

// Get all CTFs with filtering
router.get("/ctfs", async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      status = "all",
      category = "all",
      search = "",
    } = req.query;

    let filter = { isVisible: true ,isPublished:true};

    if (status !== "all") {
      filter.status = status;
    }

    if (category !== "all") {
      filter.category = category;
    }

    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ];
    }

    const ctfs = await CTF.find(filter).populate("participants")
      .populate("createdBy", "fullName email")
      .select("-flag -participants")
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await CTF.countDocuments(filter);

     // ✅ Update status for each CTF
    const updatedCTFs = await Promise.all(
      ctfs.map(async (ctf) => {
        const newStatus = ctf.calculateStatus();
        if (ctf.status !== newStatus) {
          ctf.status = newStatus;
          await ctf.save();
        }
        return ctf;
      })
    );

    // Get unique categories for filter
    const categories = await CTF.distinct("category", { isVisible: true });

    res.json({
      ctfs: updatedCTFs,
      categories,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Get CTFs error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get single CTF
router.get("/ctfs/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid CTF ID format" });
    }

    const ctf = await CTF.findById(id)
      .populate("createdBy", "fullName email")
      .select("-flag");

    if (!ctf) {
      return res.status(404).json({ error: "CTF not found" });
    }

    if (!ctf.isVisible) {
      return res.status(403).json({ error: "CTF is not visible" });
    }

    // Calculate current status
    const currentStatus = ctf.calculateStatus();
    const isCurrentlyActive = ctf.isCurrentlyActive();

    res.json({
      ctf: {
        ...ctf.toObject(),
        currentStatus,
        isCurrentlyActive,
        canSubmit: ctf.canSubmit(),
      },
    });
  } catch (error) {
    console.error("Get CTF error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get global leaderboard
router.get("/leaderboard/global", async (req, res) => {
  try {
    const { limit = 100 } = req.query;

    const leaderboard = await Submission.aggregate([
      {
        $match: {
          isCorrect: true,
        },
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
      {
        $limit: parseInt(limit),
      },
    ]);

    res.json({ leaderboard });
  } catch (error) {
    console.error("Get global leaderboard error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ==========================
// PROTECTED ROUTES (Require Auth)
// ==========================

// After Changes Deploying 
// Join CTF - Add proper status validation
router.post("/ctfs/:id/join", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    console.log('🔍 JOIN CTF - User attempting to join:', {
      ctfId: id,
      userId: userId,
      userRole: req.user.role
    });

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid CTF ID format" });
    }

    const ctf = await CTF.findById(id);
    if (!ctf) {
      return res.status(404).json({ error: "CTF not found" });
    }

    // Enhanced validation for joining
    if (!ctf.isVisible || !ctf.isPublished) {
      return res
        .status(403)
        .json({ error: "CTF is not available for joining" });
    }

    // ✅ Use the new calculateStatus method
    const currentStatus = ctf.calculateStatus();
    
    console.log('📋 CTF Status Check:', {
      title: ctf.title,
      currentStatus: currentStatus,
      isCurrentlyActive: ctf.isCurrentlyActive(),
      schedule: ctf.schedule,
      activeHours: ctf.activeHours
    });

    // Only allow joining if CTF is active or upcoming
    if (currentStatus === 'ended') {
      return res.status(403).json({
        error: "CTF has ended. Joining is no longer allowed.",
      });
    }

    if (currentStatus === 'inactive') {
      return res.status(403).json({
        error: "CTF is currently inactive. Please check the active hours.",
      });
    }

    // Check if already joined
    const alreadyJoined = ctf.participants.some(
      (participant) => participant.user.toString() === userId.toString()
    );

    if (alreadyJoined) {
      return res.status(400).json({ error: "Already joined this CTF" });
    }

    // Add participant
    ctf.addParticipant(userId);
    await ctf.save();

    res.json({
      message: "Successfully joined CTF",
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        status: currentStatus,
        isCurrentlyActive: ctf.isCurrentlyActive(),
      },
    });
  } catch (error) {
    console.error("Join CTF error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Submit flag for CTF
router.post(
  "/ctfs/:id/submit",
  requireAuth,
  [body("flag").notEmpty().withMessage("Flag is required")],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: "Validation failed",
          details: errors.array(),
        });
      }

      const { id } = req.params;
      const { flag, screenshot } = req.body;
      const userId = req.user._id;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ error: "Invalid CTF ID format" });
      }

      const ctf = await CTF.findById(id);
      if (!ctf) {
        return res.status(404).json({ error: "CTF not found" });
      }

      if (!ctf.isVisible) {
        return res.status(403).json({ error: "CTF is not available" });
      }

      // Check if user has joined the CTF
      const hasJoined = ctf.participants.some(
        (p) => p.user.toString() === userId.toString()
      );

      if (!hasJoined) {
        return res
          .status(400)
          .json({ error: "You must join the CTF before submitting" });
      }

      try {
        // Submit flag using CTF method
        const result = ctf.submitFlag(userId, flag, screenshot);

        // Create submission record
        const submission = new Submission({
          user: userId,
          ctf: id,
          flag,
          isCorrect: result.isCorrect,
          points: result.points,
          screenshot: screenshot || null,
          ipAddress:
            req.headers["x-forwarded-for"] || req.connection.remoteAddress,
          userAgent: req.headers["user-agent"],
          attemptNumber: result.attempts,
        });

        await submission.save();
        await ctf.save();

        if (result.isCorrect) {
          return res.json({
            message: "Correct flag! CTF solved.",
            points: result.points,
            solved: true,
            submissionId: submission._id,
            attempts: result.attempts,
          });
        } else {
          return res.status(400).json({
            error: "Incorrect flag",
            solved: false,
            attempts: result.attempts,
            maxAttempts: result.maxAttempts,
          });
        }
      } catch (submitError) {
        return res.status(400).json({
          error: submitError.message,
        });
      }
    } catch (error) {
      console.error("Submit flag error:", error);
      res.status(500).json({ error: "Server error" });
    }
  }
);

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
    const { page = 1, limit = 20 } = req.query;

    const submissions = await Submission.find({ user: req.user._id })
      .populate("ctf", "title category points")
      .sort({ submittedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select("-ipAddress -userAgent");

    const total = await Submission.countDocuments({ user: req.user._id });

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

// Check if user has joined CTF
router.get("/ctfs/:id/joined", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid CTF ID format" });
    }

    const ctf = await CTF.findById(id);
    if (!ctf) {
      return res.status(404).json({ error: "CTF not found" });
    }

    const hasJoined = ctf.participants.some(
      (participant) => participant.user.toString() === userId.toString()
    );

    res.json({
      joined: hasJoined,
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        status: ctf.status,
        isCurrentlyActive: ctf.isCurrentlyActive(),
      },
    });
  } catch (error) {
    console.error("Check CTF join status error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get CTF leaderboard
router.get("/ctfs/:id/leaderboard", async (req, res) => {
  try {
    const { id } = req.params;
    const { limit = 50 } = req.query;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid CTF ID format" });
    }

    const leaderboard = await Submission.aggregate([
      {
        $match: {
          ctf: new mongoose.Types.ObjectId(id),
          isCorrect: true,
        },
      },
      {
        $group: {
          _id: "$user",
          points: { $max: "$points" },
          submittedAt: { $min: "$submittedAt" },
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
          points: -1,
          submittedAt: 1,
        },
      },
      {
        $limit: parseInt(limit),
      },
    ]);

    res.json({ leaderboard });
  } catch (error) {
    console.error("Get CTF leaderboard error:", error);
    res.status(500).json({ error: "Server error" });
  }
});
// Configure multer for memory storage
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 4 * 1024 * 1024, // 4MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed!"), false);
    }
  },
});

// ==========================
// SCREENSHOT SUBMISSION ROUTES
// ==========================

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
      .sort({ submittedAt: -1 }); // Get the latest submission

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
    console.error("Get user submission error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Submit flag with screenshot
// In ctfRoutes.js - Update the submit-with-screenshot route
router.post(
  "/ctfs/:id/submit-with-screenshot",
  requireAuth,
  upload.single("screenshot"),
  [
    body("flag")
      .notEmpty()
      .withMessage("Flag is required")
      .isLength({ min: 3 })
      .withMessage("Flag must be at least 3 characters"),
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

      const { id } = req.params;
      const { flag } = req.body;
      const userId = req.user._id;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ error: "Invalid CTF ID format" });
      }

      // Check if screenshot is provided
      if (!req.file) {
        return res.status(400).json({ error: "Screenshot is required" });
      }

      // Validate file type and size
      if (!req.file.mimetype.startsWith("image/")) {
        return res.status(400).json({ error: "Only image files are allowed" });
      }

      if (req.file.size > 4 * 1024 * 1024) {
        return res
          .status(400)
          .json({ error: "File size must be less than 4MB" });
      }
      const ctf = await CTF.findById(id);
      if (!ctf) {
        return res.status(404).json({ error: "CTF not found" });
      }

      // Enhanced validation with detailed logging
      console.log("🔍 Backend Submission Validation:", {
        isVisible: ctf.isVisible,
        isPublished: ctf.isPublished,
        backendStatus: ctf.status,
        canSubmit: ctf.canSubmit(),
        isCurrentlyActive: ctf.isCurrentlyActive(),
        activeHours: ctf.activeHours,
        currentTime: new Date().toLocaleTimeString(),
      });

      // If CTF is not visible or not published, cannot submit
      if (!ctf.isVisible || !ctf.isPublished) {
        return res.status(400).json({
          error: "CTF is not available for submissions",
          details: {
            isVisible: ctf.isVisible,
            isPublished: ctf.isPublished,
          },
        });
      }

      // If backend status is not active, cannot submit
      if (ctf.status?.toLowerCase() !== "active") {
        return res.status(400).json({
          error: `CTF is ${ctf.status}. Submissions are not allowed.`,
          details: {
            backendStatus: ctf.status,
            requiredStatus: "active",
          },
        });
      }

      // If backend status is active, check if within active hours using CTF method
      if (!ctf.isCurrentlyActive()) {
        return res.status(400).json({
          error: `CTF is only active between ${ctf.activeHours.startTime} - ${
            ctf.activeHours.endTime
          }. Current time: ${new Date().toLocaleTimeString()}`,
          details: {
            activeHours: ctf.activeHours,
            currentTime: new Date().toLocaleTimeString(),
          },
        });
      }

      // Check if user has joined the CTF
      const hasJoined = ctf.participants.some(
        (p) => p.user.toString() === userId.toString()
      );

      if (!hasJoined) {
        return res
          .status(400)
          .json({ error: "You must join the CTF before submitting" });
      }

      // ✅ FIX: Check for existing submissions - allow resubmission if previous was rejected
      const existingSubmission = await Submission.findOne({
        user: userId,
        ctf: id,
      }).sort({ submittedAt: -1 });

      if (existingSubmission) {
        // Allow resubmission only if previous submission was rejected
        if (existingSubmission.submissionStatus === "pending") {
          return res.status(400).json({
            error:
              "You already have a pending submission for this CTF. Please wait for admin review or edit your existing submission.",
          });
        }

        // ✅ ALLOW resubmission if previous was rejected and CTF is still active
        if (existingSubmission.submissionStatus === "rejected") {
          console.log("🔄 Allowing resubmission for rejected submission");
          // Continue with submission creation
        }

        // Block if already approved
        if (existingSubmission.submissionStatus === "approved") {
          return res.status(400).json({
            error:
              "You have already successfully completed this CTF. No further submissions allowed.",
          });
        }
      }

      try {
        // Upload screenshot to Cloudinary
        const uploadResult = await uploadToCloudinary(
          req.file.buffer,
          `ctf-${id}`
        );

        // Submit flag using CTF method
        const result = ctf.submitFlag(userId, flag);

        // Create submission record with screenshot
        const submission = new Submission({
          user: userId,
          ctf: id,
          flag,
          isCorrect: false, // Always false initially for screenshot submissions
          points: 0, // No points until approved
          screenshot: {
            public_id: uploadResult.public_id,
            url: uploadResult.secure_url,
            filename: req.file.originalname,
            size: req.file.size,
          },
          submissionStatus: "pending", // Always starts as pending for screenshot submissions
          ipAddress:
            req.headers["x-forwarded-for"] || req.connection.remoteAddress,
          userAgent: req.headers["user-agent"],
          attemptNumber: result.attempts,
        });

        await submission.save();

        // Update CTF participant to mark as having pending submission
        ctf.updateParticipantSubmissionStatus(userId, true);
        await ctf.save();

        console.log("✅ Submission created successfully:", submission._id);
        res.json({
          message:
            "Submission received! Your screenshot is pending admin review.",
          submissionId: submission._id,
          submissionStatus: "pending",
          attempts: result.attempts,
        });
      } catch (submitError) {
        console.error("Submit flag error:", submitError);
        return res.status(400).json({
          error: submitError.message,
        });
      }
    } catch (error) {
      console.error("Submit with screenshot error:", error);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Edit submission (replace screenshot)
router.put(
  "/submissions/:submissionId/screenshot",
  requireAuth,
  upload.single("screenshot"),
  [
    body("flag")
      .notEmpty()
      .withMessage("Flag is required")
      .isLength({ min: 3 })
      .withMessage("Flag must be at least 3 characters"),
  ],
  async (req, res) => {
    try {
      const { submissionId } = req.params;
      const userId = req.user._id;
      const { flag } = req.body;

      if (!mongoose.Types.ObjectId.isValid(submissionId)) {
        return res.status(400).json({ error: "Invalid submission ID format" });
      }

      if (!req.file) {
        return res.status(400).json({ error: "New screenshot is required" });
      }

      if (!req.file.mimetype.startsWith("image/")) {
        return res.status(400).json({ error: "Only image files are allowed" });
      }

      if (req.file.size > 4 * 1024 * 1024) {
        return res
          .status(400)
          .json({ error: "File size must be less than 4MB" });
      }

      const submission = await Submission.findById(submissionId).populate(
        "ctf"
      );

      if (!submission) {
        return res.status(404).json({ error: "Submission not found" });
      }

      // Check if user owns the submission
      if (submission.user.toString() !== userId.toString()) {
        return res.status(403).json({ error: "Access denied" });
      }

      // Check if submission is still pending
      if (submission.submissionStatus !== "pending") {
        return res.status(400).json({
          error: "Cannot edit submission that has already been reviewed",
        });
      }

      // Only check if CTF is still visible/published
      if (!submission.ctf.isVisible || !submission.ctf.isPublished) {
        return res.status(400).json({
          error: "CTF is no longer available",
        });
      }

      // Delete old screenshot from Cloudinary
      if (submission.screenshot && submission.screenshot.public_id) {
        try {
          await deleteFromCloudinary(submission.screenshot.public_id);
        } catch (deleteError) {
          console.error("Error deleting old screenshot:", deleteError);
          // Continue with upload even if delete fails
        }
      }

      // Upload new screenshot to Cloudinary
      const uploadResult = await uploadToCloudinary(
        req.file.buffer,
        `ctf-${submission.ctf._id}`
      );

      // Update submission with new screenshot
      submission.screenshot = {
        public_id: uploadResult.public_id,
        url: uploadResult.secure_url,
        filename: req.file.originalname,
        size: req.file.size,
        uploadedAt: new Date(),
      };

      submission.flag = flag.trim(); // Update the flag
      submission.submittedAt = new Date(); // Update submission time
      // submission.attemptNumber = (submission.attemptNumber || 0) + 1; // Increment attempt number

      submission.submittedAt = new Date(); // Update submission time
      await submission.save();

      res.json({
        message: "Screenshot updated successfully!",
        submission: {
          _id: submission._id,
          submissionStatus: submission.submissionStatus,
          screenshot: submission.screenshot,
          flag: submission.flag,
          // attemptNumber: submission.attemptNumber,
        },
      });
    } catch (error) {
      console.error("Edit submission screenshot error:", error);
      res.status(500).json({ error: "Server error" });
    }
  }
);


// Get all CTFs with user's submissions and screenshots
router.get("/my-ctfs-with-submissions", requireAuth, async (req, res) => {
  try {
    const userId = req.user._id;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20)); // Add upper limit

    // Get all CTFs the user has participated in
    const ctfs = await CTF.find({
      "participants.user": userId,
      isVisible: true,
    })
      .populate("createdBy", "fullName email")
      .select("-flag")
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip((page - 1) * limit)
      .lean(); // Use lean() for better performance

    // Get CTF IDs for submissions query
    const ctfIds = ctfs.map((ctf) => ctf._id);
    
    // Only query submissions if we have CTFs
    let submissions = [];
    if (ctfIds.length > 0) {
      submissions = await Submission.find({
        user: userId,
        ctf: { $in: ctfIds },
      })
        .populate("ctf", "title category points")
        .sort({ submittedAt: -1 })
        .lean();
    }

    // Group submissions by CTF
    const submissionsByCTF = {};
    submissions.forEach((submission) => {
      const ctfId = submission.ctf._id.toString();
      if (!submissionsByCTF[ctfId]) {
        submissionsByCTF[ctfId] = [];
      }
      submissionsByCTF[ctfId].push(submission);
    });

    // Enhance CTFs with submission data
    const ctfsWithSubmissions = ctfs.map((ctf) => {
      const ctfId = ctf._id.toString();
      const ctfSubmissions = submissionsByCTF[ctfId] || [];
      
      return {
        ...ctf,
        submissions: ctfSubmissions,
        hasScreenshots: ctfSubmissions.some((sub) => sub.screenshot && sub.screenshot !== ''),
        latestSubmission: ctfSubmissions[0] || null,
      };
    });

    const total = await CTF.countDocuments({
      "participants.user": userId,
      isVisible: true,
    });

    res.json({
      ctfs: ctfsWithSubmissions,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Get CTFs with submissions error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get all submissions with screenshots for a user
router.get("/my-screenshots", requireAuth, async (req, res) => {
  try {
    const userId = req.user._id;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
    const { ctfId } = req.query;

    let filter = {
      user: userId,
      screenshot: { $exists: true, $ne: null, $ne: '' }, // Check for non-empty strings
    };

    if (ctfId && mongoose.Types.ObjectId.isValid(ctfId)) {
      filter.ctf = ctfId;
    }

    const submissions = await Submission.find(filter)
      .populate("ctf", "title category points")
      .populate("reviewedBy", "fullName email")
      .sort({ submittedAt: -1 })
      .limit(limit)
      .skip((page - 1) * limit)
      .select("-ipAddress -userAgent")
      .lean();

    const total = await Submission.countDocuments(filter);

    res.json({
      submissions,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Get screenshots error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get submission screenshot details
router.get(
  "/submissions/:submissionId/screenshot",
  requireAuth,
  async (req, res) => {
    try {
      const { submissionId } = req.params;
      const userId = req.user._id;

      if (!mongoose.Types.ObjectId.isValid(submissionId)) {
        return res.status(400).json({ error: "Invalid submission ID format" });
      }

      const submission = await Submission.findOne({
        _id: submissionId,
        user: userId,
      })
        .populate("ctf", "title category points")
        .select("ctf screenshot submissionStatus submittedAt reviewedAt adminFeedback points isCorrect");

      if (!submission) {
        return res.status(404).json({ error: "Submission not found" });
      }

      if (!submission.screenshot || submission.screenshot === '') {
        return res
          .status(404)
          .json({ error: "No screenshot found for this submission" });
      }

      res.json({
        submission: {
          _id: submission._id,
          ctf: submission.ctf,
          screenshot: submission.screenshot,
          submissionStatus: submission.submissionStatus,
          submittedAt: submission.submittedAt,
          reviewedAt: submission.reviewedAt,
          adminFeedback: submission.adminFeedback,
          points: submission.points,
          isCorrect: submission.isCorrect,
        },
      });
    } catch (error) {
      console.error("Get submission screenshot error:", error);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Get all CTFs with user's progress and submission status
router.get("/my-progress", requireAuth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status = "all" } = req.query;

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
      "participants.user": userId,
      isVisible: true,
      ...timeFilter,
    })
      .populate("createdBy", "fullName email")
      .select("-flag")
      .sort({ "schedule.startDate": 1 })
      .lean();

    // Get CTF IDs for submissions query
    const ctfIds = ctfs.map((ctf) => ctf._id);
    
    // Only query submissions if we have CTFs
    let submissions = [];
    if (ctfIds.length > 0) {
      submissions = await Submission.find({
        user: userId,
        ctf: { $in: ctfIds },
      })
        .populate("ctf", "title category points")
        .sort({ submittedAt: -1 })
        .lean();
    }

    // Group submissions by CTF
    const submissionsByCTF = {};
    submissions.forEach((submission) => {
      const ctfId = submission.ctf._id.toString();
      if (!submissionsByCTF[ctfId]) {
        submissionsByCTF[ctfId] = [];
      }
      submissionsByCTF[ctfId].push(submission);
    });

    // Calculate progress for each CTF
    const progressData = ctfs.map((ctf) => {
      const ctfId = ctf._id.toString();
      const ctfSubmissions = submissionsByCTF[ctfId] || [];
      const latestSubmission = ctfSubmissions[0] || null;
      const hasApproved = ctfSubmissions.some(
        (sub) => sub.submissionStatus === "approved"
      );
      const hasPending = ctfSubmissions.some(
        (sub) => sub.submissionStatus === "pending"
      );
      const hasScreenshots = ctfSubmissions.some((sub) => sub.screenshot && sub.screenshot !== '');

      // Find approved submission for points
      const approvedSubmission = ctfSubmissions.find(
        (sub) => sub.submissionStatus === "approved"
      );

      return {
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
          ctfLink: ctf.ctfLink,
          isCurrentlyActive: ctf.isCurrentlyActive ? ctf.isCurrentlyActive() : false,
          createdBy: ctf.createdBy,
        },
        progress: {
          totalSubmissions: ctfSubmissions.length,
          hasApproved,
          hasPending,
          hasScreenshots,
          latestSubmission,
          allSubmissions: ctfSubmissions,
          pointsEarned: approvedSubmission?.points || 0,
          isSolved: hasApproved,
        },
      };
    });

    res.json({
      progress: progressData,
      stats: {
        totalCTFs: progressData.length,
        solvedCTFs: progressData.filter((p) => p.progress.hasApproved).length,
        pendingCTFs: progressData.filter(
          (p) => p.progress.hasPending && !p.progress.hasApproved
        ).length,
        totalSubmissions: submissions.length,
        ctfsWithScreenshots: progressData.filter(
          (p) => p.progress.hasScreenshots
        ).length,
      },
    });
  } catch (error) {
    console.error("Get progress error:", error);
    res.status(500).json({ error: "Server error" });
  }
});
module.exports = router;
