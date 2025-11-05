const nodemailer = require("nodemailer");
require("dotenv").config();

const sendMail = async (options) => {
  try {
    // 1. Configure Transporter with your Gmail settings
    const transporter = nodemailer.createTransport({
      service: "gmail",
      host: process.env.EMAIL_HOST || "smtp.gmail.com",
      port: process.env.EMAIL_PORT || 587,
      secure: false, // Use TLS
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
      logger: process.env.NODE_ENV === 'development',
      debug: process.env.NODE_ENV === 'development',
    });

    // 2. Verify Connection
    if (process.env.NODE_ENV === 'development') {
      try {
        await transporter.verify();
        console.log("✅ SMTP connection verified - ready to send emails");
      } catch (error) {
        console.error("❌ SMTP Connection Failed:", error);
        throw new Error("SMTP connection failed");
      }
    }

    // 3. Define Email Options
    const mailOptions = {
      from: {
        name: "CTF TechD Admin",
        address: process.env.EMAIL_USER
      },
      to: options.email,
      subject: options.subject,
      html: options.message,
      // Add text version for email clients that don't support HTML
      text: options.text || options.message.replace(/<[^>]*>/g, '')
    };

    // 4. Send Email
    const info = await transporter.sendMail(mailOptions);
    
    if (process.env.NODE_ENV === 'development') {
      console.log("✅ Email sent successfully:", {
        messageId: info.messageId,
        to: options.email,
        subject: options.subject
      });
    }
    
    return info;
  } catch (error) {
    console.error("❌ Email send error:", {
      error: error.message,
      to: options.email,
      subject: options.subject
    });
    
    // Throw specific error messages for common issues
    if (error.code === 'EAUTH') {
      throw new Error("Email authentication failed. Please check email credentials.");
    } else if (error.code === 'EENVELOPE') {
      throw new Error("Invalid email address or recipient.");
    } else if (error.code === 'ECONNECTION') {
      throw new Error("Unable to connect to email server.");
    } else {
      throw new Error("Failed to send email. Please try again later.");
    }
  }
};

module.exports = sendMail;