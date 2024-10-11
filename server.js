const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const port = 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// const upload = multer({ dest: "uploads/" });

// PostgreSQL pool setup
// const pool = new Pool({
//   host: "localhost",
//   user: "lindelwa",
//   password: "@76494594tzi!",
//   database: "rstp_hackathon",
//   port: 5432,
// });

const pool = new Pool({
  host: "pg-1020a1c4-rstpapplications-37e1.i.aivencloud.com", // Aiven hostname
  user: "avnadmin", // Aiven username
  password: "AVNS_iHPjzAKysOgmJvX6g6f", // Aiven password
  database: "defaultdb", // Aiven database name
  port: 18942, // Default PostgreSQL port
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync("./ca.pem").toString(), // Path to Aiven CA certificate
  },
});

// const pool = new Pool({
//   host: "pg-2c334ff-hkwezwe-854b.h.aivencloud.com",
//   user: "avnadmin",
//   password: "AVNS_X91lzsB2QtUsyCavEpb",
//   database: "defaultdb",
//   port: 15473,
// });

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Directory where files will be saved
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // File naming
  },
});

const upload = multer({ storage: storage });

// Setup email transporter (configure with your email provider)
const transporter = nodemailer.createTransport({
  // service: "mail.rstp.org.sz",
  host: "rstp.org.sz",
  port: 465,
  secure: true,
  auth: {
    user: "codeforcare@rstp.org.sz",
    pass: "Sanelisiwe09",
  },
});

// User registration endpoint
app.post("/userRegister", async (req, res) => {
  const { email, password } = req.body;

  console.log("Reaching here...............");

  try {
    // Check if user already exists
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "User already exists." });
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database with the hashed password
    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
      [email, hashedPassword]
    );

    console.log("Trying to send mail...");

    try {
      const mailResponse = await transporter.sendMail({
        from: "codeforcare@rstp.org.sz",
        to: email,
        subject: "Hackathon Registration",
        html: `
    <div style="font-family: Arial, sans-serif; color: #333;">
      <table style="width: 100%; background-color: #f5f5f5; padding: 20px;">
        <tr>
          <td align="center">
           <img src="https://firebasestorage.googleapis.com/v0/b/hackathon-7fce3.appspot.com/o/New%20Pepfar%20logo.png?alt=media&token=4564e2b8-fe4c-484e-b241-8a94d0a5af43" alt="Hackathon Logo" style="max-width: 150px; margin-bottom: 20px;  margin-right:30px">
            <img src="https://firebasestorage.googleapis.com/v0/b/hackathon-7fce3.appspot.com/o/CGHP_Social%20(1).jpg?alt=media&token=60b32285-c08d-4103-a328-df563d95215f" alt="Hackathon Logo" style="max-width: 150px; margin-bottom: 20px; margin-right:30px">
            <img src="https://firebasestorage.googleapis.com/v0/b/hackathon-7fce3.appspot.com/o/logo%20(1).png?alt=media&token=9b2558c3-97eb-4d02-be0c-da4f5d28a7cf" alt="Hackathon Logo" style="max-width: 80px; margin-bottom: 20px;">
          </td>
        </tr>
        <tr>
          <td>
            <div style="background-color: white; padding: 20px; border-radius: 10px;">
              <h2 style="color: #007bff; text-align: center;">Congratulations!</h2>
              <p style="font-size: 16px; line-height: 1.6;">
               Congratulations,
              </p>
              <p style="font-size: 16px; line-height: 1.6;">
                You have successfully registred on the Digital Care Hackahon.
              </p>
              <p style="font-size: 16px; line-height: 1.6;">
                Continue filling in the application form and be amongts the best tech innovators!
              </p>
              
              <p style="font-size: 16px; line-height: 1.6; text-align: center;">
                Good luck, and we look forward to seeing what you build!
              </p>
              <p style="font-size: 16px; line-height: 1.6; text-align: center;">
                Best regards, <br/>
                <strong>Code for Care Hackathon Team</strong>
              </p>
              <hr style="margin: 20px 0; border: none; border-top: 1px solid #eee;">
              <p style="font-size: 12px; color: #888; text-align: center;">
                If you have any questions, feel free to contact us at 
                <a href="mailto:codeforcare@rstp.org.sz" style="color: #007bff;">codeforcare@rstp.org.sz</a>.
              </p>
            </div>
          </td>
        </tr>
      </table>
    </div>
  `,
      });

      console.log("Email sent successfully:", mailResponse);

      res.status(201).json({
        message: "User registered successfully and email sent.",
        user: result.rows[0],
      });
    } catch (mailError) {
      console.error("Error sending email:", mailError);

      res.status(201).json({
        message: "User registered successfully but email not sent.",
        user: result.rows[0],
        emailError: mailError.message,
      });
    }
  } catch (error) {
    console.error("Error inserting data:", error);
    // Send a generic error message for security
    res.status(500).json({ error: "Database insertion error" });
  }
});

app.post("/sendResetLink", async (req, res) => {
  const { email } = req.body;

  try {
    // Check if the email exists
    const result = await pool.query("SELECT id FROM users WHERE email = $1", [
      email,
    ]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Email not registered" });
    }

    const userId = result.rows[0].id;
    const token = crypto.randomBytes(20).toString("hex");
    console.log("I reach here...", token, userId);
    // Store the token in the database with an expiration time
    await pool.query(
      "INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
      [userId, token]
    );

    // Send email with reset link
    const resetLink = `https://hackathon-7fce3.web.app/reset?token=${token}`;
    try {
      const mailResponse = await transporter.sendMail({
        from: "codeforcare@rstp.org.sz",
        to: email,
        subject: "Password Reset",
        html: `
    <div style="font-family: Arial, sans-serif; color: #333;">
      <table style="width: 100%; background-color: #f5f5f5; padding: 20px;">
        <tr>
          <td align="center">
           <img src="https://firebasestorage.googleapis.com/v0/b/hackathon-7fce3.appspot.com/o/New%20Pepfar%20logo.png?alt=media&token=4564e2b8-fe4c-484e-b241-8a94d0a5af43" alt="Hackathon Logo" style="max-width: 150px; margin-bottom: 20px;  margin-right:30px">
            <img src="https://firebasestorage.googleapis.com/v0/b/hackathon-7fce3.appspot.com/o/CGHP_Social%20(1).jpg?alt=media&token=60b32285-c08d-4103-a328-df563d95215f" alt="Hackathon Logo" style="max-width: 150px; margin-bottom: 20px; margin-right:30px">
            <img src="https://firebasestorage.googleapis.com/v0/b/hackathon-7fce3.appspot.com/o/logo%20(1).png?alt=media&token=9b2558c3-97eb-4d02-be0c-da4f5d28a7cf" alt="Hackathon Logo" style="max-width: 80px; margin-bottom: 20px;">
          </td>
        </tr>
        <tr>
          <td>
            <div style="background-color: white; padding: 20px; border-radius: 10px;">
              <h2 style="color: #007bff; text-align: center;">Password Reset</h2>
              <p style="font-size: 16px; line-height: 1.6;">
                Hello,
              </p>
              <p style="font-size: 16px; line-height: 1.6;">
                We received a request to reset your password for the Digital Care Hackathon account. If you didn't make this request, you can ignore this email.
              </p>
              <p style="font-size: 16px; line-height: 1.6;">
                To reset your password, please click the button below:
              </p>
              <p style="text-align: center;">
                <a href="${resetLink}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
              </p>
              <p style="font-size: 16px; line-height: 1.6;">
                This link will expire in 1 hour for security reasons. If you need to reset your password after that, please request a new reset link.
              </p>
              <p style="font-size: 16px; line-height: 1.6; text-align: center;">
                Best regards, <br/>
                <strong>Code for Care Hackathon Team</strong>
              </p>
              <hr style="margin: 20px 0; border: none; border-top: 1px solid #eee;">
              <p style="font-size: 12px; color: #888; text-align: center;">
                If you have any questions, feel free to contact us at 
                <a href="mailto:codeforcare@rstp.org.sz" style="color: #007bff;">codeforcare@rstp.org.sz</a>.
              </p>
            </div>
          </td>
        </tr>
      </table>
    </div>
  `,
      });

      console.log("Email sent successfully:", mailResponse);

      res.status(200).json({
        message: "Password reset link sent successfully.",
      });
    } catch (mailError) {
      console.error("Error sending email:", mailError);
      res.status(500).json({
        message: "Error sending password reset email.",
        emailError: mailError.message,
      });
    }
  } catch (error) {
    console.error("Error sending reset link:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// app.post("/userRegister", async (req, res) => {
//   const { email, password } = req.body;

//   console.log("Reaching here...............");

//   try {
//     // Check if user already exists
//     const existingUser = await pool.query(
//       "SELECT * FROM users WHERE email = $1",
//       [email]
//     );

//     if (existingUser.rows.length > 0) {
//       return res.status(400).json({ error: "User already exists." });
//     }

//     // Hash the password before storing it
//     const hashedPassword = await bcrypt.hash(password, 10);

//     // Insert the new user into the database with the hashed password
//     const result = await pool.query(
//       "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
//       [email, hashedPassword]
//     );

//     console.log("Trying to send mail");

//     await transporter.sendMail({
//       to: email,
//       subject: "Hackathon Application",
//       text: `Congratulations, we have successfully receiced your digital health application. Please stay tuned for updates!`,
//     });

//     console.log("sent mail");

//     // Successful registration response
//     res
//       .status(201)
//       .json({ message: "User registered successfully", user: result.rows[0] });
//   } catch (error) {
//     console.error("Error inserting data:", error);
//     // Send a generic error message for security
//     res.status(500).json({ error: "Database insertion error" });
//   }
// });

app.post("/userLogin", async (req, res) => {
  const { email, password } = req.body;
  console.log("FROM SERVER.....", email, password);

  try {
    // Query the user by username
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const user = result.rows[0];
    console.log("Stored hashed password:", user.password);

    // Compare the provided password with the stored hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    console.log("Password match result:", isMatch);

    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // If credentials are valid
    res.json({
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        phone: user.phone,
        address_type: user.address_type,
        address: user.address,
      },
    });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// app.post("/Application", async (req, res) => {
//   const {
//     teamName,
//     teamMembers,
//     experience,
//     tools,
//     previousHackathons,
//     previousSolutions,
//     howDidYouHear,
//     user,
//   } = req.body;

//   try {
//     const result = await pool.query(
//       "INSERT INTO applications (team_name, team_members, experience, tools, previous_hackathons, previous_solutions, how_did_you_hear, email) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
//       [
//         teamName,
//         JSON.stringify(teamMembers), // Make sure to stringify if necessary
//         experience,
//         tools,
//         previousHackathons,
//         previousSolutions,
//         howDidYouHear,
//         user,
//       ]
//     );

//     res.status(201).json(result.rows[0]); // Send back the created record
//   } catch (error) {
//     console.error("Error inserting data into applications table:", error);
//     res.status(500).json({ error: "Database insertion error" });
//   }
// });

app.post("/Application", async (req, res) => {
  const {
    teamName,
    teamMembers,
    experience,
    tools,
    previousHackathons,
    previousSolutions,
    howDidYouHear,
    user, // Assuming this is the email of the user
  } = req.body;

  try {
    // First, check if an application has already been submitted by this user
    const existingApplication = await pool.query(
      "SELECT * FROM applications WHERE email = $1",
      [user]
    );

    if (existingApplication.rows.length > 0) {
      // If the application already exists, return a 409 (Conflict) response
      return res.status(409).json({
        error: "An application has already been submitted for this email.",
      });
    }

    // If no application exists, proceed with the insertion
    const result = await pool.query(
      "INSERT INTO applications (team_name, team_members, experience, tools, previous_hackathons, previous_solutions, how_did_you_hear, email) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
      [
        teamName,
        JSON.stringify(teamMembers), // Make sure to stringify if necessary
        experience,
        tools,
        previousHackathons,
        previousSolutions,
        howDidYouHear,
        user, // Store user email
      ]
    );

    try {
      const mailResponse = await transporter.sendMail({
        from: "codeforcare@rstp.org.sz",
        to: email,
        subject: "Congratulations!",
        html: `
    <div style="font-family: Arial, sans-serif; color: #333;">
      <table style="width: 100%; background-color: #f5f5f5; padding: 20px;">
        <tr>
          <td align="center">
           <img src="https://firebasestorage.googleapis.com/v0/b/hackathon-7fce3.appspot.com/o/New%20Pepfar%20logo.png?alt=media&token=4564e2b8-fe4c-484e-b241-8a94d0a5af43" alt="Hackathon Logo" style="max-width: 150px; margin-bottom: 20px;  margin-right:30px">
            <img src="https://firebasestorage.googleapis.com/v0/b/hackathon-7fce3.appspot.com/o/CGHP_Social%20(1).jpg?alt=media&token=60b32285-c08d-4103-a328-df563d95215f" alt="Hackathon Logo" style="max-width: 150px; margin-bottom: 20px; margin-right:30px">
            <img src="https://firebasestorage.googleapis.com/v0/b/hackathon-7fce3.appspot.com/o/logo%20(1).png?alt=media&token=9b2558c3-97eb-4d02-be0c-da4f5d28a7cf" alt="Hackathon Logo" style="max-width: 80px; margin-bottom: 20px;">
          </td>
        </tr>
        <tr>
          <td>
            <div style="background-color: white; padding: 20px; border-radius: 10px;">
              <h2 style="color: #007bff; text-align: center;">Congratulations!</h2>
              <p style="font-size: 16px; line-height: 1.6;">
                Dear Participant,
              </p>
              <p style="font-size: 16px; line-height: 1.6;">
                We are excited to confirm that your application for the Digital Health Hackathon <strong>"Code for Care Hackathon"</strong>has been successfully received. You will have the opportunity to develop digital health solutions that address critical barriers to accessing healthcare services.
              </p>
              <p style="font-size: 16px; line-height: 1.6;">
                We envision a future where the youth of Eswatini are equipped with the skills and knowledge to create impactful digital health solutions that improve healthcare outcomes. Your participation is vital in fostering innovation and entrepreneurship within the digital health sector.
              </p>
              <p style="font-size: 16px; line-height: 1.6;">
                Should your team be successful, we will reach out to you via email with further details and next steps in the hackathon process.
              </p>
              <div style="text-align: center; margin: 20px 0;">
                <img src="https://img.freepik.com/free-vector/medical-protective-shield-banner-background_1419-2191.jpg?w=1380&t=st=1673734162~exp=1673734762~hmac=5ff4319dd6564336bdb551ee7eeaf67066f26b0c2310e193de1c1ea33853db1c" alt="Hackathon Event" style="max-width: 300px; border-radius: 10px;">
              </div>
              <p style="font-size: 16px; line-height: 1.6; text-align: center;">
                Please stay tuned for further updates regarding the next steps in the hackathon process. Thank you for your commitment to this mission; we look forward to seeing the innovative solutions you will create!
              </p>
              <p style="font-size: 16px; line-height: 1.6; text-align: center;">
                Best regards, <br/>
                <strong>Code for Care Hackathon Team</strong>
              </p>
              <hr style="margin: 20px 0; border: none; border-top: 1px solid #eee;">
              <p style="font-size: 12px; color: #888; text-align: center;">
                If you have any questions, feel free to contact us at 
                <a href="mailto:codeforcare@rstp.org.sz" style="color: #007bff;">codeforcare@rstp.org.sz</a>.
              </p>
            </div>
          </td>
        </tr>
      </table>
    </div>
  `,
      });

      console.log("Email sent successfully:", mailResponse);

      res.status(201).json({
        message: "Application sent successfully and email sent.",
        user: result.rows[0],
      });
    } catch (mailError) {
      console.error("Error sending email:", mailError);

      res.status(201).json({
        message: "Application sent successfully but email not sent.",
        user: result.rows[0],
        emailError: mailError.message,
      });
    }

    res.status(201).json(result.rows[0]); // Send back the created record
  } catch (error) {
    console.error("Error inserting data into applications table:", error);
    res.status(500).json({ error: "Database insertion error" });
  }
});

app.get("/checkTeamName/:teamName", async (req, res) => {
  const { teamName } = req.params;

  try {
    const result = await pool.query(
      "SELECT * FROM applications WHERE team_name = $1",
      [teamName]
    );

    if (result.rows.length > 0) {
      // If team name exists, return isTaken as true
      return res.json({ isTaken: true });
    } else {
      // Team name is available
      return res.json({ isTaken: false });
    }
  } catch (error) {
    console.error("Error checking team name:", error);
    res.status(500).json({ error: "Database query error" });
  }
});

// Assuming you have express and your database connection set up
app.get("/checkSubmission/:email", async (req, res) => {
  const email = req.params.email;

  try {
    const result = await pool.query(
      "SELECT has_submitted FROM applications WHERE email = $1",
      [email]
    );

    if (result.rows.length > 0) {
      // User found, check their submission status
      const hasSubmitted = result.rows[0].has_submitted;
      res.status(200).json({ hasSubmitted });
    } else {
      // User not found
      res.status(404).json({ message: "User not found." });
    }
  } catch (error) {
    console.error("Error checking submission status:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

// Get all users endpoint
app.get("/getUsers", async (req, res) => {
  try {
    const result = await pool.query("SELECT id, username, email FROM users");
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete user endpoint
app.delete("/deleteUser/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM users WHERE id = $1 RETURNING *",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update user endpoint
app.put("/updateUser/:id", async (req, res) => {
  const { id } = req.params;
  const { username, email } = req.body;

  try {
    const result = await pool.query(
      "UPDATE users SET username = $1, email = $2 WHERE id = $3 RETURNING *",
      [username, email, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// app.post("/sendResetLink", async (req, res) => {
//   const { email } = req.body;

//   try {
//     // Check if the email exists
//     const result = await pool.query("SELECT id FROM users WHERE email = $1", [
//       email,
//     ]);

//     if (result.rows.length === 0) {
//       return res.status(400).json({ error: "Email not registered" });
//     }

//     const userId = result.rows[0].id;
//     const token = crypto.randomBytes(20).toString("hex");
//     console.log("I reach here...", token, userId);
//     // Store the token in the database with an expiration time
//     await pool.query(
//       "INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
//       [userId, token]
//     );

//     // Send email with reset link
//     const resetLink = `http://localhost:5173/reset/`;
//     await transporter.sendMail({
//       to: email,
//       subject: "Password Reset",
//       text: `You requested a password reset. Click the link to reset your password: ${resetLink}`,
//     });

//     res.status(200).json({ message: "Reset link sent" });
//   } catch (error) {
//     console.error("Error sending reset link:", error);
//     res.status(500).json({ error: "Internal server error" });
//   }
// });

app.post("/resetPassword/:token", async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    // Validate token
    const result = await pool.query(
      "SELECT user_id FROM password_resets WHERE token = $1 AND expires_at > NOW()",
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    const userId = result.rows[0].user_id;

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update user's password
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [
      hashedPassword,
      userId,
    ]);

    // Delete the token
    await pool.query("DELETE FROM password_resets WHERE token = $1", [token]);

    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/userProfile", async (req, res) => {
  const { userId } = req.body; // Extract userId from request body

  try {
    const result = await pool.query(
      "SELECT username, email, phone FROM users WHERE email = $1",
      [userId]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching user profile:", error); // Added error logging
    res.status(500).json({ message: "Error fetching user profile" });
  }
});

// server.js or routes/transactions.js
app.post("/transactionHistory", async (req, res) => {
  const { userId } = req.body; // Extract userId from request body
  console.log("get here.....", userId); // Debug logging to check if userId is received

  try {
    const result = await pool.query(
      "SELECT * FROM transactions WHERE user_id = $1",
      [userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching transaction history:", error); // Added error logging
    res.status(500).json({ message: "Error fetching transaction history" });
  }
});

app.post("/uploadDocument", upload.single("document"), async (req, res) => {
  const { documentType, userId } = req.body;
  const file = req.file;

  if (!file || !documentType || !userId) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  try {
    const result = await pool.query(
      "INSERT INTO documents (user_id, document_type, status, upload_date, file) VALUES ($1, $2, $3, $4, $5)",
      [userId, documentType, "uploaded", new Date(), file.path]
    );
    res.json({ message: "Document uploaded successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error uploading document" });
  }
});

// app.post("/getDocuments", async (req, res) => {
//   const { userId } = req.body;

//   if (!userId) {
//     return res.status(400).json({ message: "User ID is required" });
//   }

//   try {
//     // Query to fetch document statuses
//     const result = await pool.query(
//       `SELECT
//          document_type AS "documentType",
//          status AS "status"
//        FROM documents
//        WHERE user_id = $1`,
//       [userId]
//     );

//     // Transform the result into a structure similar to your client code
//     const documents = result.rows.reduce((acc, row) => {
//       acc[row.documentType] = row.status;
//       return acc;
//     }, {});

//     // Default statuses to 'missing' if not present
//     const allDocTypes = ["idDocument", "cardDocument", "photoVerification"];
//     allDocTypes.forEach((docType) => {
//       if (!documents[docType]) {
//         documents[docType] = "missing";
//       }
//     });

//     // Respond with document statuses
//     res.json(documents);
//   } catch (error) {
//     console.error("Error fetching document statuses:", error);
//     res.status(500).json({ message: "Error fetching document statuses" });
//   }
// });

app.post("/getDocuments", async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "User ID is required" });
  }

  try {
    const result = await pool.query(
      `SELECT 
         document_type AS "documentType",
         status AS "status"
       FROM documents
       WHERE user_id = $1`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ message: "No documents found for this user" });
    }

    const documents = result.rows.reduce((acc, row) => {
      acc[row.documentType] = { status: row.status };
      return acc;
    }, {});

    res.json(documents);
  } catch (error) {
    console.error("Error fetching document statuses:", error);
    res.status(500).json({ message: "Error fetching document statuses" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
