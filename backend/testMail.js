require("dotenv").config();
const nodemailer = require("nodemailer");
const dotenv = require("dotenv");

dotenv.config();

async function testEmail() {
  console.log(process.env.EMAIL_USER, process.env.EMAIL_PASS);
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: "your-email@gmail.com",
      subject: "Test Email",
      text: "Hello from Nodemailer!",
    });
    console.log("✅ Test email sent successfully!");
  } catch (error) {
    console.error("❌ Error sending test email:", error);
  }
}

testEmail();
