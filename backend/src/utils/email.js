const nodemailer = require("nodemailer");

const sendEmail = async (to, subject, text) => {
  //   console.log(
  //     process.env.EMAIL_USER,
  //     process.env.EMAIL_PASS,
  //     to,
  //     subject,
  //     text,
  //     "hwello"
  //   );
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465, // Use 465 for SSL or 587 for TLS
    secure: true, // Set to true for port 465, false for 587
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to,
      subject,
      text,
    });
    console.log(`Email sent to ${to}`);
  } catch (error) {
    console.error("Error sending email:", error);
  }
};

module.exports = { sendEmail };
